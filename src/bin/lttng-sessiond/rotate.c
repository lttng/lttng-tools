/*
 * Copyright (C) 2017 - Julien Desfossez <jdesfossez@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define _LGPL_SOURCE
#include <lttng/trigger/trigger.h>
#include <common/error.h>
#include <common/config/session-config.h>
#include <common/defaults.h>
#include <common/utils.h>
#include <common/futex.h>
#include <common/align.h>
#include <common/time.h>
#include <common/hashtable/utils.h>
#include <common/kernel-ctl/kernel-ctl.h>
#include <sys/eventfd.h>
#include <sys/stat.h>
#include <time.h>
#include <signal.h>
#include <inttypes.h>

#include <lttng/rotate-internal.h>

#include "session.h"
#include "rotate.h"
#include "rotation-thread.h"
#include "lttng-sessiond.h"
#include "health-sessiond.h"
#include "cmd.h"
#include "utils.h"

#include <urcu.h>
#include <urcu/list.h>
#include <urcu/rculfhash.h>

unsigned long hash_channel_key(struct rotation_channel_key *key)
{
	return hash_key_u64(&key->key, lttng_ht_seed) ^ hash_key_ulong(
			(void *) (unsigned long) key->domain, lttng_ht_seed);
}

int rotate_add_channel_pending(uint64_t key, enum lttng_domain_type domain,
		struct ltt_session *session)
{
	int ret;
	struct rotation_channel_info *new_info;
	struct rotation_channel_key channel_key = { .key = key,
		.domain = domain };

	new_info = zmalloc(sizeof(struct rotation_channel_info));
	if (!new_info) {
		goto error;
	}

	new_info->channel_key.key = key;
	new_info->channel_key.domain = domain;
	new_info->session_id = session->id;
	cds_lfht_node_init(&new_info->rotate_channels_ht_node);

	session->nr_chan_rotate_pending++;
	cds_lfht_add(channel_pending_rotate_ht,
			hash_channel_key(&channel_key),
			&new_info->rotate_channels_ht_node);

	ret = 0;
	goto end;

error:
	ret = -1;
end:
	return ret;
}

/* The session's lock must be held by the caller. */
static
int session_rename_chunk(struct ltt_session *session, char *current_path,
		char *new_path)
{
	int ret;
	struct consumer_socket *socket;
	struct consumer_output *output;
	struct lttng_ht_iter iter;
	uid_t uid;
	gid_t gid;

	DBG("Renaming session chunk path of session \"%s\" from %s to %s",
			session->name, current_path, new_path);

	/*
	 * Either one of the sessions is enough to find the consumer_output
	 * and uid/gid.
	 */
	if (session->kernel_session) {
		output = session->kernel_session->consumer;
		uid = session->kernel_session->uid;
		gid = session->kernel_session->gid;
	} else if (session->ust_session) {
		output = session->ust_session->consumer;
		uid = session->ust_session->uid;
		gid = session->ust_session->gid;
	} else {
		assert(0);
	}

	if (!output || !output->socks) {
		ERR("No consumer output found for session \"%s\"",
				session->name);
		ret = -1;
		goto end;
	}

	rcu_read_lock();
	/*
	 * We have to iterate to find a socket, but we only need to send the
	 * rename command to one consumer, so we break after the first one.
	 */
	cds_lfht_for_each_entry(output->socks->ht, &iter.iter, socket, node.node) {
		pthread_mutex_lock(socket->lock);
		ret = consumer_rotate_rename(socket, session->id, output,
				current_path, new_path, uid, gid);
		pthread_mutex_unlock(socket->lock);
		if (ret) {
			ret = -1;
			goto end_unlock;
		}
		break;
	}

	ret = 0;

end_unlock:
	rcu_read_unlock();
end:
	return ret;
}

/* The session's lock must be held by the caller. */
static
int rename_first_chunk(struct ltt_session *session,
		struct consumer_output *consumer, char *new_path)
{
	int ret;
	char current_full_path[LTTNG_PATH_MAX], new_full_path[LTTNG_PATH_MAX];

	/* Current domain path: <session>/kernel */
	if (session->net_handle > 0) {
		ret = snprintf(current_full_path, sizeof(current_full_path), "%s/%s",
				consumer->dst.net.base_dir, consumer->subdir);
		if (ret < 0 || ret >= sizeof(current_full_path)) {
			ERR("Failed to initialize current full path while renaming first rotation chunk of session \"%s\"",
					session->name);
			ret = -1;
			goto error;
		}
	} else {
		ret = snprintf(current_full_path, sizeof(current_full_path), "%s/%s",
				consumer->dst.session_root_path, consumer->subdir);
		if (ret < 0 || ret >= sizeof(current_full_path)) {
			ERR("Failed to initialize current full path while renaming first rotation chunk of session \"%s\"",
					session->name);
			ret = -1;
			goto error;
		}
	}
	/* New domain path: <session>/<start-date>-<end-date>-<rotate-count>/kernel */
	ret = snprintf(new_full_path, sizeof(new_full_path), "%s/%s",
			new_path, consumer->subdir);
	if (ret < 0 || ret >= sizeof(new_full_path)) {
		ERR("Failed to initialize new full path while renaming first rotation chunk of session \"%s\"",
				session->name);
		ret = -1;
		goto error;
	}
	/*
	 * Move the per-domain fcurrenter inside the first rotation
	 * fcurrenter.
	 */
	ret = session_rename_chunk(session, current_full_path, new_full_path);
	if (ret < 0) {
		ret = -LTTNG_ERR_UNK;
		goto error;
	}

	ret = 0;

error:
	return ret;
}

/*
 * Rename a chunk folder after a rotation is complete.
 * session_lock_list and session lock must be held.
 *
 * Returns 0 on success, a negative value on error.
 */
int rename_complete_chunk(struct ltt_session *session, time_t ts)
{
	struct tm *timeinfo;
	char new_path[LTTNG_PATH_MAX];
	char datetime[21], start_datetime[21];
	int ret;
	size_t strf_ret;

	DBG("Renaming completed chunk for session %s", session->name);
	timeinfo = localtime(&ts);
	if (!timeinfo) {
		ERR("Failed to retrieve local time while renaming completed chunk");
		ret = -1;
		goto end;
	}

	strf_ret = strftime(datetime, sizeof(datetime), "%Y%m%dT%H%M%S%z",
			timeinfo);
	if (strf_ret == 0) {
		ERR("Failed to format timestamp while renaming completed session chunk");
		ret = -1;
		goto end;
	}

	if (session->rotate_count == 1) {
		char start_time[21];

		timeinfo = localtime(&session->last_chunk_start_ts);
		if (!timeinfo) {
			ERR("Failed to retrieve local time while renaming completed chunk");
			ret = -1;
			goto end;
		}

		strf_ret = strftime(start_time, sizeof(start_time),
				"%Y%m%dT%H%M%S%z", timeinfo);
		if (strf_ret == 0) {
			ERR("Failed to format timestamp while renaming completed session chunk");
			ret = -1;
			goto end;
		}

		/*
		 * On the first rotation, the current_rotate_path is the
		 * session_root_path, so we need to create the chunk folder
		 * and move the domain-specific folders inside it.
		 */
		ret = snprintf(new_path, sizeof(new_path), "%s/%s-%s-%" PRIu64,
				session->rotation_chunk.current_rotate_path,
				start_time,
				datetime, session->rotate_count);
		if (ret < 0 || ret >= sizeof(new_path)) {
			ERR("Failed to format new chunk path while renaming session \"%s\"'s first chunk",
					session->name);
			ret = -1;
			goto end;
		}

		if (session->kernel_session) {
			ret = rename_first_chunk(session,
					session->kernel_session->consumer,
					new_path);
			if (ret) {
				ERR("Failed to rename kernel session trace folder to %s", new_path);
				/*
				 * This is not a fatal error for the rotation
				 * thread, we just need to inform the client
				 * that a problem occurred with the rotation.
				 * Returning 0, same for the other errors
				 * below.
				 */
				ret = 0;
				goto error;
			}
		}
		if (session->ust_session) {
			ret = rename_first_chunk(session,
					session->ust_session->consumer,
					new_path);
			if (ret) {
				ERR("Failed to rename userspace session trace folder to %s", new_path);
				ret = 0;
				goto error;
			}
		}
	} else {
		/*
		 * After the first rotation, all the trace data is already in
		 * its own chunk folder, we just need to append the suffix.
		 */
		/* Recreate the session->rotation_chunk.current_rotate_path */
		timeinfo = localtime(&session->last_chunk_start_ts);
		if (!timeinfo) {
			ERR("Failed to retrieve local time while renaming completed chunk");
			ret = -1;
			goto end;
		}
		strf_ret = strftime(start_datetime, sizeof(start_datetime),
				"%Y%m%dT%H%M%S%z", timeinfo);
		if (!strf_ret) {
			ERR("Failed to format timestamp while renaming completed session chunk");
			ret = -1;
			goto end;
		}
		ret = snprintf(new_path, sizeof(new_path), "%s/%s-%s-%" PRIu64,
				session_get_base_path(session),
				start_datetime,
				datetime, session->rotate_count);
		if (ret < 0 || ret >= sizeof(new_path)) {
			ERR("Failed to format new chunk path while renaming chunk of session \"%s\"",
					session->name);
			ret = -1;
			goto error;
		}
		ret = session_rename_chunk(session,
				session->rotation_chunk.current_rotate_path,
				new_path);
		if (ret) {
			ERR("Failed to rename session trace folder from %s to %s",
					session->rotation_chunk.current_rotate_path,
					new_path);
			ret = 0;
			goto error;
		}
	}

	/*
	 * Store the path where the readable chunk is. This path is valid
	 * and can be queried by the client with rotate_pending until the next
	 * rotation is started.
	 */
	ret = lttng_strncpy(session->rotation_chunk.current_rotate_path,
			new_path,
			sizeof(session->rotation_chunk.current_rotate_path));
	if (ret) {
		ERR("Failed the current chunk's path of session \"%s\"",
				session->name);
		ret = -1;
		goto error;
	}

	goto end;

error:
	session->rotation_state = LTTNG_ROTATION_STATE_ERROR;
end:
	return ret;
}

int relay_rotate_pending(struct ltt_session *session, uint64_t chunk_id)
{
	int ret;
	struct consumer_socket *socket;
	struct consumer_output *output;
	struct lttng_ht_iter iter;

	/*
	 * Either one of the sessions is enough to find the consumer_output
	 * and uid/gid.
	 */
	if (session->kernel_session) {
		output = session->kernel_session->consumer;
	} else if (session->ust_session) {
		output = session->ust_session->consumer;
	} else {
		assert(0);
	}

	if (!output || !output->socks) {
		ERR("No consumer output found");
		ret = -1;
		goto end;
	}

	ret = -1;

	rcu_read_lock();
	/*
	 * We have to iterate to find a socket, but we only need to send the
	 * rotate pending command to one consumer, so we break after the first
	 * one.
	 */
	cds_lfht_for_each_entry(output->socks->ht, &iter.iter, socket,
			node.node) {
		pthread_mutex_lock(socket->lock);
		ret = consumer_rotate_pending_relay(socket, output, session->id,
				chunk_id);
		pthread_mutex_unlock(socket->lock);
		break;
	}
	rcu_read_unlock();

end:
	return ret;
}
