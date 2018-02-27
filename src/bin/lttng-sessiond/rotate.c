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

#include <lttng/notification/channel-internal.h>
#include <lttng/rotate-internal.h>

#include "session.h"
#include "rotate.h"
#include "rotation-thread.h"
#include "lttng-sessiond.h"
#include "health-sessiond.h"
#include "cmd.h"
#include "utils.h"
#include "notification-thread-commands.h"

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
		ERR("No consumer output found");
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
			ERR("Consumer rename chunk");
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

static
int rename_first_chunk(struct ltt_session *session,
		struct consumer_output *consumer, char *new_path)
{
	int ret;
	char *tmppath = NULL, *tmppath2 = NULL;

	tmppath = zmalloc(PATH_MAX * sizeof(char));
	if (!tmppath) {
		ret = -LTTNG_ERR_NOMEM;
		goto error;
	}
	tmppath2 = zmalloc(PATH_MAX * sizeof(char));
	if (!tmppath2) {
		ret = -LTTNG_ERR_NOMEM;
		goto error;
	}

	/* Current domain path: <session>/kernel */
	if (session->net_handle > 0) {
		ret = snprintf(tmppath, PATH_MAX, "%s/%s",
				consumer->dst.net.base_dir, consumer->subdir);
		if (ret < 0 || ret >= PATH_MAX) {
			ERR("Format tmppath");
			ret = -1;
			goto error;
		}
	} else {
		ret = snprintf(tmppath, PATH_MAX, "%s/%s",
				consumer->dst.session_root_path, consumer->subdir);
		if (ret < 0 || ret >= PATH_MAX) {
			ERR("Format tmppath");
			ret = -1;
			goto error;
		}
	}
	/* New domain path: <session>/<start-date>-<end-date>-<rotate-count>/kernel */
	ret = snprintf(tmppath2, PATH_MAX, "%s/%s",
			new_path, consumer->subdir);
	if (ret < 0 || ret >= PATH_MAX) {
		ERR("Format tmppath2");
		ret = -1;
		goto error;
	}
	/*
	 * Move the per-domain folder inside the first rotation
	 * folder.
	 */
	ret = session_rename_chunk(session, tmppath, tmppath2);
	if (ret < 0) {
		ERR("Rename first trace directory");
		ret = -LTTNG_ERR_UNK;
		goto error;
	}

	ret = 0;

error:
	free(tmppath);
	free(tmppath2);

	return ret;
}

/*
 * Rename a chunk folder after a rotation is complete.
 * session_lock_list and session lock must be held.
 * Returns 0 on success, a negative value on error.
 */
int rename_complete_chunk(struct ltt_session *session, time_t ts)
{
	struct tm *timeinfo;
	char datetime[21], start_datetime[21];
	char *new_path = NULL;
	int ret;
	size_t strf_ret;

	DBG("Renaming complete chunk for session %s", session->name);
	timeinfo = localtime(&ts);
	if (!timeinfo) {
		ERR("Retrieve local time");
		ret = -1;
		goto end;
	}
	strf_ret = strftime(datetime, sizeof(datetime), "%Y%m%dT%H%M%S%z", timeinfo);
	if (!strf_ret) {
		ERR("Format timestamp");
		ret = -1;
		goto end;
	}

	new_path = zmalloc(PATH_MAX * sizeof(char));
	if (!new_path) {
		session->rotation_status = LTTNG_ROTATION_STATUS_ERROR;
		ERR("Alloc new_path");
		ret = -1;
		goto end;
	}

	if (session->rotate_count == 1) {
		char start_time[21];

		timeinfo = localtime(&session->last_chunk_start_ts);
		if (!timeinfo) {
			ERR("Retrieve local time");
			ret = -1;
			goto end;
		}
		strf_ret = strftime(start_time, sizeof(start_time), "%Y%m%dT%H%M%S%z",
				timeinfo);
		if (!strf_ret) {
			ERR("Format timestamp");
			ret = -1;
			goto end;
		}

		/*
		 * On the first rotation, the current_rotate_path is the
		 * session_root_path, so we need to create the chunk folder
		 * and move the domain-specific folders inside it.
		 */
		ret = snprintf(new_path, PATH_MAX, "%s/%s-%s-%" PRIu64,
				session->rotation_chunk.current_rotate_path,
				start_time,
				datetime, session->rotate_count);
		if (ret < 0 || ret >= PATH_MAX) {
			ERR("Format tmppath");
			ret = -1;
			goto end;
		}

		if (session->kernel_session) {
			ret = rename_first_chunk(session,
					session->kernel_session->consumer,
					new_path);
			if (ret) {
				ERR("Rename kernel session");
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
				ERR("Rename ust session");
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
			ERR("Retrieve local time");
			ret = -1;
			goto end;
		}
		strf_ret = strftime(start_datetime, sizeof(start_datetime),
				"%Y%m%dT%H%M%S%z", timeinfo);
		if (!strf_ret) {
			ERR("Format timestamp");
			ret = -1;
			goto end;
		}
		ret = snprintf(new_path, PATH_MAX, "%s/%s-%s-%" PRIu64,
				session_get_base_path(session),
				start_datetime,
				datetime, session->rotate_count);
		if (ret < 0 || ret >= PATH_MAX) {
			ERR("Format new_path");
			ret = -1;
			goto error;
		}
		ret = session_rename_chunk(session,
				session->rotation_chunk.current_rotate_path,
				new_path);
		if (ret) {
			ERR("Session rename");
			ret = 0;
			goto error;
		}
	}

	/*
	 * Store the path where the readable chunk is. This path is valid
	 * and can be queried by the client with rotate_pending until the next
	 * rotation is started.
	 */
	ret = snprintf(session->rotation_chunk.current_rotate_path, PATH_MAX,
			"%s", new_path);
	if (ret < 0 || ret >= PATH_MAX) {
		ERR("Format current_rotate_path");
		ret = -1;
		goto error;
	}

	goto end;

error:
	session->rotation_status = LTTNG_ROTATION_STATUS_ERROR;
end:
	free(new_path);
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
	cds_lfht_for_each_entry(output->socks->ht, &iter.iter, socket, node.node) {
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

int subscribe_session_usage_rotation(struct ltt_session *session, uint64_t size,
		struct notification_thread_handle *notification_thread_handle)
{
	int ret;
	enum lttng_condition_status condition_status;
	enum lttng_notification_channel_status nc_status;
	struct lttng_action *action;

	session->rotate_condition = lttng_condition_session_consumed_size_create();
	if (!session->rotate_condition) {
		ERR("Create condition object");
		ret = -1;
		goto end;
	}

	condition_status = lttng_condition_session_consumed_size_set_threshold(
			session->rotate_condition, size);
	if (condition_status != LTTNG_CONDITION_STATUS_OK) {
		ERR("Could not set threshold");
		ret = -1;
		goto end;
	}

	condition_status =
			lttng_condition_session_consumed_size_set_session_name(
				session->rotate_condition, session->name);
	if (condition_status != LTTNG_CONDITION_STATUS_OK) {
		ERR("Could not set session name");
		ret = -1;
		goto end;
	}

	action = lttng_action_notify_create();
	if (!action) {
		ERR("Could not create action notify");
		ret = -1;
		goto end;
	}

	session->rotate_trigger = lttng_trigger_create(session->rotate_condition,
			action);
	if (!session->rotate_trigger) {
		ERR("Could not create trigger");
		ret = -1;
		goto end;
	}

	nc_status = lttng_notification_channel_subscribe(
			rotate_notification_channel, session->rotate_condition);
	if (nc_status != LTTNG_NOTIFICATION_CHANNEL_STATUS_OK) {
		ERR("Could not subscribe");
		ret = -1;
		goto end;
	}

	ret = notification_thread_command_register_trigger(
			notification_thread_handle, session->rotate_trigger);
	if (ret < 0 && ret != -LTTNG_ERR_TRIGGER_EXISTS) {
		ERR("Register trigger, %s", lttng_strerror(ret));
		ret = -1;
		goto end;
	}

	ret = 0;

end:
	return ret;
}

void unsubscribe_session_usage_rotation(struct ltt_session *session,
		struct notification_thread_handle *notification_thread_handle)
{
	int ret;

	ret = lttng_notification_channel_unsubscribe(rotate_notification_channel,
			session->rotate_condition);
	if (ret != LTTNG_NOTIFICATION_CHANNEL_STATUS_OK) {
		ERR("Session unsubscribe error: %d", ret);
	}

	ret = notification_thread_command_unregister_trigger(
			notification_thread_handle, session->rotate_trigger);
	if (ret != LTTNG_OK) {
		ERR("Session unregister trigger error");
	}
}
