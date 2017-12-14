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
#include <sys/eventfd.h>
#include <sys/stat.h>
#include <time.h>
#include <signal.h>
#include <inttypes.h>

#include <common/kernel-ctl/kernel-ctl.h>
#include <lttng/notification/channel-internal.h>

#include "rotation-thread.h"
#include "lttng-sessiond.h"
#include "health-sessiond.h"
#include "rotate.h"
#include "cmd.h"
#include "session.h"

#include <urcu.h>
#include <urcu/list.h>
#include <urcu/rculfhash.h>

/*
 * Store a struct rotation_channel_info for each channel that is currently
 * being rotated by the consumer.
 */
struct cds_lfht *channel_pending_rotate_ht;

struct rotation_thread_state {
	struct lttng_poll_event events;
};

static
void channel_rotation_info_destroy(struct rotation_channel_info *channel_info)
{
	assert(channel_info);
	free(channel_info);
}

static
int match_channel_info(struct cds_lfht_node *node, const void *key)
{
	struct rotation_channel_key *channel_key = (struct rotation_channel_key *) key;
	struct rotation_channel_info *channel_info;

	channel_info = caa_container_of(node, struct rotation_channel_info,
			rotate_channels_ht_node);

	return !!((channel_key->key == channel_info->channel_key.key) &&
			(channel_key->domain == channel_info->channel_key.domain));
}

static
struct rotation_channel_info *lookup_channel_pending(uint64_t key,
		enum lttng_domain_type domain)
{
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;
	struct rotation_channel_info *channel_info = NULL;
	struct rotation_channel_key channel_key = { .key = key,
		.domain = domain };

	cds_lfht_lookup(channel_pending_rotate_ht,
			hash_channel_key(&channel_key),
			match_channel_info,
			&channel_key, &iter);
	node = cds_lfht_iter_get_node(&iter);
	if (!node) {
		goto end;
	}

	channel_info = caa_container_of(node, struct rotation_channel_info,
			rotate_channels_ht_node);
	cds_lfht_del(channel_pending_rotate_ht, node);
end:
	return channel_info;
}

/*
 * Destroy the thread data previously created by the init function.
 */
void rotation_thread_handle_destroy(
		struct rotation_thread_handle *handle)
{
	int ret;

	if (!handle) {
		goto end;
	}

	if (handle->ust32_consumer >= 0) {
		ret = close(handle->ust32_consumer);
		if (ret) {
			PERROR("close 32-bit consumer channel rotation pipe");
		}
	}
	if (handle->ust64_consumer >= 0) {
		ret = close(handle->ust64_consumer);
		if (ret) {
			PERROR("close 64-bit consumer channel rotation pipe");
		}
	}
	if (handle->kernel_consumer >= 0) {
		ret = close(handle->kernel_consumer);
		if (ret) {
			PERROR("close kernel consumer channel rotation pipe");
		}
	}

end:
	free(handle);
}

struct rotation_thread_handle *rotation_thread_handle_create(
		struct lttng_pipe *ust32_channel_rotate_pipe,
		struct lttng_pipe *ust64_channel_rotate_pipe,
		struct lttng_pipe *kernel_channel_rotate_pipe,
		int thread_quit_pipe)
{
	struct rotation_thread_handle *handle;

	handle = zmalloc(sizeof(*handle));
	if (!handle) {
		goto end;
	}

	if (ust32_channel_rotate_pipe) {
		handle->ust32_consumer =
				lttng_pipe_release_readfd(
					ust32_channel_rotate_pipe);
		if (handle->ust32_consumer < 0) {
			goto error;
		}
	} else {
		handle->ust32_consumer = -1;
	}
	if (ust64_channel_rotate_pipe) {
		handle->ust64_consumer =
				lttng_pipe_release_readfd(
					ust64_channel_rotate_pipe);
		if (handle->ust64_consumer < 0) {
			goto error;
		}
	} else {
		handle->ust64_consumer = -1;
	}
	if (kernel_channel_rotate_pipe) {
		handle->kernel_consumer =
				lttng_pipe_release_readfd(
					kernel_channel_rotate_pipe);
		if (handle->kernel_consumer < 0) {
			goto error;
		}
	} else {
		handle->kernel_consumer = -1;
	}
	handle->thread_quit_pipe = thread_quit_pipe;

end:
	return handle;
error:
	rotation_thread_handle_destroy(handle);
	return NULL;
}

static
int init_poll_set(struct lttng_poll_event *poll_set,
		struct rotation_thread_handle *handle)
{
	int ret;

	/*
	 * Create pollset with size 4:
	 *	- sessiond quit pipe
	 *	- consumerd (32-bit user space) channel rotate pipe,
	 *	- consumerd (64-bit user space) channel rotate pipe,
	 *	- consumerd (kernel) channel rotate pipe,
	 */
	ret = lttng_poll_create(poll_set, 4, LTTNG_CLOEXEC);
	if (ret < 0) {
		goto end;
	}

	ret = lttng_poll_add(poll_set, handle->thread_quit_pipe,
			LPOLLIN | LPOLLERR);
	if (ret < 0) {
		ERR("[rotation-thread] Failed to add thread_quit_pipe fd to pollset");
		goto error;
	}
	ret = lttng_poll_add(poll_set, handle->ust32_consumer,
			LPOLLIN | LPOLLERR);
	if (ret < 0) {
		ERR("[rotation-thread] Failed to add ust-32 channel rotation pipe fd to pollset");
		goto error;
	}
	ret = lttng_poll_add(poll_set, handle->ust64_consumer,
			LPOLLIN | LPOLLERR);
	if (ret < 0) {
		ERR("[rotation-thread] Failed to add ust-64 channel rotation pipe fd to pollset");
		goto error;
	}
	if (handle->kernel_consumer >= 0) {
		ret = lttng_poll_add(poll_set, handle->kernel_consumer,
				LPOLLIN | LPOLLERR);
		if (ret < 0) {
			ERR("[rotation-thread] Failed to add kernel channel rotation pipe fd to pollset");
			goto error;
		}
	}

end:
	return ret;
error:
	lttng_poll_clean(poll_set);
	return ret;
}

static
void fini_thread_state(struct rotation_thread_state *state)
{
	lttng_poll_clean(&state->events);
	cds_lfht_destroy(channel_pending_rotate_ht, NULL);
}

static
int init_thread_state(struct rotation_thread_handle *handle,
		struct rotation_thread_state *state)
{
	int ret;

	memset(state, 0, sizeof(*state));
	lttng_poll_init(&state->events);

	ret = init_poll_set(&state->events, handle);
	if (ret) {
		goto end;
	}

	channel_pending_rotate_ht = cds_lfht_new(DEFAULT_HT_SIZE,
			1, 0, CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING, NULL);
	if (!channel_pending_rotate_ht) {
		ret = -1;
	}

end:
	return 0;
}

static
int handle_channel_rotation_pipe(int fd, uint32_t revents,
		struct rotation_thread_handle *handle,
		struct rotation_thread_state *state)
{
	int ret = 0;
	enum lttng_domain_type domain;
	struct rotation_channel_info *channel_info;
	struct ltt_session *session = NULL;
	uint64_t key;

	if (fd == handle->ust32_consumer ||
			fd == handle->ust64_consumer) {
		domain = LTTNG_DOMAIN_UST;
	} else if (fd == handle->kernel_consumer) {
		domain = LTTNG_DOMAIN_KERNEL;
	} else {
		abort();
	}

	if (revents & (LPOLLERR | LPOLLHUP | LPOLLRDHUP)) {
		ret = lttng_poll_del(&state->events, fd);
		if (ret) {
			ERR("[rotation-thread] Failed to remove consumer "
					"rotation pipe from poll set");
		}
		goto end;
	}

	do {
		ret = read(fd, &key, sizeof(key));
	} while (ret == -1 && errno == EINTR);
	if (ret != sizeof(key)) {
		ERR("[rotation-thread] Failed to read from pipe (fd = %i)",
				fd);
		ret = -1;
		goto end;
	}

	DBG("[rotation-thread] Received notification for chan %" PRIu64
			", domain %d\n", key, domain);

	channel_info = lookup_channel_pending(key, domain);
	if (!channel_info) {
		ERR("[rotation-thread] Failed to find channel_info (key = %"
				PRIu64 ")", key);
		ret = -1;
		goto end;
	}
	rcu_read_lock();
	session_lock_list();
	session = session_find_by_id(channel_info->session_id);
	if (!session) {
		/*
		 * The session may have been destroyed before we had a chance to
		 * perform this action, return gracefully.
		 */
		DBG("[rotation-thread] Session %" PRIu64 " not found",
				channel_info->session_id);
		ret = 0;
		goto end_unlock_session_list;
	}

	session_lock(session);
	if (--session->nr_chan_rotate_pending == 0) {
		time_t now = time(NULL);

		if (now == (time_t) -1) {
			session->rotate_status = LTTNG_ROTATE_ERROR;
			ret = LTTNG_ERR_UNK;
			goto end_unlock_session;
		}

		ret = rename_complete_chunk(session, now);
		if (ret < 0) {
			ERR("Failed to rename completed rotation chunk");
			goto end_unlock_session;
		}
		session->rotate_pending = false;
		session->rotate_status = LTTNG_ROTATE_COMPLETED;
		session->last_chunk_start_ts = session->current_chunk_start_ts;
		DBG("Rotation completed for session %s", session->name);
	}

	ret = 0;

end_unlock_session:
	channel_rotation_info_destroy(channel_info);
	session_unlock(session);
end_unlock_session_list:
	session_unlock_list();
	rcu_read_unlock();
end:
	return ret;
}

void *thread_rotation(void *data)
{
	int ret;
	struct rotation_thread_handle *handle = data;
	struct rotation_thread_state state;

	DBG("[rotation-thread] Started rotation thread");

	if (!handle) {
		ERR("[rotation-thread] Invalid thread context provided");
		goto end;
	}

	rcu_register_thread();
	rcu_thread_online();

	health_register(health_sessiond, HEALTH_SESSIOND_TYPE_ROTATION);
	health_code_update();

	ret = init_thread_state(handle, &state);
	if (ret) {
		goto end;
	}

	/* Ready to handle client connections. */
	sessiond_notify_ready();

	while (true) {
		int fd_count, i;

		health_poll_entry();
		DBG("[rotation-thread] Entering poll wait");
		ret = lttng_poll_wait(&state.events, -1);
		DBG("[rotation-thread] Poll wait returned (%i)", ret);
		health_poll_exit();
		if (ret < 0) {
			/*
			 * Restart interrupted system call.
			 */
			if (errno == EINTR) {
				continue;
			}
			ERR("[rotation-thread] Error encountered during lttng_poll_wait (%i)", ret);
			goto error;
		}

		fd_count = ret;
		for (i = 0; i < fd_count; i++) {
			int fd = LTTNG_POLL_GETFD(&state.events, i);
			uint32_t revents = LTTNG_POLL_GETEV(&state.events, i);

			DBG("[rotation-thread] Handling fd (%i) activity (%u)",
					fd, revents);

			if (fd == handle->thread_quit_pipe) {
				DBG("[rotation-thread] Quit pipe activity");
				goto exit;
			} else if (fd == handle->ust32_consumer ||
					fd == handle->ust64_consumer ||
					fd == handle->kernel_consumer) {
				ret = handle_channel_rotation_pipe(fd,
						revents, handle, &state);
				if (ret) {
					ERR("[rotation-thread] Handle channel rotation pipe");
					goto error;
				}
			}
		}
	}
exit:
error:
	DBG("[rotation-thread] Exit");
	fini_thread_state(&state);
	health_unregister(health_sessiond);
	rcu_thread_offline();
	rcu_unregister_thread();
end:
	return NULL;
}
