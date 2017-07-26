/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define _LGPL_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>

#include <common/common.h>
#include <common/consumer/consumer.h>
#include <common/defaults.h>

#include "consumer.h"
#include "health-sessiond.h"
#include "ust-consumer.h"
#include "buffer-registry.h"
#include "session.h"
#include "lttng-sessiond.h"

/*
 * Return allocated full pathname of the session using the consumer trace path
 * and subdir if available. On a successful allocation, the directory of the
 * trace is created with the session credentials.
 *
 * The caller can safely free(3) the returned value. On error, NULL is
 * returned.
 */
static char *setup_trace_path(struct consumer_output *consumer,
		struct ust_app_session *ua_sess)
{
	int ret;
	char *pathname;

	assert(consumer);
	assert(ua_sess);

	health_code_update();

	/* Allocate our self the string to make sure we never exceed PATH_MAX. */
	pathname = zmalloc(PATH_MAX);
	if (!pathname) {
		goto error;
	}

	/* Get correct path name destination */
	if (consumer->type == CONSUMER_DST_LOCAL) {
		/* Set application path to the destination path */
		ret = snprintf(pathname, PATH_MAX, "%s%s%s",
				consumer->dst.trace_path, consumer->subdir, ua_sess->path);
		if (ret < 0) {
			PERROR("snprintf channel path");
			goto error;
		}

		/* Create directory. Ignore if exist. */
		ret = run_as_mkdir_recursive(pathname, S_IRWXU | S_IRWXG,
				ua_sess->euid, ua_sess->egid);
		if (ret < 0) {
			if (errno != EEXIST) {
				ERR("Trace directory creation error");
				goto error;
			}
		}
	} else {
		ret = snprintf(pathname, PATH_MAX, "%s%s", consumer->subdir,
				ua_sess->path);
		if (ret < 0) {
			PERROR("snprintf channel path");
			goto error;
		}
	}

	return pathname;

error:
	free(pathname);
	return NULL;
}

/*
 * Send a single channel to the consumer using command ASK_CHANNEL_CREATION.
 *
 * Consumer socket lock MUST be acquired before calling this.
 */
static int ask_channel_creation(struct ust_app_session *ua_sess,
		struct ust_app_channel *ua_chan, struct consumer_output *consumer,
		struct consumer_socket *socket, struct ust_registry_session *registry)
{
	int ret, output;
	uint32_t chan_id;
	uint64_t key, chan_reg_key;
	char *pathname = NULL;
	struct lttcomm_consumer_msg msg;
	struct ust_registry_channel *chan_reg;
	char shm_path[PATH_MAX] = "";
	char root_shm_path[PATH_MAX] = "";

	assert(ua_sess);
	assert(ua_chan);
	assert(socket);
	assert(consumer);
	assert(registry);

	DBG2("Asking UST consumer for channel");

	/* Get and create full trace path of session. */
	if (ua_sess->output_traces) {
		pathname = setup_trace_path(consumer, ua_sess);
		if (!pathname) {
			ret = -1;
			goto error;
		}
	}

	/* Depending on the buffer type, a different channel key is used. */
	if (ua_sess->buffer_type == LTTNG_BUFFER_PER_UID) {
		chan_reg_key = ua_chan->tracing_channel_id;
	} else {
		chan_reg_key = ua_chan->key;
	}

	if (ua_chan->attr.type == LTTNG_UST_CHAN_METADATA) {
		chan_id = -1U;
		/*
		 * Metadata channels shm_path (buffers) are handled within
		 * session daemon. Consumer daemon should not try to create
		 * those buffer files.
		 */
	} else {
		chan_reg = ust_registry_channel_find(registry, chan_reg_key);
		assert(chan_reg);
		chan_id = chan_reg->chan_id;
		if (ua_sess->shm_path[0]) {
			strncpy(shm_path, ua_sess->shm_path, sizeof(shm_path));
			shm_path[sizeof(shm_path) - 1] = '\0';
			strncat(shm_path, "/",
				sizeof(shm_path) - strlen(shm_path) - 1);
			strncat(shm_path, ua_chan->name,
					sizeof(shm_path) - strlen(shm_path) - 1);
				strncat(shm_path, "_",
					sizeof(shm_path) - strlen(shm_path) - 1);
		}
		strncpy(root_shm_path, ua_sess->root_shm_path, sizeof(root_shm_path));
		root_shm_path[sizeof(root_shm_path) - 1] = '\0';
	}

	switch (ua_chan->attr.output) {
	case LTTNG_UST_MMAP:
	default:
		output = LTTNG_EVENT_MMAP;
		break;
	}

	consumer_init_ask_channel_comm_msg(&msg,
			ua_chan->attr.subbuf_size,
			ua_chan->attr.num_subbuf,
			ua_chan->attr.overwrite,
			ua_chan->attr.switch_timer_interval,
			ua_chan->attr.read_timer_interval,
			ua_sess->live_timer_interval,
			ua_chan->monitor_timer_interval,
			output,
			(int) ua_chan->attr.type,
			ua_sess->tracing_id,
			pathname,
			ua_chan->name,
			ua_sess->euid,
			ua_sess->egid,
			consumer->net_seq_index,
			ua_chan->key,
			registry->uuid,
			chan_id,
			ua_chan->tracefile_size,
			ua_chan->tracefile_count,
			ua_sess->id,
			ua_sess->output_traces,
			ua_sess->uid,
			ua_chan->attr.blocking_timeout,
			root_shm_path, shm_path);

	health_code_update();

	ret = consumer_socket_send(socket, &msg, sizeof(msg));
	if (ret < 0) {
		goto error;
	}

	ret = consumer_recv_status_channel(socket, &key,
			&ua_chan->expected_stream_count);
	if (ret < 0) {
		goto error;
	}
	/* Communication protocol error. */
	assert(key == ua_chan->key);
	/* We need at least one where 1 stream for 1 cpu. */
	if (ua_sess->output_traces) {
		assert(ua_chan->expected_stream_count > 0);
	}

	DBG2("UST ask channel %" PRIu64 " successfully done with %u stream(s)", key,
			ua_chan->expected_stream_count);

error:
	free(pathname);
	health_code_update();
	return ret;
}

/*
 * Ask consumer to create a channel for a given session.
 *
 * Session list and rcu read side locks must be held by the caller.
 *
 * Returns 0 on success else a negative value.
 */
int ust_consumer_ask_channel(struct ust_app_session *ua_sess,
		struct ust_app_channel *ua_chan, struct consumer_output *consumer,
		struct consumer_socket *socket, struct ust_registry_session *registry)
{
	int ret;
	struct ltt_session *session;

	assert(ua_sess);
	assert(ua_chan);
	assert(consumer);
	assert(socket);
	assert(registry);

	if (!consumer->enabled) {
		ret = -LTTNG_ERR_NO_CONSUMER;
		DBG3("Consumer is disabled");
		goto error;
	}

	session = session_find_by_id(ua_sess->tracing_id);
	assert(session);

	pthread_mutex_lock(socket->lock);
	ret = ask_channel_creation(ua_sess, ua_chan, consumer, socket, registry);
	pthread_mutex_unlock(socket->lock);
	if (ret < 0) {
		ERR("ask_channel_creation consumer command failed");
		goto error;
	}

error:
	return ret;
}

/*
 * Send a get channel command to consumer using the given channel key.  The
 * channel object is populated and the stream list.
 *
 * Return 0 on success else a negative value.
 */
int ust_consumer_get_channel(struct consumer_socket *socket,
		struct ust_app_channel *ua_chan)
{
	int ret;
	struct lttcomm_consumer_msg msg;

	assert(ua_chan);
	assert(socket);

	memset(&msg, 0, sizeof(msg));
	msg.cmd_type = LTTNG_CONSUMER_GET_CHANNEL;
	msg.u.get_channel.key = ua_chan->key;

	pthread_mutex_lock(socket->lock);
	health_code_update();

	/* Send command and wait for OK reply. */
	ret = consumer_send_msg(socket, &msg);
	if (ret < 0) {
		goto error;
	}

	/* First, get the channel from consumer. */
	ret = ustctl_recv_channel_from_consumer(*socket->fd_ptr, &ua_chan->obj);
	if (ret < 0) {
		if (ret != -EPIPE) {
			ERR("Error recv channel from consumer %d with ret %d",
					*socket->fd_ptr, ret);
		} else {
			DBG3("UST app recv channel from consumer. Consumer is dead.");
		}
		goto error;
	}

	/* Next, get all streams. */
	while (1) {
		struct ust_app_stream *stream;

		/* Create UST stream */
		stream = ust_app_alloc_stream();
		if (stream == NULL) {
			ret = -ENOMEM;
			goto error;
		}

		/* Stream object is populated by this call if successful. */
		ret = ustctl_recv_stream_from_consumer(*socket->fd_ptr, &stream->obj);
		if (ret < 0) {
			free(stream);
			if (ret == -LTTNG_UST_ERR_NOENT) {
				DBG3("UST app consumer has no more stream available");
				break;
			}
			if (ret != -EPIPE) {
				ERR("Recv stream from consumer %d with ret %d",
						*socket->fd_ptr, ret);
			} else {
				DBG3("UST app recv stream from consumer. Consumer is dead.");
			}
			goto error;
		}

		/* Order is important this is why a list is used. */
		cds_list_add_tail(&stream->list, &ua_chan->streams.head);
		ua_chan->streams.count++;

		DBG2("UST app stream %d received successfully", ua_chan->streams.count);
	}

	/* This MUST match or else we have a synchronization problem. */
	assert(ua_chan->expected_stream_count == ua_chan->streams.count);

	/* Wait for confirmation that we can proceed with the streams. */
	ret = consumer_recv_status_reply(socket);
	if (ret < 0) {
		goto error;
	}

error:
	health_code_update();
	pthread_mutex_unlock(socket->lock);
	return ret;
}

/*
 * Send a destroy channel command to consumer using the given channel key.
 *
 * Note that this command MUST be used prior to a successful
 * LTTNG_CONSUMER_GET_CHANNEL because once this command is done successfully,
 * the streams are dispatched to the consumer threads and MUST be teardown
 * through the hang up process.
 *
 * Return 0 on success else a negative value.
 */
int ust_consumer_destroy_channel(struct consumer_socket *socket,
		struct ust_app_channel *ua_chan)
{
	int ret;
	struct lttcomm_consumer_msg msg;

	assert(ua_chan);
	assert(socket);

	memset(&msg, 0, sizeof(msg));
	msg.cmd_type = LTTNG_CONSUMER_DESTROY_CHANNEL;
	msg.u.destroy_channel.key = ua_chan->key;

	pthread_mutex_lock(socket->lock);
	health_code_update();

	ret = consumer_send_msg(socket, &msg);
	if (ret < 0) {
		goto error;
	}

error:
	health_code_update();
	pthread_mutex_unlock(socket->lock);
	return ret;
}

/*
 * Send a given stream to UST tracer.
 *
 * On success return 0 else a negative value.
 */
int ust_consumer_send_stream_to_ust(struct ust_app *app,
		struct ust_app_channel *channel, struct ust_app_stream *stream)
{
	int ret;

	assert(app);
	assert(stream);
	assert(channel);

	DBG2("UST consumer send stream to app %d", app->sock);

	/* Relay stream to application. */
	pthread_mutex_lock(&app->sock_lock);
	ret = ustctl_send_stream_to_ust(app->sock, channel->obj, stream->obj);
	pthread_mutex_unlock(&app->sock_lock);
	if (ret < 0) {
		if (ret != -EPIPE && ret != -LTTNG_UST_ERR_EXITING) {
			ERR("ustctl send stream handle %d to app pid: %d with ret %d",
					stream->obj->handle, app->pid, ret);
		} else {
			DBG3("UST app send stream to ust failed. Application is dead.");
		}
		goto error;
	}
	channel->handle = channel->obj->handle;

error:
	return ret;
}

/*
 * Send channel previously received from the consumer to the UST tracer.
 *
 * On success return 0 else a negative value.
 */
int ust_consumer_send_channel_to_ust(struct ust_app *app,
		struct ust_app_session *ua_sess, struct ust_app_channel *channel)
{
	int ret;

	assert(app);
	assert(ua_sess);
	assert(channel);
	assert(channel->obj);

	DBG2("UST app send channel to sock %d pid %d (name: %s, key: %" PRIu64 ")",
			app->sock, app->pid, channel->name, channel->tracing_channel_id);

	/* Send stream to application. */
	pthread_mutex_lock(&app->sock_lock);
	ret = ustctl_send_channel_to_ust(app->sock, ua_sess->handle, channel->obj);
	pthread_mutex_unlock(&app->sock_lock);
	if (ret < 0) {
		if (ret != -EPIPE && ret != -LTTNG_UST_ERR_EXITING) {
			ERR("Error ustctl send channel %s to app pid: %d with ret %d",
					channel->name, app->pid, ret);
		} else {
			DBG3("UST app send channel to ust failed. Application is dead.");
		}
		goto error;
	}

error:
	return ret;
}

/*
 * Handle the metadata requests from the UST consumer
 *
 * Return 0 on success else a negative value.
 */
int ust_consumer_metadata_request(struct consumer_socket *socket)
{
	int ret;
	ssize_t ret_push;
	struct lttcomm_metadata_request_msg request;
	struct buffer_reg_uid *reg_uid;
	struct ust_registry_session *ust_reg;
	struct lttcomm_consumer_msg msg;

	assert(socket);

	rcu_read_lock();
	health_code_update();

	/* Wait for a metadata request */
	pthread_mutex_lock(socket->lock);
	ret = consumer_socket_recv(socket, &request, sizeof(request));
	pthread_mutex_unlock(socket->lock);
	if (ret < 0) {
		goto end;
	}

	DBG("Metadata request received for session %" PRIu64 ", key %" PRIu64,
			request.session_id, request.key);

	reg_uid = buffer_reg_uid_find(request.session_id,
			request.bits_per_long, request.uid);
	if (reg_uid) {
		ust_reg = reg_uid->registry->reg.ust;
	} else {
		struct buffer_reg_pid *reg_pid =
			buffer_reg_pid_find(request.session_id_per_pid);
		if (!reg_pid) {
			DBG("PID registry not found for session id %" PRIu64,
					request.session_id_per_pid);

			memset(&msg, 0, sizeof(msg));
			msg.cmd_type = LTTNG_ERR_UND;
			(void) consumer_send_msg(socket, &msg);
			/*
			 * This is possible since the session might have been destroyed
			 * during a consumer metadata request. So here, return gracefully
			 * because the destroy session will push the remaining metadata to
			 * the consumer.
			 */
			ret = 0;
			goto end;
		}
		ust_reg = reg_pid->registry->reg.ust;
	}
	assert(ust_reg);

	pthread_mutex_lock(&ust_reg->lock);
	ret_push = ust_app_push_metadata(ust_reg, socket, 1);
	pthread_mutex_unlock(&ust_reg->lock);
	if (ret_push == -EPIPE) {
		DBG("Application or relay closed while pushing metadata");
	} else if (ret_push < 0) {
		ERR("Pushing metadata");
		ret = -1;
		goto end;
	} else {
		DBG("UST Consumer metadata pushed successfully");
	}
	ret = 0;

end:
	rcu_read_unlock();
	return ret;
}
