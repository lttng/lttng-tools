/*
 * Copyright (C) 2013 - Julien Desfossez <jdesfossez@efficios.com>
 *                      David Goulet <dgoulet@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define _GNU_SOURCE
#include <getopt.h>
#include <grp.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <inttypes.h>
#include <urcu/futex.h>
#include <urcu/uatomic.h>
#include <unistd.h>
#include <fcntl.h>
#include <config.h>

#include <lttng/lttng.h>
#include <common/common.h>
#include <common/compat/poll.h>
#include <common/compat/socket.h>
#include <common/defaults.h>
#include <common/futex.h>
#include <common/sessiond-comm/sessiond-comm.h>
#include <common/sessiond-comm/inet.h>
#include <common/sessiond-comm/relayd.h>
#include <common/uri.h>
#include <common/utils.h>

#include "cmd.h"
#include "utils.h"
#include "lttng-relayd.h"
#include "lttng-viewer.h"

static struct lttng_uri *live_uri;

/*
 * Quit pipe for all threads. This permits a single cancellation point
 * for all threads when receiving an event on the pipe.
 */
static int live_thread_quit_pipe[2] = { -1, -1 };

/*
 * This pipe is used to inform the worker thread that a command is queued and
 * ready to be processed.
 */
static int live_relay_cmd_pipe[2] = { -1, -1 };

/* Shared between threads */
static int live_dispatch_thread_exit;

static pthread_t live_listener_thread;
static pthread_t live_dispatcher_thread;
static pthread_t live_worker_thread;

/*
 * Relay command queue.
 *
 * The relay_thread_listener and relay_thread_dispatcher communicate with this
 * queue.
 */
static struct relay_cmd_queue viewer_cmd_queue;

static uint64_t last_relay_viewer_session_id;

/*
 * Cleanup the daemon
 */
static
void live_cleanup(void)
{
	DBG("Cleaning up");

	/* Close thread quit pipes */
	utils_close_pipe(live_thread_quit_pipe);
	free(live_uri);
}

/*
 * Write to writable pipe used to notify a thread.
 */
static
int live_notify_thread_pipe(int wpipe)
{
	int ret;

	do {
		ret = write(wpipe, "!", 1);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0 || ret != 1) {
		PERROR("write poll pipe");
	}

	return ret;
}

/*
 * Stop all threads by closing the thread quit pipe.
 */
static
void live_stop_threads(void)
{
	int ret;

	/* Stopping all threads */
	DBG("Terminating all live threads");
	ret = live_notify_thread_pipe(live_thread_quit_pipe[1]);
	if (ret < 0) {
		ERR("write error on thread quit pipe");
	}

	/* Dispatch thread */
	CMM_STORE_SHARED(live_dispatch_thread_exit, 1);
	futex_nto1_wake(&viewer_cmd_queue.futex);
}

/*
 * Init thread quit pipe.
 *
 * Return -1 on error or 0 if all pipes are created.
 */
static
int live_init_thread_quit_pipe(void)
{
	int ret;

	ret = utils_create_pipe_cloexec(live_thread_quit_pipe);

	return ret;
}

/*
 * Create a poll set with O_CLOEXEC and add the thread quit pipe to the set.
 */
static
int live_create_thread_poll_set(struct lttng_poll_event *events, int size)
{
	int ret;

	if (events == NULL || size == 0) {
		ret = -1;
		goto error;
	}

	ret = lttng_poll_create(events, size, LTTNG_CLOEXEC);
	if (ret < 0) {
		goto error;
	}

	/* Add quit pipe */
	ret = lttng_poll_add(events, live_thread_quit_pipe[0], LPOLLIN);
	if (ret < 0) {
		goto error;
	}

	return 0;

error:
	return ret;
}

/*
 * Check if the thread quit pipe was triggered.
 *
 * Return 1 if it was triggered else 0;
 */
static
int live_check_thread_quit_pipe(int fd, uint32_t events)
{
	if (fd == live_thread_quit_pipe[0] && (events & LPOLLIN)) {
		return 1;
	}

	return 0;
}

/*
 * Create and init socket from uri.
 */
static
struct lttcomm_sock *live_relay_init_sock(struct lttng_uri *uri)
{
	int ret;
	struct lttcomm_sock *sock = NULL;

	sock = lttcomm_alloc_sock_from_uri(uri);
	if (sock == NULL) {
		ERR("Allocating socket");
		goto error;
	}

	ret = lttcomm_create_sock(sock);
	if (ret < 0) {
		goto error;
	}
	DBG("Listening on sock %d for live", sock->fd);

	ret = sock->ops->bind(sock);
	if (ret < 0) {
		goto error;
	}

	ret = sock->ops->listen(sock, -1);
	if (ret < 0) {
		goto error;

	}

	return sock;

error:
	if (sock) {
		lttcomm_destroy_sock(sock);
	}
	return NULL;
}

/*
 * This thread manages the listening for new connections on the network
 */
static
void *live_relay_thread_listener(void *data)
{
	int i, ret, pollfd, err = -1;
	int val = 1;
	uint32_t revents, nb_fd;
	struct lttng_poll_event events;
	struct lttcomm_sock *live_control_sock;

	DBG("[thread] Relay live listener started");

	live_control_sock = live_relay_init_sock(live_uri);
	if (!live_control_sock) {
		goto error_sock_control;
	}

	/*
	 * Pass 3 as size here for the thread quit pipe, control and data socket.
	 */
	ret = live_create_thread_poll_set(&events, 2);
	if (ret < 0) {
		goto error_create_poll;
	}

	/* Add the control socket */
	ret = lttng_poll_add(&events, live_control_sock->fd, LPOLLIN | LPOLLRDHUP);
	if (ret < 0) {
		goto error_poll_add;
	}

	while (1) {
		DBG("Listener accepting live viewers connections");

restart:
		ret = lttng_poll_wait(&events, -1);
		if (ret < 0) {
			/*
			 * Restart interrupted system call.
			 */
			if (errno == EINTR) {
				goto restart;
			}
			goto error;
		}

		nb_fd = ret;

		DBG("Relay new viewer connection received");
		for (i = 0; i < nb_fd; i++) {
			/* Fetch once the poll data */
			revents = LTTNG_POLL_GETEV(&events, i);
			pollfd = LTTNG_POLL_GETFD(&events, i);

			/* Thread quit pipe has been closed. Killing thread. */
			ret = live_check_thread_quit_pipe(pollfd, revents);
			if (ret) {
				err = 0;
				goto exit;
			}

			if (revents & (LPOLLERR | LPOLLHUP | LPOLLRDHUP)) {
				ERR("socket poll error");
				goto error;
			} else if (revents & LPOLLIN) {
				/*
				 * Get allocated in this thread,
				 * enqueued to a global queue, dequeued
				 * and freed in the worker thread.
				 */
				struct relay_command *relay_cmd;
				struct lttcomm_sock *newsock;

				relay_cmd = zmalloc(sizeof(struct relay_command));
				if (relay_cmd == NULL) {
					PERROR("relay command zmalloc");
					goto error;
				}

				assert(pollfd == live_control_sock->fd);
				newsock = live_control_sock->ops->accept(
						live_control_sock);
				if (!newsock) {
					PERROR("accepting control sock");
					free(relay_cmd);
					goto error;
				}
				DBG("Relay viewer connection accepted,"
						"socket %d", newsock->fd);
				ret = setsockopt(newsock->fd, SOL_SOCKET, SO_REUSEADDR,
						&val, sizeof(int));
				if (ret < 0) {
					PERROR("setsockopt inet");
					lttcomm_destroy_sock(newsock);
					free(relay_cmd);
					goto error;
				}
				relay_cmd->sock = newsock;
				/*
				 * Lock free enqueue the request.
				 */
				cds_wfq_enqueue(&viewer_cmd_queue.queue,
						&relay_cmd->node);

				/*
				 * Wake the dispatch queue futex. Implicit memory
				 * barrier with the exchange in cds_wfq_enqueue.
				 */
				futex_nto1_wake(&viewer_cmd_queue.futex);
			}
		}
	}

exit:
error:
error_poll_add:
	lttng_poll_clean(&events);
error_create_poll:
	if (live_control_sock->fd >= 0) {
		ret = live_control_sock->ops->close(live_control_sock);
		if (ret) {
			PERROR("close");
		}
	}
	lttcomm_destroy_sock(live_control_sock);
error_sock_control:
	if (err) {
		DBG("Live viewer listener thread exited with error");
	}
	DBG("Live viewer listener thread cleanup complete");
	live_stop_threads();
	return NULL;
}

/*
 * This thread manages the dispatching of the requests to worker threads
 */
static
void *live_relay_thread_dispatcher(void *data)
{
	int ret;
	struct cds_wfq_node *node;
	struct relay_command *relay_cmd = NULL;

	DBG("[thread] Live viewer relay dispatcher started");

	while (!CMM_LOAD_SHARED(live_dispatch_thread_exit)) {
		/* Atomically prepare the queue futex */
		futex_nto1_prepare(&viewer_cmd_queue.futex);

		do {
			/* Dequeue commands */
			node = cds_wfq_dequeue_blocking(&viewer_cmd_queue.queue);
			if (node == NULL) {
				DBG("Woken up but nothing in the live-viewer "
						"relay command queue");
				/* Continue thread execution */
				break;
			}

			relay_cmd = caa_container_of(node, struct relay_command, node);
			DBG("Dispatching viewer request waiting on sock %d",
					relay_cmd->sock->fd);

			/*
			 * Inform worker thread of the new request. This call
			 * is blocking so we can be assured that the data will
			 * be read at some point in time or wait to the end of
			 * the world :)
			 */
			do {
				ret = write(live_relay_cmd_pipe[1], relay_cmd,
						sizeof(struct relay_command));
			} while (ret < 0 && errno == EINTR);
			free(relay_cmd);
			if (ret < 0 || ret != sizeof(struct relay_command)) {
				PERROR("write cmd pipe");
				goto error;
			}
		} while (node != NULL);

		/* Futex wait on queue. Blocking call on futex() */
		futex_nto1_wait(&viewer_cmd_queue.futex);
	}

error:
	DBG("Live viewer dispatch thread dying");
	live_stop_threads();
	return NULL;
}

/*
 * viewer_connect: establish connection with the viewer and check the versions.
 */
static
int viewer_connect(struct lttng_viewer_cmd *recv_hdr,
		struct relay_command *cmd, struct lttng_ht *streams_ht)
{
	int ret;
	struct lttng_viewer_connect reply, msg;

	assert(cmd);

	cmd->version_check_done = 1;

	/* Get version from the other side. */
	ret = cmd->sock->ops->recvmsg(cmd->sock, &msg, sizeof(msg), 0);
	if (ret < 0 || ret != sizeof(msg)) {
		if (ret == 0) {
			/* Orderly shutdown. Not necessary to print an error. */
			DBG("Socket %d did an orderly shutdown", cmd->sock->fd);
		} else {
			ERR("Relay failed to receive the version values.");
		}
		ret = -1;
		goto end;
	}

	/* FIXME : new protocol version or reuse lttng-tools version ? */
	reply.major = RELAYD_VERSION_COMM_MAJOR;
	reply.minor = RELAYD_VERSION_COMM_MINOR;

	/* Major versions must be the same */
	if (reply.major != be32toh(msg.major)) {
		DBG("Incompatible major versions (%u vs %u), deleting session",
				reply.major, be32toh(msg.major));
		ret = 0;
		goto end;
	}

	cmd->major = reply.major;
	/* We adapt to the lowest compatible version */
	if (reply.minor <= be32toh(msg.minor)) {
		cmd->minor = reply.minor;
	} else {
		cmd->minor = be32toh(msg.minor);
	}

	if (be32toh(msg.type) == VIEWER_CLIENT_COMMAND) {
		cmd->type = RELAY_VIEWER_COMMAND;
	} else if (be32toh(msg.type) == VIEWER_CLIENT_NOTIFICATION) {
		cmd->type = RELAY_VIEWER_NOTIFICATION;
	} else {
		ERR("Unknown connection type : %u", be32toh(msg.type));
		ret = -1;
		goto end;
	}

	/*
	 * TODO for notification connection : check the viewer_session_id
	 * provided by the client, lookup the corresponding command connection
	 * and link the two "relayd_command"
	 */

	reply.major = htobe32(reply.major);
	reply.minor = htobe32(reply.minor);
	if (cmd->type == RELAY_VIEWER_COMMAND) {
		reply.viewer_session_id = htobe64(++last_relay_viewer_session_id);
	}
	ret = cmd->sock->ops->sendmsg(cmd->sock, &reply,
			sizeof(struct lttng_viewer_connect), 0);
	if (ret < 0) {
		ERR("Relay sending version");
	}

	DBG("Version check done using protocol %u.%u", cmd->major,
			cmd->minor);
	ret = 0;

end:
	return ret;
}

/*
 * viewer_list_sessions: send the viewer the list of current sessions.
 */
static
int viewer_list_sessions(struct lttng_viewer_cmd *recv_hdr,
		struct relay_command *cmd, struct lttng_ht *streams_ht,
		struct lttng_ht *sessions_ht)
{
	int ret;
	struct lttng_viewer_list_sessions session_list;
	unsigned long count;
	long approx_before, approx_after;
	struct lttng_ht_node_ulong *node;
	struct lttng_ht_iter iter;
	struct lttng_viewer_session send_session;
	struct relay_session *session;

	DBG("List sessions received");

	if (cmd->version_check_done == 0) {
		ERR("Trying to list sessions before version check");
		ret = -1;
		goto end_no_session;
	}
	rcu_read_lock();
	cds_lfht_count_nodes(sessions_ht->ht, &approx_before, &count, &approx_after);
	session_list.sessions_count = htobe32(count);
	ret = cmd->sock->ops->sendmsg(cmd->sock, &session_list,
			sizeof(session_list), 0);
	if (ret < 0) {
		ERR("Relay sending sessions list");
		goto end_unlock;
	}

	cds_lfht_for_each_entry(sessions_ht->ht, &iter.iter, node, node) {
		node = lttng_ht_iter_get_node_ulong(&iter);
		if (!node) {
			goto end_unlock;
		}
		session = caa_container_of(node, struct relay_session,
				session_n);
		strncpy(send_session.session_name,
				session->session_name,
				sizeof(send_session.session_name));
		strncpy(send_session.hostname,
				session->hostname,
				sizeof(send_session.hostname));
		send_session.id = htobe64(session->id);
		send_session.live_timer = htobe32(session->live_timer);
		send_session.clients = htobe32(session->viewer_attached);
		ret = cmd->sock->ops->sendmsg(cmd->sock,
				&send_session,
				sizeof(struct lttng_viewer_session), 0);
		if (ret < 0) {
			ERR("Relay sending session info");
			goto end_unlock;
		}
	}
	rcu_read_unlock();
	ret = 0;
	goto end;

end_unlock:
	rcu_read_unlock();

end:
end_no_session:
	return ret;
}

/*
 * relay_init_viewer_stream: allocate and init a new viewer_stream.
 *
 * Copies the values from the stream passed in parameter and insert the new
 * stream in the viewer_streams_ht.
 * Must be called with rcu_read_lock held.
 * Returns 0 on success or a negative value on error.
 */
static
int relay_init_viewer_stream(struct relay_stream *stream,
		struct lttng_ht *viewer_streams_ht)
{
	struct relay_viewer_stream *viewer_stream;
	int ret;

	viewer_stream = zmalloc(sizeof(struct relay_viewer_stream));
	if (viewer_stream == NULL) {
		PERROR("relay viewer stream zmalloc");
		ret = -1;
		goto error;
	}

	viewer_stream->read_fd = -1;
	viewer_stream->index_read_fd = -1;
	viewer_stream->session = stream->session;
	viewer_stream->stream = stream;
	viewer_stream->stream_handle = stream->stream_handle;
	viewer_stream->path_name = strndup(stream->path_name, PATH_MAX);
	viewer_stream->channel_name = strndup(stream->channel_name, NAME_MAX);
	viewer_stream->total_index_received = stream->total_index_received;
	viewer_stream->tracefile_size = stream->tracefile_size;
	viewer_stream->tracefile_count = stream->tracefile_count;
	viewer_stream->metadata_flag = stream->metadata_flag;
	viewer_stream->beacon_ts_end = -1ULL;

	viewer_stream->ctf_trace = stream->ctf_trace;
	uatomic_inc(&stream->ctf_trace->refcount);

	lttng_ht_node_init_u64(&viewer_stream->stream_n,
			stream->stream_handle);
	lttng_ht_add_unique_u64(viewer_streams_ht,
			&viewer_stream->stream_n);

	/* FIXME : safe ? */
	stream->viewer_stream = viewer_stream;

	ret = 0;

error:
	return ret;
}

/*
 * viewer_attach_session: send the viewer the list of current sessions.
 */
static
int viewer_attach_session(struct lttng_viewer_cmd *recv_hdr,
		struct relay_command *cmd, struct lttng_ht *streams_ht,
		struct lttng_ht *sessions_ht,
		struct lttng_ht *viewer_streams_ht)
{
	int ret;
	struct lttng_viewer_attach_session_request request;
	struct lttng_viewer_attach_session_response response;
	struct lttng_viewer_stream send_stream;
	struct relay_stream *stream;
	struct relay_viewer_stream *viewer_stream;
	struct lttng_ht_node_ulong *node;
	struct lttng_ht_node_u64 *node64;
	struct lttng_ht_iter iter;
	struct relay_session *session;
	int send_streams = 0;
	int nb_streams = 0;

	DBG("Attach session received");

	if (cmd->version_check_done == 0) {
		ERR("Trying to attach session before version check");
		ret = -1;
		goto end_no_session;
	}
	ret = cmd->sock->ops->recvmsg(cmd->sock, &request, sizeof(request), 0);
	if (ret < 0 || ret != sizeof(request)) {
		if (ret == 0) {
			/* Orderly shutdown. Not necessary to print an error. */
			DBG("Socket %d did an orderly shutdown", cmd->sock->fd);
		} else {
			ERR("Relay failed to receive the attach parameters.");
		}
		ret = -1;
		goto error;
	}

	rcu_read_lock();
	lttng_ht_lookup(sessions_ht,
			(void *)((unsigned long) be64toh(request.session_id)),
			&iter);
	node = lttng_ht_iter_get_node_ulong(&iter);
	if (node == NULL) {
		DBG("Relay session %" PRIu64 " not found",
				be64toh(request.session_id));
		ret = -1;
		goto end_unlock;
	}

	session = caa_container_of(node, struct relay_session, session_n);
	if (!session) {
		DBG("Unknown session");
		response.status = htobe32(VIEWER_ATTACH_UNK);
	} else if (cmd->session == session) {
		/* same viewer already attached, just send the stream list. */
		send_streams = 1;
		response.status = htobe32(VIEWER_ATTACH_OK);
	} else if (session->viewer_attached != 0) {
		DBG("Already a viewer attached");
		response.status = htobe32(VIEWER_ATTACH_ALREADY);
	} else if (session->live_timer == 0) {
		DBG("Not live session");
		response.status = htobe32(VIEWER_ATTACH_NOT_LIVE);
	} else {
		session->viewer_attached++;
		send_streams = 1;
		response.status = htobe32(VIEWER_ATTACH_OK);
		cmd->session = session;
	}

	switch (be32toh(request.seek)) {
	case VIEWER_SEEK_BEGINNING:
		/* Default behaviour. */
		break;
	case VIEWER_SEEK_LAST:
		/* TODO */
		break;
	default:
		ERR("Wrong seek parameter");
		response.status = htobe32(VIEWER_ATTACH_SEEK_ERR);
		send_streams = 0;
	}

	if (send_streams) {
		/* We should only be there if we have a session to attach to. */
		assert(session);

		/*
		 * Fill the viewer_streams_ht to count the number of streams
		 * ready to be sent and avoid concurrency issues on the
		 * streams_ht and don't rely on a total session stream count.
		 */
		cds_lfht_for_each_entry(streams_ht->ht, &iter.iter, node, node) {
			node = lttng_ht_iter_get_node_ulong(&iter);
			if (node) {
				stream = caa_container_of(node,
						struct relay_stream, stream_n);
				if (stream->session == cmd->session) {
					/*
					 * Don't send streams with no ctf_trace,
					 * they are not ready to be read.
					 */
					pthread_mutex_lock(&stream->lock);
					if (!stream->ctf_trace) {
						pthread_mutex_unlock(&stream->lock);
						continue;
					}
					if (!stream->viewer_stream) {
						ret = relay_init_viewer_stream(
								stream,
								viewer_streams_ht);
						if (ret < 0) {
							pthread_mutex_unlock(&stream->lock);
							goto end_unlock;
						}
					}
					pthread_mutex_unlock(&stream->lock);
					nb_streams++;
				}
			}
		}
		response.streams_count = htobe32(nb_streams);
	}

	ret = cmd->sock->ops->sendmsg(cmd->sock, &response,
			sizeof(response), 0);
	if (ret < 0) {
		ERR("Relay sending viewer attach response");
		goto end_unlock;
	}

	/*
	 * Unknown or busy session, just return gracefully, the viewer
	 * knows what is happening.
	 */
	if (!send_streams) {
		ret = 0;
		goto end_unlock;
	}

	cds_lfht_for_each_entry(viewer_streams_ht->ht, &iter.iter, node, node) {
		node64 = lttng_ht_iter_get_node_u64(&iter);
		if (node64) {
			viewer_stream = caa_container_of(node64,
					struct relay_viewer_stream, stream_n);
			if (viewer_stream->session == cmd->session) {
				send_stream.id = htobe64(viewer_stream->stream_handle);
				send_stream.ctf_trace_id =
					htobe64(viewer_stream->ctf_trace->id);
				send_stream.metadata_flag = htobe32(
						viewer_stream->metadata_flag);
				strncpy(send_stream.path_name,
						viewer_stream->path_name,
						sizeof(send_stream.path_name));
				strncpy(send_stream.channel_name,
						viewer_stream->channel_name,
						sizeof(send_stream.channel_name));
				ret = cmd->sock->ops->sendmsg(cmd->sock, &send_stream,
						sizeof(send_stream), 0);
				if (ret < 0) {
					ERR("Relay sending stream %" PRIu64,
							viewer_stream->stream_handle);
					goto end_unlock;
				}
				DBG("Sent stream %" PRIu64 " to viewer",
						viewer_stream->stream_handle);
			}
		}
	}
	ret = 0;

end_unlock:
	rcu_read_unlock();
end_no_session:
error:
	return ret;
}

static int open_index(struct relay_viewer_stream *stream)
{
	int ret;
	char fullpath[PATH_MAX];
	struct lttng_packet_index_file_hdr hdr;

	if (stream->tracefile_size > 0) {
		/* For now we don't support on-disk ring buffer. */
		ret = -1;
		goto end;
	} else {
		ret = snprintf(fullpath, sizeof(fullpath), "%s/" DEFAULT_INDEX_DIR
				"/%s" DEFAULT_INDEX_FILE_SUFFIX,
				stream->path_name, stream->channel_name);
		if (ret < 0) {
			PERROR("snprintf index path");
			goto error;
		}
	}

	DBG("Opening index file %s in read only", fullpath);
	ret = open(fullpath, O_RDONLY);
	if (ret < 0) {
		if (errno == ENOENT) {
			ret = ENOENT;
			goto error;
		} else {
			PERROR("opening index in read-only");
		}
		goto error;
	}
	stream->index_read_fd = ret;
	DBG("Opening index file %s in read only, (fd: %d)", fullpath, ret);

	do {
		ret = read(stream->index_read_fd, &hdr, sizeof(hdr));
	} while (ret < 0 && errno == EINTR);
	if (ret < 0) {
		PERROR("Reading index header");
		goto error;
	}
	/* FIXME : check hdr values */
	ret = 0;

error:
end:
	return ret;
}

/*
 * Get viewer stream from stream id.
 * Need to be called with RCU read-side lock held.
 */
struct relay_viewer_stream *relay_viewer_stream_from_stream_id(
		uint64_t stream_id,
		struct lttng_ht *viewer_streams_ht)
{
	struct lttng_ht_node_u64 *node;
	struct lttng_ht_iter iter;
	struct relay_viewer_stream *ret;

	lttng_ht_lookup(viewer_streams_ht,
			&stream_id,
			&iter);
	node = lttng_ht_iter_get_node_u64(&iter);
	if (node == NULL) {
		DBG("Relay viewer stream %" PRIu64 " not found", stream_id);
		ret = NULL;
		goto end;
	}

	ret = caa_container_of(node, struct relay_viewer_stream, stream_n);

end:
	return ret;
}

/*
 * viewer_get_next_index: send the next index for a stream
 */
static
int viewer_get_next_index(struct lttng_viewer_cmd *recv_hdr,
		struct relay_command *cmd, struct lttng_ht *viewer_streams_ht,
		struct lttng_ht *sessions_ht)
{
	struct lttng_viewer_get_next_index request_index;
	struct lttng_viewer_index viewer_index;
	struct lttng_packet_index packet_index;
	struct relay_viewer_stream *stream;
	int ret;

	DBG("Viewer get next index");

	if (cmd->version_check_done == 0) {
		ERR("Trying to request index before version check");
		ret = -1;
		goto end_no_session;
	}

	ret = cmd->sock->ops->recvmsg(cmd->sock, &request_index,
			sizeof(request_index), 0);
	if (ret < 0 || ret != sizeof(request_index)) {
		ret = -1;
		ERR("Relay didn't receive the whole packet");
		goto end;
	}

	rcu_read_lock();
	stream = relay_viewer_stream_from_stream_id(be64toh(request_index.stream_id),
			viewer_streams_ht);
	if (!stream) {
		ret = -1;
		goto end_unlock;
	}

	/*
	 * The viewer should not ask for index on metadata stream.
	 */
	if (stream->metadata_flag) {
		viewer_index.status = htobe32(VIEWER_INDEX_HUP);
		goto send_reply;
	}
	viewer_index.new_metadata = 0;

	/* first time, we open the index file */
	if (stream->index_read_fd < 0) {
		ret = open_index(stream);
		if (ret == ENOENT) {
			/*
			 * The index is created only when the first data packet
			 * arrives, it might not be ready at the beginning of
			 * the session
			 */
			viewer_index.status = htobe32(VIEWER_INDEX_RETRY);
			goto send_reply;
		} else if (ret < 0) {
			viewer_index.status = htobe32(VIEWER_INDEX_ERR);
			goto send_reply;
		}
	}

	if (stream->beacon_ts_end != -1ULL) {
		viewer_index.status = htobe32(VIEWER_INDEX_INACTIVE);
		viewer_index.timestamp_end = htobe64(stream->beacon_ts_end);
	} else if (stream->total_index_received == 0 && stream->stream) {
		/* No index received yet but session is alive. */
		viewer_index.status = htobe32(VIEWER_INDEX_RETRY);
	} else if (!stream->stream &&
			stream->total_index_received == stream->last_sent_index) {
		/* Last index sent and stream closed */
		viewer_index.status = htobe32(VIEWER_INDEX_HUP);
	} else if (stream->total_index_received <= stream->last_sent_index) {
		/* No new index to send, retry later. */
		viewer_index.status = htobe32(VIEWER_INDEX_RETRY);
	} else {
		if (!stream->ctf_trace->metadata_received ||
				stream->ctf_trace->metadata_received >
				stream->ctf_trace->metadata_sent) {
			viewer_index.new_metadata = htobe32(1);
		}
		do {
			ret = read(stream->index_read_fd, &packet_index,
					sizeof(packet_index));
		} while (ret < 0 && errno == EINTR);
		if (ret < sizeof(packet_index)) {
			PERROR("Relay reading index file");
			viewer_index.status = htobe32(VIEWER_INDEX_ERR);
		} else {
			viewer_index.status = htobe32(VIEWER_INDEX_OK);
			stream->last_sent_index++;
		}
		/*
		 * Indexes are stored in big endian, no need to switch
		 * before sending.
		 */
		viewer_index.offset = packet_index.offset;
		viewer_index.packet_size = packet_index.packet_size;
		viewer_index.content_size = packet_index.content_size;
		viewer_index.timestamp_begin = packet_index.timestamp_begin;
		viewer_index.timestamp_end = packet_index.timestamp_end;
		viewer_index.events_discarded = packet_index.events_discarded;
		viewer_index.stream_id = packet_index.stream_id;
	}

send_reply:
	ret = cmd->sock->ops->sendmsg(cmd->sock, &viewer_index,
			sizeof(viewer_index), 0);
	if (ret < 0) {
		ERR("Relay index to viewer");
		goto end_unlock;
	}

	DBG("Index %" PRIu64 "for stream %" PRIu64 "sent",
			stream->last_sent_index, stream->stream_handle);

end_unlock:
	rcu_read_unlock();

end_no_session:
end:
	return ret;
}

/*
 * viewer_get_packet: send the next index for a stream
 */
static
int viewer_get_packet(struct lttng_viewer_cmd *recv_hdr,
		struct relay_command *cmd, struct lttng_ht *viewer_streams_ht)
{
	struct lttng_viewer_get_packet get_packet_info;
	struct lttng_viewer_trace_packet reply;
	struct relay_viewer_stream *stream;
	char *data = NULL;
	int ret;
	uint64_t len = 0;
	int send_data = 0;

	DBG2("Relay get data packet");

	if (cmd->version_check_done == 0) {
		ERR("Trying to get packet before version check");
		ret = -1;
		goto end;
	}

	ret = cmd->sock->ops->recvmsg(cmd->sock, &get_packet_info,
			sizeof(get_packet_info), 0);
	if (ret < 0 || ret != sizeof(get_packet_info)) {
		ret = -1;
		ERR("Relay didn't receive the whole packet");
		goto end;
	}

	rcu_read_lock();
	stream = relay_viewer_stream_from_stream_id(
			be64toh(get_packet_info.stream_id),
			viewer_streams_ht);
	if (!stream) {
		goto error;
	}
	assert(stream->ctf_trace);

	/*
	 * First time we read this stream, we need open the tracefile, we
	 * should only arrive here if an index has already been sent to the
	 * viewer, so the tracefile must exist, if it does not it is a fatal
	 * error.
	 */
	if (stream->read_fd < 0) {
		char fullpath[PATH_MAX];

		ret = snprintf(fullpath, PATH_MAX, "%s/%s", stream->path_name,
				stream->channel_name);
		if (ret < 0) {
			goto error;
		}
		ret = open(fullpath, O_RDONLY);
		if (ret < 0) {
			PERROR("Relay opening trace file");
			goto error;
		}
		stream->read_fd = ret;
	}
	if (!stream->ctf_trace->metadata_received ||
			stream->ctf_trace->metadata_received >
			stream->ctf_trace->metadata_sent) {
		reply.status = htobe32(VIEWER_GET_PACKET_NEW_METADATA);
		goto send_reply;
	}

	len = be64toh(get_packet_info.len);
	data = zmalloc(len);
	if (!data) {
		PERROR("relay data zmalloc");
		goto error;
	}

	ret = lseek(stream->read_fd, be64toh(get_packet_info.offset), SEEK_SET);
	if (ret < 0) {
		PERROR("lseek");
		goto error;
	}
	ret = read(stream->read_fd, data, len);
	if (ret < len) {
		PERROR("Relay reading trace file, fd : %d, offset : %lu", stream->read_fd,
				be64toh(get_packet_info.offset));
		goto error;
	}
	reply.status = htobe32(VIEWER_GET_PACKET_OK);
	reply.len = htobe64(len);
	send_data = 1;
	goto send_reply;

error:
	reply.status = htobe32(VIEWER_GET_PACKET_ERR);

send_reply:
	ret = cmd->sock->ops->sendmsg(cmd->sock, &reply, sizeof(reply), 0);
	if (ret < 0) {
		ERR("Relay data header to viewer");
		goto end_unlock;
	}

	if (send_data) {
		ret = cmd->sock->ops->sendmsg(cmd->sock, data, len, 0);
		if (ret < 0) {
			ERR("Relay send data to viewer");
			goto end_unlock;
		}
	}

	free(data);
	DBG("Sent %" PRIu64 " bytes for stream %" PRIu64, len,
			be64toh(get_packet_info.stream_id));

end_unlock:
	rcu_read_unlock();

end:
	return ret;
}

/*
 * viewer_get_metadata: send the session's metadata
 */
static
int viewer_get_metadata(struct lttng_viewer_cmd *recv_hdr,
		struct relay_command *cmd, struct lttng_ht *viewer_streams_ht)
{
	int ret = 0;
	struct lttng_viewer_get_metadata request;
	struct lttng_viewer_metadata_packet reply;
	struct relay_viewer_stream *stream;
	uint64_t len = 0;
	char *data = NULL;

	DBG("Relay get metadata");

	if (cmd->version_check_done == 0) {
		ERR("Trying to get metadata before version check");
		ret = -1;
		goto end;
	}

	ret = cmd->sock->ops->recvmsg(cmd->sock, &request,
			sizeof(request), 0);
	if (ret < 0 || ret != sizeof(request)) {
		ret = -1;
		ERR("Relay didn't receive the whole packet");
		goto end;
	}

	rcu_read_lock();
	stream = relay_viewer_stream_from_stream_id(
			be64toh(request.stream_id),
			viewer_streams_ht);
	if (!stream || !stream->metadata_flag) {
		ERR("Invalid metadata stream");
		goto error;
	}
	assert(stream->ctf_trace);
	assert(stream->ctf_trace->metadata_sent <=
			stream->ctf_trace->metadata_received);

	len = stream->ctf_trace->metadata_received -
		stream->ctf_trace->metadata_sent;
	if (len == 0) {
		reply.status = htobe32(VIEWER_NO_NEW_METADATA);
		goto send_reply;
	}

	reply.len = htobe64(len);
	/* first time, we open the metadata file */
	if (stream->read_fd < 0) {
		char fullpath[PATH_MAX];

		ret = snprintf(fullpath, PATH_MAX, "%s/%s", stream->path_name,
				stream->channel_name);
		if (ret < 0) {
			goto error;
		}
		ret = open(fullpath, O_RDONLY);
		if (ret < 0) {
			PERROR("Relay opening metadata file");
			goto error;
		}
		stream->read_fd = ret;
	}

	data = zmalloc(len);
	if (!data) {
		PERROR("viewer metadata zmalloc");
		goto error;
	}

	ret = read(stream->read_fd, data, len);
	if (ret < len) {
		PERROR("Relay reading metadata file");
		goto error;
	}
	stream->ctf_trace->metadata_sent += ret;
	reply.status = htobe32(VIEWER_METADATA_OK);
	goto send_reply;

error:
	reply.status = htobe32(VIEWER_METADATA_ERR);

send_reply:
	ret = cmd->sock->ops->sendmsg(cmd->sock, &reply, sizeof(reply), 0);
	if (ret < 0) {
		ERR("Relay data header to viewer");
		goto end_unlock;
	}

	if (len > 0) {
		ret = cmd->sock->ops->sendmsg(cmd->sock, data, len, 0);
		if (ret < 0) {
			ERR("Relay send data to viewer");
			goto end_unlock;
		}
	}

	free(data);
	DBG("Sent %" PRIu64 " bytes of metadata for stream %" PRIu64, len,
			be64toh(request.stream_id));

	DBG("Metadata sent");

end_unlock:
	rcu_read_unlock();
end:
	return ret;
}

/*
 * live_relay_unknown_command: send -1 if received unknown command
 */
static
void live_relay_unknown_command(struct relay_command *cmd)
{
	struct lttcomm_relayd_generic_reply reply;
	int ret;

	reply.ret_code = htobe32(LTTNG_ERR_UNK);
	ret = cmd->sock->ops->sendmsg(cmd->sock, &reply,
			sizeof(struct lttcomm_relayd_generic_reply), 0);
	if (ret < 0) {
		ERR("Relay sending unknown command");
	}
}

/*
 * relay_process_control: Process the commands received on the control socket
 */
static
int live_relay_process_control(struct lttng_viewer_cmd *recv_hdr,
		struct relay_command *cmd, struct lttng_ht *streams_ht,
		struct lttng_ht *sessions_ht,
		struct lttng_ht *viewer_streams_ht)
{
	int ret = 0;

	switch (be32toh(recv_hdr->cmd)) {
	case VIEWER_CONNECT:
		ret = viewer_connect(recv_hdr, cmd, streams_ht);
		break;
	case VIEWER_LIST_SESSIONS:
		ret = viewer_list_sessions(recv_hdr, cmd, streams_ht,
				sessions_ht);
		break;
	case VIEWER_ATTACH_SESSION:
		ret = viewer_attach_session(recv_hdr, cmd, streams_ht,
				sessions_ht, viewer_streams_ht);
		break;
	case VIEWER_GET_NEXT_INDEX:
		ret = viewer_get_next_index(recv_hdr, cmd, viewer_streams_ht,
				sessions_ht);
		break;
	case VIEWER_GET_PACKET:
		ret = viewer_get_packet(recv_hdr, cmd, viewer_streams_ht);
		break;
	case VIEWER_GET_METADATA:
		ret = viewer_get_metadata(recv_hdr, cmd, viewer_streams_ht);
		break;
	default:
		ERR("Received unknown viewer command (%u)", be32toh(recv_hdr->cmd));
		live_relay_unknown_command(cmd);
		ret = -1;
		goto end;
	}

end:
	return ret;
}

static
void live_relay_cleanup_poll_connection(struct lttng_poll_event *events, int pollfd)
{
	int ret;

	lttng_poll_del(events, pollfd);

	ret = close(pollfd);
	if (ret < 0) {
		ERR("Closing pollfd %d", pollfd);
	}
}

static
int live_relay_add_connection(int fd, struct lttng_poll_event *events,
		struct lttng_ht *relay_connections_ht)
{
	struct relay_command *relay_connection;
	int ret;

	relay_connection = zmalloc(sizeof(struct relay_command));
	if (relay_connection == NULL) {
		PERROR("Relay command zmalloc");
		goto error;
	}
	do {
		ret = read(fd, relay_connection, sizeof(struct relay_command));
	} while (ret < 0 && errno == EINTR);
	if (ret < 0 || ret < sizeof(struct relay_command)) {
		PERROR("read relay cmd pipe");
		goto error_read;
	}

	lttng_ht_node_init_ulong(&relay_connection->sock_n,
			(unsigned long) relay_connection->sock->fd);
	rcu_read_lock();
	lttng_ht_add_unique_ulong(relay_connections_ht,
			&relay_connection->sock_n);
	rcu_read_unlock();
	return lttng_poll_add(events,
			relay_connection->sock->fd,
			LPOLLIN | LPOLLRDHUP);

error_read:
	free(relay_connection);
error:
	return -1;
}

static
void live_deferred_free_connection(struct rcu_head *head)
{
	struct relay_command *relay_connection =
		caa_container_of(head, struct relay_command, rcu_node);

	if (relay_connection->session &&
			relay_connection->session->viewer_attached > 0) {
		relay_connection->session->viewer_attached--;
	}
	lttcomm_destroy_sock(relay_connection->sock);
	free(relay_connection);
}

static
void live_deferred_free_viewer_stream(struct rcu_head *head)
{
	struct relay_viewer_stream *stream =
		caa_container_of(head, struct relay_viewer_stream, rcu_node);

	/* FIXME : safe ? */
	if (stream->stream) {
		stream->stream->viewer_stream = NULL;
	}
	if (stream->ctf_trace) {
		uatomic_dec(&stream->ctf_trace->refcount);
		assert(uatomic_read(&stream->ctf_trace->refcount) >= 0);
		if (uatomic_read(&stream->ctf_trace->refcount) == 0) {
			DBG("Freeing ctf_trace %" PRIu64,
					stream->ctf_trace->id);
			free(stream->ctf_trace);
		}
	}

	free(stream->path_name);
	free(stream->channel_name);
	free(stream);
}

static
void viewer_del_streams(struct lttng_ht *viewer_streams_ht,
		struct relay_session *session)
{
	struct relay_viewer_stream *stream;
	struct lttng_ht_node_u64 *node;
	struct lttng_ht_iter iter;
	int ret;

	cds_lfht_for_each_entry(viewer_streams_ht->ht, &iter.iter, node, node) {
		node = lttng_ht_iter_get_node_u64(&iter);
		if (node) {
			stream = caa_container_of(node,
					struct relay_viewer_stream, stream_n);
			if (stream->session == session) {
				if (stream->read_fd > 0) {
					ret = close(stream->read_fd);
					if (ret < 0) {
						PERROR("close read_fd");
					}
				}
				if (stream->index_read_fd > 0) {
					ret = close(stream->index_read_fd);
					if (ret < 0) {
						PERROR("close index_read_fd");
					}
				}
				if (stream->metadata_flag && stream->ctf_trace) {
					stream->ctf_trace->metadata_sent = 0;
				}
				ret = lttng_ht_del(viewer_streams_ht, &iter);
				assert(!ret);
				call_rcu(&stream->rcu_node,
						live_deferred_free_viewer_stream);
			}
		}
	}
}

static
void live_relay_del_connection(struct lttng_ht *relay_connections_ht,
		struct lttng_ht *streams_ht, struct lttng_ht_iter *iter,
		struct relay_command *relay_connection,
		struct lttng_ht *viewer_streams_ht)
{
	int ret;

	ret = lttng_ht_del(relay_connections_ht, iter);
	assert(!ret);

	if (relay_connection->session) {
		viewer_del_streams(viewer_streams_ht,
				relay_connection->session);
	}

	call_rcu(&relay_connection->rcu_node,
		live_deferred_free_connection);
}

/*
 * This thread does the actual work
 */
static
void *live_relay_thread_worker(void *data)
{
	int ret, err = -1;
	uint32_t nb_fd;
	struct relay_command *relay_connection;
	struct lttng_poll_event events;
	struct lttng_ht *relay_connections_ht;
	struct lttng_ht_node_ulong *node;
	struct lttng_ht_iter iter;
	struct lttng_viewer_cmd recv_hdr;
	struct relay_local_data *relay_ctx = (struct relay_local_data *) data;
	struct lttng_ht *sessions_ht = relay_ctx->sessions_ht;
	struct lttng_ht *streams_ht = relay_ctx->streams_ht;
	struct lttng_ht *viewer_streams_ht = relay_ctx->viewer_streams_ht;

	DBG("[thread] Live viewer relay worker started");

	rcu_register_thread();

	/* table of connections indexed on socket */
	relay_connections_ht = lttng_ht_new(0, LTTNG_HT_TYPE_ULONG);
	if (!relay_connections_ht) {
		goto relay_connections_ht_error;
	}

	ret = live_create_thread_poll_set(&events, 2);
	if (ret < 0) {
		goto error_poll_create;
	}

	ret = lttng_poll_add(&events, live_relay_cmd_pipe[0], LPOLLIN | LPOLLRDHUP);
	if (ret < 0) {
		goto error;
	}

restart:
	while (1) {
		int i;

		/* Infinite blocking call, waiting for transmission */
		DBG3("Relayd live viewer worker thread polling...");
		ret = lttng_poll_wait(&events, -1);
		if (ret < 0) {
			/*
			 * Restart interrupted system call.
			 */
			if (errno == EINTR) {
				goto restart;
			}
			goto error;
		}

		nb_fd = ret;

		/*
		 * Process control. The control connection is prioritised so we don't
		 * starve it with high throughput tracing data on the data
		 * connection.
		 */
		for (i = 0; i < nb_fd; i++) {
			/* Fetch once the poll data */
			uint32_t revents = LTTNG_POLL_GETEV(&events, i);
			int pollfd = LTTNG_POLL_GETFD(&events, i);

			/* Thread quit pipe has been closed. Killing thread. */
			ret = live_check_thread_quit_pipe(pollfd, revents);
			if (ret) {
				err = 0;
				goto exit;
			}

			/* Inspect the relay cmd pipe for new connection */
			if (pollfd == live_relay_cmd_pipe[0]) {
				if (revents & (LPOLLERR | LPOLLHUP | LPOLLRDHUP)) {
					ERR("Relay live pipe error");
					goto error;
				} else if (revents & LPOLLIN) {
					DBG("Relay live viewer command received");
					ret = live_relay_add_connection(live_relay_cmd_pipe[0],
							&events, relay_connections_ht);
					if (ret < 0) {
						goto error;
					}
				}
			} else if (revents) {
				rcu_read_lock();
				lttng_ht_lookup(relay_connections_ht,
						(void *)((unsigned long) pollfd),
						&iter);
				node = lttng_ht_iter_get_node_ulong(&iter);
				if (node == NULL) {
					DBG2("Relay viewer sock %d not found", pollfd);
					rcu_read_unlock();
					goto error;
				}
				relay_connection = caa_container_of(node,
						struct relay_command, sock_n);

				if (revents & (LPOLLERR)) {
					ERR("VIEWER POLL ERROR");
					live_relay_cleanup_poll_connection(&events, pollfd);
					live_relay_del_connection(relay_connections_ht,
							streams_ht, &iter,
							relay_connection,
							viewer_streams_ht);
				} else if (revents & (LPOLLHUP | LPOLLRDHUP)) {
					DBG("Viewer socket %d hung up", pollfd);
					live_relay_cleanup_poll_connection(&events, pollfd);
					live_relay_del_connection(relay_connections_ht,
							streams_ht, &iter,
							relay_connection,
							viewer_streams_ht);
				} else if (revents & LPOLLIN) {
					ret = relay_connection->sock->ops->recvmsg(
							relay_connection->sock, &recv_hdr,
							sizeof(struct lttng_viewer_cmd),
							0);
					/* connection closed */
					if (ret <= 0) {
						live_relay_cleanup_poll_connection(&events,
								pollfd);
						live_relay_del_connection(
								relay_connections_ht,
								streams_ht, &iter,
								relay_connection,
								viewer_streams_ht);
						DBG("Viewer control connection closed "
								"with %d", pollfd);
					} else {
						if (relay_connection->session) {
							DBG2("Relay viewer worker "
									"receiving data for "
									"session : %" PRIu64,
									relay_connection->session->id);
						}
						ret = live_relay_process_control(&recv_hdr,
								relay_connection,
								streams_ht,
								sessions_ht,
								viewer_streams_ht);
						if (ret < 0) {
							/* Clear the session on error. */
							live_relay_cleanup_poll_connection(
									&events, pollfd);
							live_relay_del_connection(
									relay_connections_ht,
									streams_ht, &iter,
									relay_connection,
									viewer_streams_ht);
							DBG("Viewer connection closed "
									"with %d", pollfd);
						}
					}
				}
				rcu_read_unlock();
			}
		}
	}

exit:
error:
	lttng_poll_clean(&events);

	/* empty the hash table and free the memory */
	rcu_read_lock();
	cds_lfht_for_each_entry(relay_connections_ht->ht, &iter.iter, node, node) {
		node = lttng_ht_iter_get_node_ulong(&iter);
		if (node) {
			relay_connection = caa_container_of(node,
					struct relay_command, sock_n);
			live_relay_del_connection(relay_connections_ht,
					streams_ht, &iter,
					relay_connection,
					viewer_streams_ht);
		}
	}
	rcu_read_unlock();
error_poll_create:
	lttng_ht_destroy(relay_connections_ht);
relay_connections_ht_error:
	/* Close relay cmd pipes */
	utils_close_pipe(live_relay_cmd_pipe);
	if (err) {
		DBG("Viewer worker thread exited with error");
	}
	DBG("Viewer worker thread cleanup complete");
	live_stop_threads();
	rcu_unregister_thread();
	return NULL;
}

/*
 * Create the relay command pipe to wake thread_manage_apps.
 * Closed in cleanup().
 */
static int live_create_relay_cmd_pipe(void)
{
	int ret;

	ret = utils_create_pipe_cloexec(live_relay_cmd_pipe);

	return ret;
}

void stop_live_threads()
{
	int ret;
	void *status;

	live_stop_threads();

	ret = pthread_join(live_listener_thread, &status);
	if (ret != 0) {
		PERROR("pthread_join live listener");
		goto error;	/* join error, exit without cleanup */
	}

	ret = pthread_join(live_worker_thread, &status);
	if (ret != 0) {
		PERROR("pthread_join live worker");
		goto error;	/* join error, exit without cleanup */
	}

	ret = pthread_join(live_dispatcher_thread, &status);
	if (ret != 0) {
		PERROR("pthread_join live dispatcher");
		goto error;	/* join error, exit without cleanup */
	}

	live_cleanup();

error:
	return;
}

/*
 * main
 */
int start_live_threads(struct lttng_uri *uri,
		struct relay_local_data *relay_ctx)
{
	int ret = 0;
	void *status;
	int is_root;

	assert(uri);
	live_uri = uri;

	/* Create thread quit pipe */
	if ((ret = live_init_thread_quit_pipe()) < 0) {
		goto error;
	}

	/* Check if daemon is UID = 0 */
	is_root = !getuid();

	if (!is_root) {
		if (live_uri->port < 1024) {
			ERR("Need to be root to use ports < 1024");
			ret = -1;
			goto exit;
		}
	}

	/* Setup the thread apps communication pipe. */
	if ((ret = live_create_relay_cmd_pipe()) < 0) {
		goto exit;
	}

	/* Init relay command queue. */
	cds_wfq_init(&viewer_cmd_queue.queue);

	/* Set up max poll set size */
	lttng_poll_set_max_size();

	/* Setup the dispatcher thread */
	ret = pthread_create(&live_dispatcher_thread, NULL,
			live_relay_thread_dispatcher, (void *) NULL);
	if (ret != 0) {
		PERROR("pthread_create viewer dispatcher");
		goto exit_dispatcher;
	}

	/* Setup the worker thread */
	ret = pthread_create(&live_worker_thread, NULL,
			live_relay_thread_worker, relay_ctx);
	if (ret != 0) {
		PERROR("pthread_create viewer worker");
		goto exit_worker;
	}

	/* Setup the listener thread */
	ret = pthread_create(&live_listener_thread, NULL,
			live_relay_thread_listener, (void *) NULL);
	if (ret != 0) {
		PERROR("pthread_create viewer listener");
		goto exit_listener;
	}

	ret = 0;
	goto end;

exit_listener:
	ret = pthread_join(live_listener_thread, &status);
	if (ret != 0) {
		PERROR("pthread_join live listener");
		goto error;	/* join error, exit without cleanup */
	}

exit_worker:
	ret = pthread_join(live_worker_thread, &status);
	if (ret != 0) {
		PERROR("pthread_join live worker");
		goto error;	/* join error, exit without cleanup */
	}

exit_dispatcher:
	ret = pthread_join(live_dispatcher_thread, &status);
	if (ret != 0) {
		PERROR("pthread_join live dispatcher");
		goto error;	/* join error, exit without cleanup */
	}

exit:
	live_cleanup();

end:
error:
	return ret;
}
