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
#include <common/compat/endian.h>
#include <common/defaults.h>
#include <common/futex.h>
#include <common/index/index.h>
#include <common/sessiond-comm/sessiond-comm.h>
#include <common/sessiond-comm/inet.h>
#include <common/sessiond-comm/relayd.h>
#include <common/uri.h>
#include <common/utils.h>

#include "cmd.h"
#include "live.h"
#include "lttng-relayd.h"
#include "utils.h"
#include "health-relayd.h"
#include "testpoint.h"
#include "viewer-stream.h"
#include "stream.h"
#include "session.h"
#include "ctf-trace.h"
#include "connection.h"

static struct lttng_uri *live_uri;

/*
 * This pipe is used to inform the worker thread that a command is queued and
 * ready to be processed.
 */
static int live_conn_pipe[2] = { -1, -1 };

/* Shared between threads */
static int live_dispatch_thread_exit;

static pthread_t live_listener_thread;
static pthread_t live_dispatcher_thread;
static pthread_t live_worker_thread;

/*
 * Relay command queue.
 *
 * The live_thread_listener and live_thread_dispatcher communicate with this
 * queue.
 */
static struct relay_conn_queue viewer_conn_queue;

static uint64_t last_relay_viewer_session_id;

/*
 * Cleanup the daemon
 */
static
void cleanup_relayd_live(void)
{
	DBG("Cleaning up");

	free(live_uri);
}

/*
 * Receive a request buffer using a given socket, destination allocated buffer
 * of length size.
 *
 * Return the size of the received message or else a negative value on error
 * with errno being set by recvmsg() syscall.
 */
static
ssize_t recv_request(struct lttcomm_sock *sock, void *buf, size_t size)
{
	ssize_t ret;

	assert(sock);
	assert(buf);

	ret = sock->ops->recvmsg(sock, buf, size, 0);
	if (ret < 0 || ret != size) {
		if (ret == 0) {
			/* Orderly shutdown. Not necessary to print an error. */
			DBG("Socket %d did an orderly shutdown", sock->fd);
		} else {
			ERR("Relay failed to receive request.");
		}
		ret = -1;
	}

	return ret;
}

/*
 * Send a response buffer using a given socket, source allocated buffer of
 * length size.
 *
 * Return the size of the sent message or else a negative value on error with
 * errno being set by sendmsg() syscall.
 */
static
ssize_t send_response(struct lttcomm_sock *sock, void *buf, size_t size)
{
	ssize_t ret;

	assert(sock);
	assert(buf);

	ret = sock->ops->sendmsg(sock, buf, size, 0);
	if (ret < 0) {
		ERR("Relayd failed to send response.");
	}

	return ret;
}

/*
 * Atomically check if new streams got added in one of the sessions attached
 * and reset the flag to 0.
 *
 * Returns 1 if new streams got added, 0 if nothing changed, a negative value
 * on error.
 */
static
int check_new_streams(struct relay_connection *conn)
{
	struct relay_session *session;
	unsigned long current_val;
	int ret = 0;

	if (!conn->viewer_session) {
		goto end;
	}
	cds_list_for_each_entry(session,
			&conn->viewer_session->sessions_head,
			viewer_session_list) {
		current_val = uatomic_cmpxchg(&session->new_streams, 1, 0);
		ret = current_val;
		if (ret == 1) {
			goto end;
		}
	}

end:
	return ret;
}

/*
 * Send viewer streams to the given socket. The ignore_sent_flag indicates if
 * this function should ignore the sent flag or not.
 *
 * Return 0 on success or else a negative value.
 */
static
ssize_t send_viewer_streams(struct lttcomm_sock *sock,
		struct relay_session *session, unsigned int ignore_sent_flag)
{
	ssize_t ret;
	struct lttng_viewer_stream send_stream;
	struct lttng_ht_iter iter;
	struct relay_viewer_stream *vstream;

	assert(session);

	rcu_read_lock();

	cds_lfht_for_each_entry(viewer_streams_ht->ht, &iter.iter, vstream,
			stream_n.node) {
		struct ctf_trace *ctf_trace;

		health_code_update();

		/* Ignore if not the same session. */
		if (vstream->session_id != session->id ||
				(!ignore_sent_flag && vstream->sent_flag)) {
			continue;
		}

		ctf_trace = ctf_trace_find_by_path(session->ctf_traces_ht,
				vstream->path_name);
		assert(ctf_trace);

		send_stream.id = htobe64(vstream->stream_handle);
		send_stream.ctf_trace_id = htobe64(ctf_trace->id);
		send_stream.metadata_flag = htobe32(vstream->metadata_flag);
		strncpy(send_stream.path_name, vstream->path_name,
				sizeof(send_stream.path_name));
		strncpy(send_stream.channel_name, vstream->channel_name,
				sizeof(send_stream.channel_name));

		DBG("Sending stream %" PRIu64 " to viewer", vstream->stream_handle);
		ret = send_response(sock, &send_stream, sizeof(send_stream));
		if (ret < 0) {
			goto end_unlock;
		}
		vstream->sent_flag = 1;
	}

	ret = 0;

end_unlock:
	rcu_read_unlock();
	return ret;
}

/*
 * Create every viewer stream possible for the given session with the seek
 * type. Three counters *can* be return which are in order the total amount of
 * viewer stream of the session, the number of unsent stream and the number of
 * stream created. Those counters can be NULL and thus will be ignored.
 *
 * Return 0 on success or else a negative value.
 */
static
int make_viewer_streams(struct relay_session *session,
		enum lttng_viewer_seek seek_t, uint32_t *nb_total, uint32_t *nb_unsent,
		uint32_t *nb_created)
{
	int ret;
	struct lttng_ht_iter iter;
	struct ctf_trace *ctf_trace;

	assert(session);

	/*
	 * This is to make sure we create viewer streams for a full received
	 * channel. For instance, if we have 8 streams for a channel that are
	 * concurrently being flagged ready, we can end up creating just a subset
	 * of the 8 streams (the ones that are flagged). This lock avoids this
	 * limbo state.
	 */
	pthread_mutex_lock(&session->viewer_ready_lock);

	/*
	 * Create viewer streams for relay streams that are ready to be used for a
	 * the given session id only.
	 */
	rcu_read_lock();
	cds_lfht_for_each_entry(session->ctf_traces_ht->ht, &iter.iter, ctf_trace,
			node.node) {
		struct relay_stream *stream;

		health_code_update();

		if (ctf_trace->invalid_flag) {
			continue;
		}

		cds_list_for_each_entry(stream, &ctf_trace->stream_list, trace_list) {
			struct relay_viewer_stream *vstream;

			if (!stream->viewer_ready) {
				continue;
			}

			vstream = viewer_stream_find_by_id(stream->stream_handle);
			if (!vstream) {
				vstream = viewer_stream_create(stream, seek_t, ctf_trace);
				if (!vstream) {
					ret = -1;
					goto error_unlock;
				}
				/* Acquire reference to ctf_trace. */
				ctf_trace_get_ref(ctf_trace);

				if (nb_created) {
					/* Update number of created stream counter. */
					(*nb_created)++;
				}
			} else if (!vstream->sent_flag && nb_unsent) {
				/* Update number of unsent stream counter. */
				(*nb_unsent)++;
			}
			/* Update number of total stream counter. */
			if (nb_total) {
				(*nb_total)++;
			}
		}
	}

	ret = 0;

error_unlock:
	rcu_read_unlock();
	pthread_mutex_unlock(&session->viewer_ready_lock);
	return ret;
}

int relayd_live_stop(void)
{
	/* Stop dispatch thread */
	CMM_STORE_SHARED(live_dispatch_thread_exit, 1);
	futex_nto1_wake(&viewer_conn_queue.futex);
	return 0;
}

/*
 * Create a poll set with O_CLOEXEC and add the thread quit pipe to the set.
 */
static
int create_thread_poll_set(struct lttng_poll_event *events, int size)
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
	ret = lttng_poll_add(events, thread_quit_pipe[0], LPOLLIN | LPOLLERR);
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
int check_thread_quit_pipe(int fd, uint32_t events)
{
	if (fd == thread_quit_pipe[0] && (events & LPOLLIN)) {
		return 1;
	}

	return 0;
}

/*
 * Create and init socket from uri.
 */
static
struct lttcomm_sock *init_socket(struct lttng_uri *uri)
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
void *thread_listener(void *data)
{
	int i, ret, pollfd, err = -1;
	uint32_t revents, nb_fd;
	struct lttng_poll_event events;
	struct lttcomm_sock *live_control_sock;

	DBG("[thread] Relay live listener started");

	health_register(health_relayd, HEALTH_RELAYD_TYPE_LIVE_LISTENER);

	health_code_update();

	live_control_sock = init_socket(live_uri);
	if (!live_control_sock) {
		goto error_sock_control;
	}

	/* Pass 2 as size here for the thread quit pipe and control sockets. */
	ret = create_thread_poll_set(&events, 2);
	if (ret < 0) {
		goto error_create_poll;
	}

	/* Add the control socket */
	ret = lttng_poll_add(&events, live_control_sock->fd, LPOLLIN | LPOLLRDHUP);
	if (ret < 0) {
		goto error_poll_add;
	}

	lttng_relay_notify_ready();

	if (testpoint(relayd_thread_live_listener)) {
		goto error_testpoint;
	}

	while (1) {
		health_code_update();

		DBG("Listener accepting live viewers connections");

restart:
		health_poll_entry();
		ret = lttng_poll_wait(&events, -1);
		health_poll_exit();
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
			health_code_update();

			/* Fetch once the poll data */
			revents = LTTNG_POLL_GETEV(&events, i);
			pollfd = LTTNG_POLL_GETFD(&events, i);

			if (!revents) {
				/* No activity for this FD (poll implementation). */
				continue;
			}

			/* Thread quit pipe has been closed. Killing thread. */
			ret = check_thread_quit_pipe(pollfd, revents);
			if (ret) {
				err = 0;
				goto exit;
			}

			if (revents & (LPOLLERR | LPOLLHUP | LPOLLRDHUP)) {
				ERR("socket poll error");
				goto error;
			} else if (revents & LPOLLIN) {
				/*
				 * Get allocated in this thread, enqueued to a global queue,
				 * dequeued and freed in the worker thread.
				 */
				int val = 1;
				struct relay_connection *new_conn;
				struct lttcomm_sock *newsock;

				new_conn = connection_create();
				if (!new_conn) {
					goto error;
				}

				newsock = live_control_sock->ops->accept(live_control_sock);
				if (!newsock) {
					PERROR("accepting control sock");
					connection_free(new_conn);
					goto error;
				}
				DBG("Relay viewer connection accepted socket %d", newsock->fd);

				ret = setsockopt(newsock->fd, SOL_SOCKET, SO_REUSEADDR, &val,
						sizeof(val));
				if (ret < 0) {
					PERROR("setsockopt inet");
					lttcomm_destroy_sock(newsock);
					connection_free(new_conn);
					goto error;
				}
				new_conn->sock = newsock;

				/* Enqueue request for the dispatcher thread. */
				cds_wfcq_enqueue(&viewer_conn_queue.head, &viewer_conn_queue.tail,
						 &new_conn->qnode);

				/*
				 * Wake the dispatch queue futex. Implicit memory barrier with
				 * the exchange in cds_wfcq_enqueue.
				 */
				futex_nto1_wake(&viewer_conn_queue.futex);
			}
		}
	}

exit:
error:
error_poll_add:
error_testpoint:
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
		health_error();
		DBG("Live viewer listener thread exited with error");
	}
	health_unregister(health_relayd);
	DBG("Live viewer listener thread cleanup complete");
	if (lttng_relay_stop_threads()) {
		ERR("Error stopping threads");
	}
	return NULL;
}

/*
 * This thread manages the dispatching of the requests to worker threads
 */
static
void *thread_dispatcher(void *data)
{
	int err = -1;
	ssize_t ret;
	struct cds_wfcq_node *node;
	struct relay_connection *conn = NULL;

	DBG("[thread] Live viewer relay dispatcher started");

	health_register(health_relayd, HEALTH_RELAYD_TYPE_LIVE_DISPATCHER);

	if (testpoint(relayd_thread_live_dispatcher)) {
		goto error_testpoint;
	}

	health_code_update();

	while (!CMM_LOAD_SHARED(live_dispatch_thread_exit)) {
		health_code_update();

		/* Atomically prepare the queue futex */
		futex_nto1_prepare(&viewer_conn_queue.futex);

		do {
			health_code_update();

			/* Dequeue commands */
			node = cds_wfcq_dequeue_blocking(&viewer_conn_queue.head,
							 &viewer_conn_queue.tail);
			if (node == NULL) {
				DBG("Woken up but nothing in the live-viewer "
						"relay command queue");
				/* Continue thread execution */
				break;
			}
			conn = caa_container_of(node, struct relay_connection, qnode);
			DBG("Dispatching viewer request waiting on sock %d",
					conn->sock->fd);

			/*
			 * Inform worker thread of the new request. This call is blocking
			 * so we can be assured that the data will be read at some point in
			 * time or wait to the end of the world :)
			 */
			ret = lttng_write(live_conn_pipe[1], &conn, sizeof(conn));
			if (ret < 0) {
				PERROR("write conn pipe");
				connection_destroy(conn);
				goto error;
			}
		} while (node != NULL);

		/* Futex wait on queue. Blocking call on futex() */
		health_poll_entry();
		futex_nto1_wait(&viewer_conn_queue.futex);
		health_poll_exit();
	}

	/* Normal exit, no error */
	err = 0;

error:
error_testpoint:
	if (err) {
		health_error();
		ERR("Health error occurred in %s", __func__);
	}
	health_unregister(health_relayd);
	DBG("Live viewer dispatch thread dying");
	if (lttng_relay_stop_threads()) {
		ERR("Error stopping threads");
	}
	return NULL;
}

/*
 * Establish connection with the viewer and check the versions.
 *
 * Return 0 on success or else negative value.
 */
static
int viewer_connect(struct relay_connection *conn)
{
	int ret;
	struct lttng_viewer_connect reply, msg;

	assert(conn);

	conn->version_check_done = 1;

	health_code_update();

	DBG("Viewer is establishing a connection to the relayd.");

	ret = recv_request(conn->sock, &msg, sizeof(msg));
	if (ret < 0) {
		goto end;
	}

	health_code_update();

	memset(&reply, 0, sizeof(reply));
	reply.major = RELAYD_VERSION_COMM_MAJOR;
	reply.minor = RELAYD_VERSION_COMM_MINOR;

	/* Major versions must be the same */
	if (reply.major != be32toh(msg.major)) {
		DBG("Incompatible major versions ([relayd] %u vs [client] %u)",
				reply.major, be32toh(msg.major));
		ret = -1;
		goto end;
	}

	conn->major = reply.major;
	/* We adapt to the lowest compatible version */
	if (reply.minor <= be32toh(msg.minor)) {
		conn->minor = reply.minor;
	} else {
		conn->minor = be32toh(msg.minor);
	}

	if (be32toh(msg.type) == LTTNG_VIEWER_CLIENT_COMMAND) {
		conn->type = RELAY_VIEWER_COMMAND;
	} else if (be32toh(msg.type) == LTTNG_VIEWER_CLIENT_NOTIFICATION) {
		conn->type = RELAY_VIEWER_NOTIFICATION;
	} else {
		ERR("Unknown connection type : %u", be32toh(msg.type));
		ret = -1;
		goto end;
	}

	reply.major = htobe32(reply.major);
	reply.minor = htobe32(reply.minor);
	if (conn->type == RELAY_VIEWER_COMMAND) {
		/*
		 * Increment outside of htobe64 macro, because can be used more than once
		 * within the macro, and thus the operation may be undefined.
		 */
		last_relay_viewer_session_id++;
		reply.viewer_session_id = htobe64(last_relay_viewer_session_id);
	}

	health_code_update();

	ret = send_response(conn->sock, &reply, sizeof(reply));
	if (ret < 0) {
		goto end;
	}

	health_code_update();

	DBG("Version check done using protocol %u.%u", conn->major, conn->minor);
	ret = 0;

end:
	return ret;
}

/*
 * Send the viewer the list of current sessions.
 *
 * Return 0 on success or else a negative value.
 */
static
int viewer_list_sessions(struct relay_connection *conn)
{
	int ret;
	struct lttng_viewer_list_sessions session_list;
	unsigned long count;
	long approx_before, approx_after;
	struct lttng_ht_iter iter;
	struct lttng_viewer_session send_session;
	struct relay_session *session;

	DBG("List sessions received");

	rcu_read_lock();
	cds_lfht_count_nodes(conn->sessions_ht->ht, &approx_before, &count,
			&approx_after);
	session_list.sessions_count = htobe32(count);

	health_code_update();

	ret = send_response(conn->sock, &session_list, sizeof(session_list));
	if (ret < 0) {
		goto end_unlock;
	}

	health_code_update();

	cds_lfht_for_each_entry(conn->sessions_ht->ht, &iter.iter, session,
			session_n.node) {
		health_code_update();

		strncpy(send_session.session_name, session->session_name,
				sizeof(send_session.session_name));
		strncpy(send_session.hostname, session->hostname,
				sizeof(send_session.hostname));
		send_session.id = htobe64(session->id);
		send_session.live_timer = htobe32(session->live_timer);
		send_session.clients = htobe32(session->viewer_refcount);
		send_session.streams = htobe32(session->stream_count);

		health_code_update();

		ret = send_response(conn->sock, &send_session, sizeof(send_session));
		if (ret < 0) {
			goto end_unlock;
		}
	}
	health_code_update();

	ret = 0;
end_unlock:
	rcu_read_unlock();
	return ret;
}

/*
 * Check if a connection is attached to a session.
 * Return 1 if attached, 0 if not attached, a negative value on error.
 */
static
int session_attached(struct relay_connection *conn, uint64_t session_id)
{
	struct relay_session *session;
	int found = 0;

	if (!conn->viewer_session) {
		goto end;
	}
	cds_list_for_each_entry(session,
			&conn->viewer_session->sessions_head,
			viewer_session_list) {
		if (session->id == session_id) {
			found = 1;
			goto end;
		}
	}

end:
	return found;
}

/*
 * Delete all streams for a specific session ID.
 */
static void destroy_viewer_streams_by_session(struct relay_session *session)
{
	struct relay_viewer_stream *stream;
	struct lttng_ht_iter iter;

	assert(session);

	rcu_read_lock();
	cds_lfht_for_each_entry(viewer_streams_ht->ht, &iter.iter, stream,
			stream_n.node) {
		struct ctf_trace *ctf_trace;

		health_code_update();
		if (stream->session_id != session->id) {
			continue;
		}

		ctf_trace = ctf_trace_find_by_path(session->ctf_traces_ht,
				stream->path_name);
		assert(ctf_trace);

		viewer_stream_delete(stream);

		if (stream->metadata_flag) {
			ctf_trace->metadata_sent = 0;
			ctf_trace->viewer_metadata_stream = NULL;
		}

		viewer_stream_destroy(ctf_trace, stream);
	}
	rcu_read_unlock();
}

static void try_destroy_streams(struct relay_session *session)
{
	struct ctf_trace *ctf_trace;
	struct lttng_ht_iter iter;

	assert(session);

	cds_lfht_for_each_entry(session->ctf_traces_ht->ht, &iter.iter, ctf_trace,
			node.node) {
		/* Attempt to destroy the ctf trace of that session. */
		ctf_trace_try_destroy(session, ctf_trace);
	}
}

/*
 * Cleanup a session.
 */
static void cleanup_session(struct relay_connection *conn,
		struct relay_session *session)
{
	/*
	 * Very important that this is done before destroying the session so we
	 * can put back every viewer stream reference from the ctf_trace.
	 */
	destroy_viewer_streams_by_session(session);
	try_destroy_streams(session);
	cds_list_del(&session->viewer_session_list);
	session_viewer_try_destroy(conn->sessions_ht, session);
}

/*
 * Send the viewer the list of current sessions.
 */
static
int viewer_get_new_streams(struct relay_connection *conn)
{
	int ret, send_streams = 0;
	uint32_t nb_created = 0, nb_unsent = 0, nb_streams = 0;
	struct lttng_viewer_new_streams_request request;
	struct lttng_viewer_new_streams_response response;
	struct relay_session *session;
	uint64_t session_id;

	assert(conn);

	DBG("Get new streams received");

	health_code_update();

	/* Receive the request from the connected client. */
	ret = recv_request(conn->sock, &request, sizeof(request));
	if (ret < 0) {
		goto error;
	}
	session_id = be64toh(request.session_id);

	health_code_update();

	memset(&response, 0, sizeof(response));

	rcu_read_lock();
	session = session_find_by_id(conn->sessions_ht, session_id);
	if (!session) {
		DBG("Relay session %" PRIu64 " not found", session_id);
		response.status = htobe32(LTTNG_VIEWER_NEW_STREAMS_ERR);
		goto send_reply;
	}

	if (!session_attached(conn, session_id)) {
		send_streams = 0;
		response.status = htobe32(LTTNG_VIEWER_NEW_STREAMS_ERR);
		goto send_reply;
	}

	send_streams = 1;
	response.status = htobe32(LTTNG_VIEWER_NEW_STREAMS_OK);

	ret = make_viewer_streams(session, LTTNG_VIEWER_SEEK_LAST, NULL, &nb_unsent,
			&nb_created);
	if (ret < 0) {
		goto end_unlock;
	}
	/* Only send back the newly created streams with the unsent ones. */
	nb_streams = nb_created + nb_unsent;
	response.streams_count = htobe32(nb_streams);

	/*
	 * If the session is closed and we have no new streams to send,
	 * it means that the viewer has already received the whole trace
	 * for this session and should now close it.
	 */
	if (nb_streams == 0 && session->close_flag) {
		send_streams = 0;
		response.status = htobe32(LTTNG_VIEWER_NEW_STREAMS_HUP);
		/*
		 * Remove the session from the attached list of the connection
		 * and try to destroy it.
		 */
		cds_list_del(&session->viewer_session_list);
		cleanup_session(conn, session);
		goto send_reply;
	}

send_reply:
	health_code_update();
	ret = send_response(conn->sock, &response, sizeof(response));
	if (ret < 0) {
		goto end_unlock;
	}
	health_code_update();

	/*
	 * Unknown or empty session, just return gracefully, the viewer knows what
	 * is happening.
	 */
	if (!send_streams || !nb_streams) {
		ret = 0;
		goto end_unlock;
	}

	/*
	 * Send stream and *DON'T* ignore the sent flag so every viewer streams
	 * that were not sent from that point will be sent to the viewer.
	 */
	ret = send_viewer_streams(conn->sock, session, 0);
	if (ret < 0) {
		goto end_unlock;
	}

end_unlock:
	rcu_read_unlock();
error:
	return ret;
}

/*
 * Send the viewer the list of current sessions.
 */
static
int viewer_attach_session(struct relay_connection *conn)
{
	int send_streams = 0;
	ssize_t ret;
	uint32_t nb_streams = 0;
	enum lttng_viewer_seek seek_type;
	struct lttng_viewer_attach_session_request request;
	struct lttng_viewer_attach_session_response response;
	struct relay_session *session;

	assert(conn);

	health_code_update();

	/* Receive the request from the connected client. */
	ret = recv_request(conn->sock, &request, sizeof(request));
	if (ret < 0) {
		goto error;
	}

	health_code_update();

	memset(&response, 0, sizeof(response));

	if (!conn->viewer_session) {
		DBG("Client trying to attach before creating a live viewer session");
		response.status = htobe32(LTTNG_VIEWER_ATTACH_NO_SESSION);
		goto send_reply;
	}

	rcu_read_lock();
	session = session_find_by_id(conn->sessions_ht,
			be64toh(request.session_id));
	if (!session) {
		DBG("Relay session %" PRIu64 " not found",
				be64toh(request.session_id));
		response.status = htobe32(LTTNG_VIEWER_ATTACH_UNK);
		goto send_reply;
	}
	session_viewer_attach(session);
	DBG("Attach session ID %" PRIu64 " received", be64toh(request.session_id));

	if (uatomic_read(&session->viewer_refcount) > 1) {
		DBG("Already a viewer attached");
		response.status = htobe32(LTTNG_VIEWER_ATTACH_ALREADY);
		session_viewer_detach(session);
		goto send_reply;
	} else if (session->live_timer == 0) {
		DBG("Not live session");
		response.status = htobe32(LTTNG_VIEWER_ATTACH_NOT_LIVE);
		goto send_reply;
	} else {
		send_streams = 1;
		response.status = htobe32(LTTNG_VIEWER_ATTACH_OK);
		cds_list_add(&session->viewer_session_list,
				&conn->viewer_session->sessions_head);
	}

	switch (be32toh(request.seek)) {
	case LTTNG_VIEWER_SEEK_BEGINNING:
	case LTTNG_VIEWER_SEEK_LAST:
		seek_type = be32toh(request.seek);
		break;
	default:
		ERR("Wrong seek parameter");
		response.status = htobe32(LTTNG_VIEWER_ATTACH_SEEK_ERR);
		send_streams = 0;
		goto send_reply;
	}

	ret = make_viewer_streams(session, seek_type, &nb_streams, NULL, NULL);
	if (ret < 0) {
		goto end_unlock;
	}
	response.streams_count = htobe32(nb_streams);

send_reply:
	health_code_update();
	ret = send_response(conn->sock, &response, sizeof(response));
	if (ret < 0) {
		goto end_unlock;
	}
	health_code_update();

	/*
	 * Unknown or empty session, just return gracefully, the viewer knows what
	 * is happening.
	 */
	if (!send_streams || !nb_streams) {
		ret = 0;
		goto end_unlock;
	}

	/* Send stream and ignore the sent flag. */
	ret = send_viewer_streams(conn->sock, session, 1);
	if (ret < 0) {
		goto end_unlock;
	}

end_unlock:
	rcu_read_unlock();
error:
	return ret;
}

/*
 * Open the index file if needed for the given vstream.
 *
 * If an index file is successfully opened, the index_read_fd of the stream is
 * set with it.
 *
 * Return 0 on success, a negative value on error (-ENOENT if not ready yet).
 */
static int try_open_index(struct relay_viewer_stream *vstream,
		struct relay_stream *rstream)
{
	int ret = 0;

	assert(vstream);
	assert(rstream);

	if (vstream->index_read_fd >= 0) {
		goto end;
	}

	/*
	 * First time, we open the index file and at least one index is ready.  The
	 * race between the read and write of the total_index_received is
	 * acceptable here since the client will be notified to simply come back
	 * and get the next index.
	 */
	if (rstream->total_index_received <= 0) {
		ret = -ENOENT;
		goto end;
	}
	ret = index_open(vstream->path_name, vstream->channel_name,
			vstream->tracefile_count, vstream->tracefile_count_current);
	if (ret >= 0) {
		vstream->index_read_fd = ret;
		ret = 0;
		goto end;
	}

end:
	return ret;
}

/*
 * Check the status of the index for the given stream. This function updates
 * the index structure if needed and can destroy the vstream also for the HUP
 * situation.
 *
 * Return 0 means that we can proceed with the index. A value of 1 means that
 * the index has been updated and is ready to be send to the client. A negative
 * value indicates an error that can't be handled.
 */
static int check_index_status(struct relay_viewer_stream *vstream,
		struct relay_stream *rstream, struct ctf_trace *trace,
		struct lttng_viewer_index *index)
{
	int ret;

	assert(vstream);
	assert(rstream);
	assert(index);
	assert(trace);

	if (!rstream->close_flag) {
		/* Rotate on abort (overwrite). */
		if (vstream->abort_flag) {
			DBG("Viewer stream %" PRIu64 " rotate because of overwrite",
					vstream->stream_handle);
			ret = viewer_stream_rotate(vstream, rstream);
			if (ret < 0) {
				goto error;
			} else if (ret == 1) {
				/* EOF */
				index->status = htobe32(LTTNG_VIEWER_INDEX_HUP);
				goto hup;
			}
			/* ret == 0 means successful so we continue. */
		}

		/* Check if we are in the same trace file at this point. */
		if (rstream->tracefile_count_current == vstream->tracefile_count_current) {
			if (rstream->beacon_ts_end != -1ULL &&
					vstream->last_sent_index == rstream->total_index_received) {
				/*
				 * We've received a synchronization beacon and the last index
				 * available has been sent, the index for now is inactive.
				 */
				index->status = htobe32(LTTNG_VIEWER_INDEX_INACTIVE);
				index->timestamp_end = htobe64(rstream->beacon_ts_end);
				index->stream_id = htobe64(rstream->ctf_stream_id);
				goto index_ready;
			} else if (rstream->total_index_received <= vstream->last_sent_index
					&& !vstream->close_write_flag) {
				/*
				 * Reader and writer are working in the same tracefile, so we care
				 * about the number of index received and sent. Otherwise, we read
				 * up to EOF.
				 */
				index->status = htobe32(LTTNG_VIEWER_INDEX_RETRY);
				goto index_ready;
			}
		}
		/* Nothing to do with the index, continue with it. */
		ret = 0;
	} else if (rstream->close_flag && vstream->close_write_flag &&
			vstream->total_index_received == vstream->last_sent_index) {
		/* Last index sent and current tracefile closed in write */
		index->status = htobe32(LTTNG_VIEWER_INDEX_HUP);
		goto hup;
	} else {
		vstream->close_write_flag = 1;
		ret = 0;
	}

error:
	return ret;

hup:
	viewer_stream_delete(vstream);
	viewer_stream_destroy(trace, vstream);
index_ready:
	return 1;
}

/*
 * Send the next index for a stream.
 *
 * Return 0 on success or else a negative value.
 */
static
int viewer_get_next_index(struct relay_connection *conn)
{
	int ret;
	ssize_t read_ret;
	struct lttng_viewer_get_next_index request_index;
	struct lttng_viewer_index viewer_index;
	struct ctf_packet_index packet_index;
	struct relay_viewer_stream *vstream;
	struct relay_stream *rstream;
	struct ctf_trace *ctf_trace;
	struct relay_session *session;

	assert(conn);

	DBG("Viewer get next index");

	health_code_update();

	ret = recv_request(conn->sock, &request_index, sizeof(request_index));
	if (ret < 0) {
		goto end;
	}
	health_code_update();

	rcu_read_lock();
	vstream = viewer_stream_find_by_id(be64toh(request_index.stream_id));
	if (!vstream) {
		ret = -1;
		goto end_unlock;
	}

	session = session_find_by_id(conn->sessions_ht, vstream->session_id);
	if (!session) {
		ret = -1;
		goto end_unlock;
	}

	ctf_trace = ctf_trace_find_by_path(session->ctf_traces_ht, vstream->path_name);
	assert(ctf_trace);

	memset(&viewer_index, 0, sizeof(viewer_index));

	/*
	 * The viewer should not ask for index on metadata stream.
	 */
	if (vstream->metadata_flag) {
		viewer_index.status = htobe32(LTTNG_VIEWER_INDEX_HUP);
		goto send_reply;
	}

	rstream = stream_find_by_id(relay_streams_ht, vstream->stream_handle);
	assert(rstream);

	/* Try to open an index if one is needed for that stream. */
	ret = try_open_index(vstream, rstream);
	if (ret < 0) {
		if (ret == -ENOENT) {
			/*
			 * The index is created only when the first data packet arrives, it
			 * might not be ready at the beginning of the session
			 */
			viewer_index.status = htobe32(LTTNG_VIEWER_INDEX_RETRY);
		} else {
			/* Unhandled error. */
			viewer_index.status = htobe32(LTTNG_VIEWER_INDEX_ERR);
		}
		goto send_reply;
	}

	pthread_mutex_lock(&rstream->viewer_stream_rotation_lock);
	ret = check_index_status(vstream, rstream, ctf_trace, &viewer_index);
	pthread_mutex_unlock(&rstream->viewer_stream_rotation_lock);
	if (ret < 0) {
		goto end_unlock;
	} else if (ret == 1) {
		/*
		 * This means the viewer index data structure has been populated by the
		 * check call thus we now send back the reply to the client.
		 */
		goto send_reply;
	}
	/* At this point, ret MUST be 0 thus we continue with the get. */
	assert(!ret);

	if (!ctf_trace->metadata_received ||
			ctf_trace->metadata_received > ctf_trace->metadata_sent) {
		viewer_index.flags |= LTTNG_VIEWER_FLAG_NEW_METADATA;
	}

	ret = check_new_streams(conn);
	if (ret < 0) {
		goto end_unlock;
	} else if (ret == 1) {
		viewer_index.flags |= LTTNG_VIEWER_FLAG_NEW_STREAM;
	}

	pthread_mutex_lock(&rstream->viewer_stream_rotation_lock);
	pthread_mutex_lock(&vstream->overwrite_lock);
	if (vstream->abort_flag) {
		/* The file is being overwritten by the writer, we cannot use it. */
		pthread_mutex_unlock(&vstream->overwrite_lock);
		ret = viewer_stream_rotate(vstream, rstream);
		pthread_mutex_unlock(&rstream->viewer_stream_rotation_lock);
		if (ret < 0) {
			goto end_unlock;
		} else if (ret == 1) {
			viewer_index.status = htobe32(LTTNG_VIEWER_INDEX_HUP);
			viewer_stream_delete(vstream);
			viewer_stream_destroy(ctf_trace, vstream);
		} else {
			viewer_index.status = htobe32(LTTNG_VIEWER_INDEX_RETRY);
		}
		goto send_reply;
	}

	read_ret = lttng_read(vstream->index_read_fd, &packet_index,
			sizeof(packet_index));
	pthread_mutex_unlock(&vstream->overwrite_lock);
	pthread_mutex_unlock(&rstream->viewer_stream_rotation_lock);
	if (read_ret < 0) {
		viewer_index.status = htobe32(LTTNG_VIEWER_INDEX_HUP);
		viewer_stream_delete(vstream);
		viewer_stream_destroy(ctf_trace, vstream);
		goto send_reply;
	} else if (read_ret < sizeof(packet_index)) {
		pthread_mutex_lock(&rstream->viewer_stream_rotation_lock);
		if (vstream->close_write_flag) {
			ret = viewer_stream_rotate(vstream, rstream);
			if (ret < 0) {
				pthread_mutex_unlock(&rstream->viewer_stream_rotation_lock);
				goto end_unlock;
			} else if (ret == 1) {
				viewer_index.status = htobe32(LTTNG_VIEWER_INDEX_HUP);
				viewer_stream_delete(vstream);
				viewer_stream_destroy(ctf_trace, vstream);
			} else {
				viewer_index.status = htobe32(LTTNG_VIEWER_INDEX_RETRY);
			}
		} else {
			ERR("Relay reading index file %d", vstream->index_read_fd);
			viewer_index.status = htobe32(LTTNG_VIEWER_INDEX_ERR);
		}
		pthread_mutex_unlock(&rstream->viewer_stream_rotation_lock);
		goto send_reply;
	} else {
		viewer_index.status = htobe32(LTTNG_VIEWER_INDEX_OK);
		vstream->last_sent_index++;
	}

	/*
	 * Indexes are stored in big endian, no need to switch before sending.
	 */
	viewer_index.offset = packet_index.offset;
	viewer_index.packet_size = packet_index.packet_size;
	viewer_index.content_size = packet_index.content_size;
	viewer_index.timestamp_begin = packet_index.timestamp_begin;
	viewer_index.timestamp_end = packet_index.timestamp_end;
	viewer_index.events_discarded = packet_index.events_discarded;
	viewer_index.stream_id = packet_index.stream_id;

send_reply:
	viewer_index.flags = htobe32(viewer_index.flags);
	health_code_update();

	ret = send_response(conn->sock, &viewer_index, sizeof(viewer_index));
	if (ret < 0) {
		goto end_unlock;
	}
	health_code_update();

	DBG("Index %" PRIu64 " for stream %" PRIu64 " sent",
			vstream->last_sent_index, vstream->stream_handle);

end_unlock:
	rcu_read_unlock();

end:
	return ret;
}

/*
 * Send the next index for a stream
 *
 * Return 0 on success or else a negative value.
 */
static
int viewer_get_packet(struct relay_connection *conn)
{
	int ret, send_data = 0;
	char *data = NULL;
	uint32_t len = 0;
	ssize_t read_len;
	struct lttng_viewer_get_packet get_packet_info;
	struct lttng_viewer_trace_packet reply;
	struct relay_viewer_stream *stream;
	struct relay_session *session;
	struct ctf_trace *ctf_trace;

	assert(conn);

	DBG2("Relay get data packet");

	health_code_update();

	ret = recv_request(conn->sock, &get_packet_info, sizeof(get_packet_info));
	if (ret < 0) {
		goto end;
	}
	health_code_update();

	/* From this point on, the error label can be reached. */
	memset(&reply, 0, sizeof(reply));

	rcu_read_lock();
	stream = viewer_stream_find_by_id(be64toh(get_packet_info.stream_id));
	if (!stream) {
		goto error;
	}

	session = session_find_by_id(conn->sessions_ht, stream->session_id);
	if (!session) {
		ret = -1;
		goto error;
	}

	ctf_trace = ctf_trace_find_by_path(session->ctf_traces_ht,
			stream->path_name);
	assert(ctf_trace);

	/*
	 * First time we read this stream, we need open the tracefile, we should
	 * only arrive here if an index has already been sent to the viewer, so the
	 * tracefile must exist, if it does not it is a fatal error.
	 */
	if (stream->read_fd < 0) {
		char fullpath[PATH_MAX];

		if (stream->tracefile_count > 0) {
			ret = snprintf(fullpath, PATH_MAX, "%s/%s_%" PRIu64, stream->path_name,
					stream->channel_name,
					stream->tracefile_count_current);
		} else {
			ret = snprintf(fullpath, PATH_MAX, "%s/%s", stream->path_name,
					stream->channel_name);
		}
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

	if (!ctf_trace->metadata_received ||
			ctf_trace->metadata_received > ctf_trace->metadata_sent) {
		reply.status = htobe32(LTTNG_VIEWER_GET_PACKET_ERR);
		reply.flags |= LTTNG_VIEWER_FLAG_NEW_METADATA;
		goto send_reply;
	}

	ret = check_new_streams(conn);
	if (ret < 0) {
		goto end_unlock;
	} else if (ret == 1) {
		reply.status = htobe32(LTTNG_VIEWER_GET_PACKET_ERR);
		reply.flags |= LTTNG_VIEWER_FLAG_NEW_STREAM;
		goto send_reply;
	}

	len = be32toh(get_packet_info.len);
	data = zmalloc(len);
	if (!data) {
		PERROR("relay data zmalloc");
		goto error;
	}

	ret = lseek(stream->read_fd, be64toh(get_packet_info.offset), SEEK_SET);
	if (ret < 0) {
		/*
		 * If the read fd was closed by the streaming side, the
		 * abort_flag will be set to 1, otherwise it is an error.
		 */
		if (stream->abort_flag == 0) {
			PERROR("lseek");
			goto error;
		}
		reply.status = htobe32(LTTNG_VIEWER_GET_PACKET_EOF);
		goto send_reply;
	}
	read_len = lttng_read(stream->read_fd, data, len);
	if (read_len < len) {
		/*
		 * If the read fd was closed by the streaming side, the
		 * abort_flag will be set to 1, otherwise it is an error.
		 */
		if (stream->abort_flag == 0) {
			PERROR("Relay reading trace file, fd: %d, offset: %" PRIu64,
					stream->read_fd,
					be64toh(get_packet_info.offset));
			goto error;
		} else {
			reply.status = htobe32(LTTNG_VIEWER_GET_PACKET_EOF);
			goto send_reply;
		}
	}
	reply.status = htobe32(LTTNG_VIEWER_GET_PACKET_OK);
	reply.len = htobe32(len);
	send_data = 1;
	goto send_reply;

error:
	reply.status = htobe32(LTTNG_VIEWER_GET_PACKET_ERR);

send_reply:
	reply.flags = htobe32(reply.flags);

	health_code_update();

	ret = send_response(conn->sock, &reply, sizeof(reply));
	if (ret < 0) {
		goto end_unlock;
	}
	health_code_update();

	if (send_data) {
		health_code_update();
		ret = send_response(conn->sock, data, len);
		if (ret < 0) {
			goto end_unlock;
		}
		health_code_update();
	}

	DBG("Sent %u bytes for stream %" PRIu64, len,
			be64toh(get_packet_info.stream_id));

end_unlock:
	free(data);
	rcu_read_unlock();

end:
	return ret;
}

/*
 * Send the session's metadata
 *
 * Return 0 on success else a negative value.
 */
static
int viewer_get_metadata(struct relay_connection *conn)
{
	int ret = 0;
	ssize_t read_len;
	uint64_t len = 0;
	char *data = NULL;
	struct lttng_viewer_get_metadata request;
	struct lttng_viewer_metadata_packet reply;
	struct relay_viewer_stream *stream;
	struct ctf_trace *ctf_trace;
	struct relay_session *session;

	assert(conn);

	DBG("Relay get metadata");

	health_code_update();

	ret = recv_request(conn->sock, &request, sizeof(request));
	if (ret < 0) {
		goto end;
	}
	health_code_update();

	memset(&reply, 0, sizeof(reply));

	rcu_read_lock();
	stream = viewer_stream_find_by_id(be64toh(request.stream_id));
	if (!stream || !stream->metadata_flag) {
		ERR("Invalid metadata stream");
		goto error;
	}

	session = session_find_by_id(conn->sessions_ht, stream->session_id);
	if (!session) {
		ret = -1;
		goto error;
	}

	ctf_trace = ctf_trace_find_by_path(session->ctf_traces_ht,
			stream->path_name);
	assert(ctf_trace);
	assert(ctf_trace->metadata_sent <= ctf_trace->metadata_received);

	len = ctf_trace->metadata_received - ctf_trace->metadata_sent;
	if (len == 0) {
		reply.status = htobe32(LTTNG_VIEWER_NO_NEW_METADATA);
		goto send_reply;
	}

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

	reply.len = htobe64(len);
	data = zmalloc(len);
	if (!data) {
		PERROR("viewer metadata zmalloc");
		goto error;
	}

	read_len = lttng_read(stream->read_fd, data, len);
	if (read_len < len) {
		PERROR("Relay reading metadata file");
		goto error;
	}
	ctf_trace->metadata_sent += read_len;
	reply.status = htobe32(LTTNG_VIEWER_METADATA_OK);
	goto send_reply;

error:
	reply.status = htobe32(LTTNG_VIEWER_METADATA_ERR);

send_reply:
	health_code_update();
	ret = send_response(conn->sock, &reply, sizeof(reply));
	if (ret < 0) {
		goto end_unlock;
	}
	health_code_update();

	if (len > 0) {
		ret = send_response(conn->sock, data, len);
		if (ret < 0) {
			goto end_unlock;
		}
	}

	DBG("Sent %" PRIu64 " bytes of metadata for stream %" PRIu64, len,
			be64toh(request.stream_id));

	DBG("Metadata sent");

end_unlock:
	free(data);
	rcu_read_unlock();
end:
	return ret;
}

/*
 * Create a viewer session.
 *
 * Return 0 on success or else a negative value.
 */
static
int viewer_create_session(struct relay_connection *conn)
{
	int ret;
	struct lttng_viewer_create_session_response resp;

	DBG("Viewer create session received");

	memset(&resp, 0, sizeof(resp));
	resp.status = htobe32(LTTNG_VIEWER_CREATE_SESSION_OK);
	conn->viewer_session = zmalloc(sizeof(*conn->viewer_session));
	if (!conn->viewer_session) {
		ERR("Allocation viewer session");
		resp.status = htobe32(LTTNG_VIEWER_CREATE_SESSION_ERR);
		goto send_reply;
	}
	CDS_INIT_LIST_HEAD(&conn->viewer_session->sessions_head);

send_reply:
	health_code_update();
	ret = send_response(conn->sock, &resp, sizeof(resp));
	if (ret < 0) {
		goto end;
	}
	health_code_update();
	ret = 0;

end:
	return ret;
}


/*
 * live_relay_unknown_command: send -1 if received unknown command
 */
static
void live_relay_unknown_command(struct relay_connection *conn)
{
	struct lttcomm_relayd_generic_reply reply;

	memset(&reply, 0, sizeof(reply));
	reply.ret_code = htobe32(LTTNG_ERR_UNK);
	(void) send_response(conn->sock, &reply, sizeof(reply));
}

/*
 * Process the commands received on the control socket
 */
static
int process_control(struct lttng_viewer_cmd *recv_hdr,
		struct relay_connection *conn)
{
	int ret = 0;
	uint32_t msg_value;

	assert(recv_hdr);
	assert(conn);

	msg_value = be32toh(recv_hdr->cmd);

	/*
	 * Make sure we've done the version check before any command other then a
	 * new client connection.
	 */
	if (msg_value != LTTNG_VIEWER_CONNECT && !conn->version_check_done) {
		ERR("Viewer conn value %" PRIu32 " before version check", msg_value);
		ret = -1;
		goto end;
	}

	switch (msg_value) {
	case LTTNG_VIEWER_CONNECT:
		ret = viewer_connect(conn);
		break;
	case LTTNG_VIEWER_LIST_SESSIONS:
		ret = viewer_list_sessions(conn);
		break;
	case LTTNG_VIEWER_ATTACH_SESSION:
		ret = viewer_attach_session(conn);
		break;
	case LTTNG_VIEWER_GET_NEXT_INDEX:
		ret = viewer_get_next_index(conn);
		break;
	case LTTNG_VIEWER_GET_PACKET:
		ret = viewer_get_packet(conn);
		break;
	case LTTNG_VIEWER_GET_METADATA:
		ret = viewer_get_metadata(conn);
		break;
	case LTTNG_VIEWER_GET_NEW_STREAMS:
		ret = viewer_get_new_streams(conn);
		break;
	case LTTNG_VIEWER_CREATE_SESSION:
		ret = viewer_create_session(conn);
		break;
	default:
		ERR("Received unknown viewer command (%u)", be32toh(recv_hdr->cmd));
		live_relay_unknown_command(conn);
		ret = -1;
		goto end;
	}

end:
	return ret;
}

static
void cleanup_connection_pollfd(struct lttng_poll_event *events, int pollfd)
{
	int ret;

	assert(events);

	(void) lttng_poll_del(events, pollfd);

	ret = close(pollfd);
	if (ret < 0) {
		ERR("Closing pollfd %d", pollfd);
	}
}

/*
 * Delete and destroy a connection.
 *
 * RCU read side lock MUST be acquired.
 */
static void destroy_connection(struct lttng_ht *relay_connections_ht,
		struct relay_connection *conn)
{
	struct relay_session *session, *tmp_session;

	assert(relay_connections_ht);
	assert(conn);

	connection_delete(relay_connections_ht, conn);

	if (!conn->viewer_session) {
		goto end;
	}

	rcu_read_lock();
	cds_list_for_each_entry_safe(session, tmp_session,
			&conn->viewer_session->sessions_head,
			viewer_session_list) {
		DBG("Cleaning connection of session ID %" PRIu64, session->id);
		cleanup_session(conn, session);
	}
	rcu_read_unlock();

end:
	connection_destroy(conn);
}

/*
 * This thread does the actual work
 */
static
void *thread_worker(void *data)
{
	int ret, err = -1;
	uint32_t nb_fd;
	struct relay_connection *conn;
	struct lttng_poll_event events;
	struct lttng_ht *relay_connections_ht;
	struct lttng_ht_iter iter;
	struct lttng_viewer_cmd recv_hdr;
	struct relay_local_data *relay_ctx = (struct relay_local_data *) data;
	struct lttng_ht *sessions_ht = relay_ctx->sessions_ht;

	DBG("[thread] Live viewer relay worker started");

	rcu_register_thread();

	health_register(health_relayd, HEALTH_RELAYD_TYPE_LIVE_WORKER);

	if (testpoint(relayd_thread_live_worker)) {
		goto error_testpoint;
	}

	/* table of connections indexed on socket */
	relay_connections_ht = lttng_ht_new(0, LTTNG_HT_TYPE_ULONG);
	if (!relay_connections_ht) {
		goto relay_connections_ht_error;
	}

	ret = create_thread_poll_set(&events, 2);
	if (ret < 0) {
		goto error_poll_create;
	}

	ret = lttng_poll_add(&events, live_conn_pipe[0], LPOLLIN | LPOLLRDHUP);
	if (ret < 0) {
		goto error;
	}

restart:
	while (1) {
		int i;

		health_code_update();

		/* Infinite blocking call, waiting for transmission */
		DBG3("Relayd live viewer worker thread polling...");
		health_poll_entry();
		ret = lttng_poll_wait(&events, -1);
		health_poll_exit();
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

			health_code_update();

			if (!revents) {
				/* No activity for this FD (poll implementation). */
				continue;
			}

			/* Thread quit pipe has been closed. Killing thread. */
			ret = check_thread_quit_pipe(pollfd, revents);
			if (ret) {
				err = 0;
				goto exit;
			}

			/* Inspect the relay conn pipe for new connection */
			if (pollfd == live_conn_pipe[0]) {
				if (revents & (LPOLLERR | LPOLLHUP | LPOLLRDHUP)) {
					ERR("Relay live pipe error");
					goto error;
				} else if (revents & LPOLLIN) {
					ret = lttng_read(live_conn_pipe[0], &conn, sizeof(conn));
					if (ret < 0) {
						goto error;
					}
					conn->sessions_ht = sessions_ht;
					connection_init(conn);
					lttng_poll_add(&events, conn->sock->fd,
							LPOLLIN | LPOLLRDHUP);
					rcu_read_lock();
					lttng_ht_add_unique_ulong(relay_connections_ht,
							&conn->sock_n);
					rcu_read_unlock();
					DBG("Connection socket %d added", conn->sock->fd);
				}
			} else {
				rcu_read_lock();
				conn = connection_find_by_sock(relay_connections_ht, pollfd);
				/* If not found, there is a synchronization issue. */
				assert(conn);

				if (revents & (LPOLLERR | LPOLLHUP | LPOLLRDHUP)) {
					cleanup_connection_pollfd(&events, pollfd);
					destroy_connection(relay_connections_ht, conn);
				} else if (revents & LPOLLIN) {
					ret = conn->sock->ops->recvmsg(conn->sock, &recv_hdr,
							sizeof(recv_hdr), 0);
					if (ret <= 0) {
						/* Connection closed */
						cleanup_connection_pollfd(&events, pollfd);
						destroy_connection(relay_connections_ht, conn);
						DBG("Viewer control conn closed with %d", pollfd);
					} else {
						ret = process_control(&recv_hdr, conn);
						if (ret < 0) {
							/* Clear the session on error. */
							cleanup_connection_pollfd(&events, pollfd);
							destroy_connection(relay_connections_ht, conn);
							DBG("Viewer connection closed with %d", pollfd);
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

	/* Cleanup reamaining connection object. */
	rcu_read_lock();
	cds_lfht_for_each_entry(relay_connections_ht->ht, &iter.iter, conn,
			sock_n.node) {
		health_code_update();
		destroy_connection(relay_connections_ht, conn);
	}
	rcu_read_unlock();
error_poll_create:
	lttng_ht_destroy(relay_connections_ht);
relay_connections_ht_error:
	/* Close relay conn pipes */
	utils_close_pipe(live_conn_pipe);
	if (err) {
		DBG("Viewer worker thread exited with error");
	}
	DBG("Viewer worker thread cleanup complete");
error_testpoint:
	if (err) {
		health_error();
		ERR("Health error occurred in %s", __func__);
	}
	health_unregister(health_relayd);
	if (lttng_relay_stop_threads()) {
		ERR("Error stopping threads");
	}
	rcu_unregister_thread();
	return NULL;
}

/*
 * Create the relay command pipe to wake thread_manage_apps.
 * Closed in cleanup().
 */
static int create_conn_pipe(void)
{
	return utils_create_pipe_cloexec(live_conn_pipe);
}

int relayd_live_join(void)
{
	int ret, retval = 0;
	void *status;

	ret = pthread_join(live_listener_thread, &status);
	if (ret) {
		errno = ret;
		PERROR("pthread_join live listener");
		retval = -1;
	}

	ret = pthread_join(live_worker_thread, &status);
	if (ret) {
		errno = ret;
		PERROR("pthread_join live worker");
		retval = -1;
	}

	ret = pthread_join(live_dispatcher_thread, &status);
	if (ret) {
		errno = ret;
		PERROR("pthread_join live dispatcher");
		retval = -1;
	}

	cleanup_relayd_live();

	return retval;
}

/*
 * main
 */
int relayd_live_create(struct lttng_uri *uri,
		struct relay_local_data *relay_ctx)
{
	int ret = 0, retval = 0;
	void *status;
	int is_root;

	if (!uri) {
		retval = -1;
		goto exit_init_data;
	}
	live_uri = uri;

	/* Check if daemon is UID = 0 */
	is_root = !getuid();

	if (!is_root) {
		if (live_uri->port < 1024) {
			ERR("Need to be root to use ports < 1024");
			retval = -1;
			goto exit_init_data;
		}
	}

	/* Setup the thread apps communication pipe. */
	if (create_conn_pipe()) {
		retval = -1;
		goto exit_init_data;
	}

	/* Init relay command queue. */
	cds_wfcq_init(&viewer_conn_queue.head, &viewer_conn_queue.tail);

	/* Set up max poll set size */
	lttng_poll_set_max_size();

	/* Setup the dispatcher thread */
	ret = pthread_create(&live_dispatcher_thread, NULL,
			thread_dispatcher, (void *) NULL);
	if (ret) {
		errno = ret;
		PERROR("pthread_create viewer dispatcher");
		retval = -1;
		goto exit_dispatcher_thread;
	}

	/* Setup the worker thread */
	ret = pthread_create(&live_worker_thread, NULL,
			thread_worker, relay_ctx);
	if (ret) {
		errno = ret;
		PERROR("pthread_create viewer worker");
		retval = -1;
		goto exit_worker_thread;
	}

	/* Setup the listener thread */
	ret = pthread_create(&live_listener_thread, NULL,
			thread_listener, (void *) NULL);
	if (ret) {
		errno = ret;
		PERROR("pthread_create viewer listener");
		retval = -1;
		goto exit_listener_thread;
	}

	/*
	 * All OK, started all threads.
	 */
	return retval;


	ret = pthread_join(live_listener_thread, &status);
	if (ret) {
		errno = ret;
		PERROR("pthread_join live listener");
		retval = -1;
	}
exit_listener_thread:

	ret = pthread_join(live_worker_thread, &status);
	if (ret) {
		errno = ret;
		PERROR("pthread_join live worker");
		retval = -1;
	}
exit_worker_thread:

	ret = pthread_join(live_dispatcher_thread, &status);
	if (ret) {
		errno = ret;
		PERROR("pthread_join live dispatcher");
		retval = -1;
	}
exit_dispatcher_thread:

exit_init_data:
	cleanup_relayd_live();

	return retval;
}
