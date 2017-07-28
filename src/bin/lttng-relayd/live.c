/*
 * Copyright (C) 2013 - Julien Desfossez <jdesfossez@efficios.com>
 *                      David Goulet <dgoulet@efficios.com>
 *               2015 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

#define _LGPL_SOURCE
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
#include <urcu/rculist.h>
#include <unistd.h>
#include <fcntl.h>

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
#include "viewer-session.h"

#define SESSION_BUF_DEFAULT_COUNT	16

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
static pthread_mutex_t last_relay_viewer_session_id_lock =
		PTHREAD_MUTEX_INITIALIZER;

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
	rcu_read_lock();
	cds_list_for_each_entry_rcu(session,
			&conn->viewer_session->session_list,
			viewer_session_node) {
		if (!session_get(session)) {
			continue;
		}
		current_val = uatomic_cmpxchg(&session->new_streams, 1, 0);
		ret = current_val;
		session_put(session);
		if (ret == 1) {
			goto end;
		}
	}
end:
	rcu_read_unlock();
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

	rcu_read_lock();

	cds_lfht_for_each_entry(viewer_streams_ht->ht, &iter.iter, vstream,
			stream_n.node) {
		struct ctf_trace *ctf_trace;

		health_code_update();

		if (!viewer_stream_get(vstream)) {
			continue;
		}

		pthread_mutex_lock(&vstream->stream->lock);
		/* Ignore if not the same session. */
		if (vstream->stream->trace->session->id != session->id ||
				(!ignore_sent_flag && vstream->sent_flag)) {
			pthread_mutex_unlock(&vstream->stream->lock);
			viewer_stream_put(vstream);
			continue;
		}

		ctf_trace = vstream->stream->trace;
		send_stream.id = htobe64(vstream->stream->stream_handle);
		send_stream.ctf_trace_id = htobe64(ctf_trace->id);
		send_stream.metadata_flag = htobe32(
				vstream->stream->is_metadata);
		if (lttng_strncpy(send_stream.path_name, vstream->path_name,
				sizeof(send_stream.path_name))) {
			pthread_mutex_unlock(&vstream->stream->lock);
			viewer_stream_put(vstream);
			ret = -1;	/* Error. */
			goto end_unlock;
		}
		if (lttng_strncpy(send_stream.channel_name,
				vstream->channel_name,
				sizeof(send_stream.channel_name))) {
			pthread_mutex_unlock(&vstream->stream->lock);
			viewer_stream_put(vstream);
			ret = -1;	/* Error. */
			goto end_unlock;
		}

		DBG("Sending stream %" PRIu64 " to viewer",
				vstream->stream->stream_handle);
		vstream->sent_flag = 1;
		pthread_mutex_unlock(&vstream->stream->lock);

		ret = send_response(sock, &send_stream, sizeof(send_stream));
		viewer_stream_put(vstream);
		if (ret < 0) {
			goto end_unlock;
		}
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
		uint32_t *nb_created, bool *closed)
{
	int ret;
	struct lttng_ht_iter iter;
	struct ctf_trace *ctf_trace;

	assert(session);

	/*
	 * Hold the session lock to ensure that we see either none or
	 * all initial streams for a session, but no intermediate state.
	 */
	pthread_mutex_lock(&session->lock);

	if (session->connection_closed) {
		*closed = true;
	}

	/*
	 * Create viewer streams for relay streams that are ready to be
	 * used for a the given session id only.
	 */
	rcu_read_lock();
	cds_lfht_for_each_entry(session->ctf_traces_ht->ht, &iter.iter, ctf_trace,
			node.node) {
		struct relay_stream *stream;

		health_code_update();

		if (!ctf_trace_get(ctf_trace)) {
			continue;
		}

		cds_list_for_each_entry_rcu(stream, &ctf_trace->stream_list, stream_node) {
			struct relay_viewer_stream *vstream;

			if (!stream_get(stream)) {
				continue;
			}
			/*
			 * stream published is protected by the session lock.
			 */
			if (!stream->published) {
				goto next;
			}
			vstream = viewer_stream_get_by_id(stream->stream_handle);
			if (!vstream) {
				vstream = viewer_stream_create(stream, seek_t);
				if (!vstream) {
					ret = -1;
					ctf_trace_put(ctf_trace);
					stream_put(stream);
					goto error_unlock;
				}

				if (nb_created) {
					/* Update number of created stream counter. */
					(*nb_created)++;
				}
				/*
				 * Ensure a self-reference is preserved even
				 * after we have put our local reference.
				 */
				if (!viewer_stream_get(vstream)) {
					ERR("Unable to get self-reference on viewer stream, logic error.");
					abort();
				}
			} else {
				if (!vstream->sent_flag && nb_unsent) {
					/* Update number of unsent stream counter. */
					(*nb_unsent)++;
				}
			}
			/* Update number of total stream counter. */
			if (nb_total) {
				if (stream->is_metadata) {
					if (!stream->closed ||
							stream->metadata_received > vstream->metadata_sent) {
						(*nb_total)++;
					}
				} else {
					if (!stream->closed ||
						!(((int64_t) (stream->prev_seq - stream->last_net_seq_num)) >= 0)) {

						(*nb_total)++;
					}
				}
			}
			/* Put local reference. */
			viewer_stream_put(vstream);
		next:
			stream_put(stream);
		}
		ctf_trace_put(ctf_trace);
	}

	ret = 0;

error_unlock:
	rcu_read_unlock();
	pthread_mutex_unlock(&session->lock);
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

			if (revents & LPOLLIN) {
				/*
				 * A new connection is requested, therefore a
				 * viewer connection is allocated in this
				 * thread, enqueued to a global queue and
				 * dequeued (and freed) in the worker thread.
				 */
				int val = 1;
				struct relay_connection *new_conn;
				struct lttcomm_sock *newsock;

				newsock = live_control_sock->ops->accept(live_control_sock);
				if (!newsock) {
					PERROR("accepting control sock");
					goto error;
				}
				DBG("Relay viewer connection accepted socket %d", newsock->fd);

				ret = setsockopt(newsock->fd, SOL_SOCKET, SO_REUSEADDR, &val,
						sizeof(val));
				if (ret < 0) {
					PERROR("setsockopt inet");
					lttcomm_destroy_sock(newsock);
					goto error;
				}
				new_conn = connection_create(newsock, RELAY_CONNECTION_UNKNOWN);
				if (!new_conn) {
					lttcomm_destroy_sock(newsock);
					goto error;
				}
				/* Ownership assumed by the connection. */
				newsock = NULL;

				/* Enqueue request for the dispatcher thread. */
				cds_wfcq_enqueue(&viewer_conn_queue.head, &viewer_conn_queue.tail,
						 &new_conn->qnode);

				/*
				 * Wake the dispatch queue futex.
				 * Implicit memory barrier with the
				 * exchange in cds_wfcq_enqueue.
				 */
				futex_nto1_wake(&viewer_conn_queue.futex);
			} else if (revents & (LPOLLERR | LPOLLHUP | LPOLLRDHUP)) {
				ERR("socket poll error");
				goto error;
			} else {
				ERR("Unexpected poll events %u for sock %d", revents, pollfd);
				goto error;
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

	for (;;) {
		health_code_update();

		/* Atomically prepare the queue futex */
		futex_nto1_prepare(&viewer_conn_queue.futex);

		if (CMM_LOAD_SHARED(live_dispatch_thread_exit)) {
			break;
		}

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
			 * Inform worker thread of the new request. This
			 * call is blocking so we can be assured that
			 * the data will be read at some point in time
			 * or wait to the end of the world :)
			 */
			ret = lttng_write(live_conn_pipe[1], &conn, sizeof(conn));
			if (ret < 0) {
				PERROR("write conn pipe");
				connection_put(conn);
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
		 * Increment outside of htobe64 macro, because the argument can
		 * be used more than once within the macro, and thus the
		 * operation may be undefined.
		 */
		pthread_mutex_lock(&last_relay_viewer_session_id_lock);
		last_relay_viewer_session_id++;
		pthread_mutex_unlock(&last_relay_viewer_session_id_lock);
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
 * We need to create a copy of the hash table content because otherwise
 * we cannot assume the number of entries stays the same between getting
 * the number of HT elements and iteration over the HT.
 *
 * Return 0 on success or else a negative value.
 */
static
int viewer_list_sessions(struct relay_connection *conn)
{
	int ret = 0;
	struct lttng_viewer_list_sessions session_list;
	struct lttng_ht_iter iter;
	struct relay_session *session;
	struct lttng_viewer_session *send_session_buf = NULL;
	uint32_t buf_count = SESSION_BUF_DEFAULT_COUNT;
	uint32_t count = 0;

	DBG("List sessions received");

	send_session_buf = zmalloc(SESSION_BUF_DEFAULT_COUNT * sizeof(*send_session_buf));
	if (!send_session_buf) {
		return -1;
	}

	rcu_read_lock();
	cds_lfht_for_each_entry(sessions_ht->ht, &iter.iter, session,
			session_n.node) {
		struct lttng_viewer_session *send_session;

		health_code_update();

		if (count >= buf_count) {
			struct lttng_viewer_session *newbuf;
			uint32_t new_buf_count = buf_count << 1;

			newbuf = realloc(send_session_buf,
				new_buf_count * sizeof(*send_session_buf));
			if (!newbuf) {
				ret = -1;
				break;
			}
			send_session_buf = newbuf;
			buf_count = new_buf_count;
		}
		send_session = &send_session_buf[count];
		if (lttng_strncpy(send_session->session_name,
				session->session_name,
				sizeof(send_session->session_name))) {
			ret = -1;
			break;
		}
		if (lttng_strncpy(send_session->hostname, session->hostname,
				sizeof(send_session->hostname))) {
			ret = -1;
			break;
		}
		send_session->id = htobe64(session->id);
		send_session->live_timer = htobe32(session->live_timer);
		if (session->viewer_attached) {
			send_session->clients = htobe32(1);
		} else {
			send_session->clients = htobe32(0);
		}
		send_session->streams = htobe32(session->stream_count);
		count++;
	}
	rcu_read_unlock();
	if (ret < 0) {
		goto end_free;
	}

	session_list.sessions_count = htobe32(count);

	health_code_update();

	ret = send_response(conn->sock, &session_list, sizeof(session_list));
	if (ret < 0) {
		goto end_free;
	}

	health_code_update();

	ret = send_response(conn->sock, send_session_buf,
			count * sizeof(*send_session_buf));
	if (ret < 0) {
		goto end_free;
	}
	health_code_update();

	ret = 0;
end_free:
	free(send_session_buf);
	return ret;
}

/*
 * Send the viewer the list of current streams.
 */
static
int viewer_get_new_streams(struct relay_connection *conn)
{
	int ret, send_streams = 0;
	uint32_t nb_created = 0, nb_unsent = 0, nb_streams = 0, nb_total = 0;
	struct lttng_viewer_new_streams_request request;
	struct lttng_viewer_new_streams_response response;
	struct relay_session *session;
	uint64_t session_id;
	bool closed = false;

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

	session = session_get_by_id(session_id);
	if (!session) {
		DBG("Relay session %" PRIu64 " not found", session_id);
		response.status = htobe32(LTTNG_VIEWER_NEW_STREAMS_ERR);
		goto send_reply;
	}

	if (!viewer_session_is_attached(conn->viewer_session, session)) {
		send_streams = 0;
		response.status = htobe32(LTTNG_VIEWER_NEW_STREAMS_ERR);
		goto send_reply;
	}

	send_streams = 1;
	response.status = htobe32(LTTNG_VIEWER_NEW_STREAMS_OK);

	ret = make_viewer_streams(session, LTTNG_VIEWER_SEEK_LAST, &nb_total, &nb_unsent,
			&nb_created, &closed);
	if (ret < 0) {
		goto end_put_session;
	}
	/* Only send back the newly created streams with the unsent ones. */
	nb_streams = nb_created + nb_unsent;
	response.streams_count = htobe32(nb_streams);

	/*
	 * If the session is closed, HUP when there are no more streams
	 * with data.
	 */
	if (closed && nb_total == 0) {
		send_streams = 0;
		response.streams_count = 0;
		response.status = htobe32(LTTNG_VIEWER_NEW_STREAMS_HUP);
		goto send_reply;
	}

send_reply:
	health_code_update();
	ret = send_response(conn->sock, &response, sizeof(response));
	if (ret < 0) {
		goto end_put_session;
	}
	health_code_update();

	/*
	 * Unknown or empty session, just return gracefully, the viewer
	 * knows what is happening.
	 */
	if (!send_streams || !nb_streams) {
		ret = 0;
		goto end_put_session;
	}

	/*
	 * Send stream and *DON'T* ignore the sent flag so every viewer
	 * streams that were not sent from that point will be sent to
	 * the viewer.
	 */
	ret = send_viewer_streams(conn->sock, session, 0);
	if (ret < 0) {
		goto end_put_session;
	}

end_put_session:
	if (session) {
		session_put(session);
	}
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
	struct relay_session *session = NULL;
	bool closed = false;

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

	session = session_get_by_id(be64toh(request.session_id));
	if (!session) {
		DBG("Relay session %" PRIu64 " not found",
				be64toh(request.session_id));
		response.status = htobe32(LTTNG_VIEWER_ATTACH_UNK);
		goto send_reply;
	}
	DBG("Attach session ID %" PRIu64 " received",
		be64toh(request.session_id));

	if (session->live_timer == 0) {
		DBG("Not live session");
		response.status = htobe32(LTTNG_VIEWER_ATTACH_NOT_LIVE);
		goto send_reply;
	}

	send_streams = 1;
	ret = viewer_session_attach(conn->viewer_session, session);
	if (ret) {
		DBG("Already a viewer attached");
		response.status = htobe32(LTTNG_VIEWER_ATTACH_ALREADY);
		goto send_reply;
	}

	switch (be32toh(request.seek)) {
	case LTTNG_VIEWER_SEEK_BEGINNING:
	case LTTNG_VIEWER_SEEK_LAST:
		response.status = htobe32(LTTNG_VIEWER_ATTACH_OK);
		seek_type = be32toh(request.seek);
		break;
	default:
		ERR("Wrong seek parameter");
		response.status = htobe32(LTTNG_VIEWER_ATTACH_SEEK_ERR);
		send_streams = 0;
		goto send_reply;
	}

	ret = make_viewer_streams(session, seek_type, &nb_streams, NULL,
			NULL, &closed);
	if (ret < 0) {
		goto end_put_session;
	}
	response.streams_count = htobe32(nb_streams);

	/*
	 * If the session is closed when the viewer is attaching, it
	 * means some of the streams may have been concurrently removed,
	 * so we don't allow the viewer to attach, even if there are
	 * streams available.
	 */
	if (closed) {
		send_streams = 0;
		response.streams_count = 0;
		response.status = htobe32(LTTNG_VIEWER_NEW_STREAMS_HUP);
		goto send_reply;
	}

send_reply:
	health_code_update();
	ret = send_response(conn->sock, &response, sizeof(response));
	if (ret < 0) {
		goto end_put_session;
	}
	health_code_update();

	/*
	 * Unknown or empty session, just return gracefully, the viewer
	 * knows what is happening.
	 */
	if (!send_streams || !nb_streams) {
		ret = 0;
		goto end_put_session;
	}

	/* Send stream and ignore the sent flag. */
	ret = send_viewer_streams(conn->sock, session, 1);
	if (ret < 0) {
		goto end_put_session;
	}

end_put_session:
	if (session) {
		session_put(session);
	}
error:
	return ret;
}

/*
 * Open the index file if needed for the given vstream.
 *
 * If an index file is successfully opened, the vstream will set it as its
 * current index file.
 *
 * Return 0 on success, a negative value on error (-ENOENT if not ready yet).
 *
 * Called with rstream lock held.
 */
static int try_open_index(struct relay_viewer_stream *vstream,
		struct relay_stream *rstream)
{
	int ret = 0;

	if (vstream->index_file) {
		goto end;
	}

	/*
	 * First time, we open the index file and at least one index is ready.
	 */
	if (rstream->index_received_seqcount == 0) {
		ret = -ENOENT;
		goto end;
	}
	vstream->index_file = lttng_index_file_open(vstream->path_name,
			vstream->channel_name,
			vstream->stream->tracefile_count,
			vstream->current_tracefile_id);
	if (!vstream->index_file) {
		ret = -1;
	}

end:
	return ret;
}

/*
 * Check the status of the index for the given stream. This function
 * updates the index structure if needed and can put (close) the vstream
 * in the HUP situation.
 *
 * Return 0 means that we can proceed with the index. A value of 1 means
 * that the index has been updated and is ready to be sent to the
 * client. A negative value indicates an error that can't be handled.
 *
 * Called with rstream lock held.
 */
static int check_index_status(struct relay_viewer_stream *vstream,
		struct relay_stream *rstream, struct ctf_trace *trace,
		struct lttng_viewer_index *index)
{
	int ret;

	if ((trace->session->connection_closed || rstream->closed)
			&& rstream->index_received_seqcount
				== vstream->index_sent_seqcount) {
		/*
		 * Last index sent and session connection or relay
		 * stream are closed.
		 */
		index->status = htobe32(LTTNG_VIEWER_INDEX_HUP);
		goto hup;
	} else if (rstream->beacon_ts_end != -1ULL &&
			rstream->index_received_seqcount
				== vstream->index_sent_seqcount) {
		/*
		 * We've received a synchronization beacon and the last index
		 * available has been sent, the index for now is inactive.
		 *
		 * In this case, we have received a beacon which allows us to
		 * inform the client of a time interval during which we can
		 * guarantee that there are no events to read (and never will
		 * be).
		 */
		index->status = htobe32(LTTNG_VIEWER_INDEX_INACTIVE);
		index->timestamp_end = htobe64(rstream->beacon_ts_end);
		index->stream_id = htobe64(rstream->ctf_stream_id);
		goto index_ready;
	} else if (rstream->index_received_seqcount
			== vstream->index_sent_seqcount) {
		/*
		 * This checks whether received == sent seqcount. In
		 * this case, we have not received a beacon. Therefore,
		 * we can only ask the client to retry later.
		 */
		index->status = htobe32(LTTNG_VIEWER_INDEX_RETRY);
		goto index_ready;
	} else if (!tracefile_array_seq_in_file(rstream->tfa,
			vstream->current_tracefile_id,
			vstream->index_sent_seqcount)) {
		/*
		 * The next index we want to send cannot be read either
		 * because we need to perform a rotation, or due to
		 * the producer having overwritten its trace file.
		 */
		DBG("Viewer stream %" PRIu64 " rotation",
				vstream->stream->stream_handle);
		ret = viewer_stream_rotate(vstream);
		if (ret < 0) {
			goto end;
		} else if (ret == 1) {
			/* EOF across entire stream. */
			index->status = htobe32(LTTNG_VIEWER_INDEX_HUP);
			goto hup;
		}
		/*
		 * If we have been pushed due to overwrite, it
		 * necessarily means there is data that can be read in
		 * the stream. If we rotated because we reached the end
		 * of a tracefile, it means the following tracefile
		 * needs to contain at least one index, else we would
		 * have already returned LTTNG_VIEWER_INDEX_RETRY to the
		 * viewer. The updated index_sent_seqcount needs to
		 * point to a readable index entry now.
		 *
		 * In the case where we "rotate" on a single file, we
		 * can end up in a case where the requested index is
		 * still unavailable.
		 */
		if (rstream->tracefile_count == 1 &&
				!tracefile_array_seq_in_file(
					rstream->tfa,
					vstream->current_tracefile_id,
					vstream->index_sent_seqcount)) {
			index->status = htobe32(LTTNG_VIEWER_INDEX_RETRY);
			goto index_ready;
		}
		assert(tracefile_array_seq_in_file(rstream->tfa,
				vstream->current_tracefile_id,
				vstream->index_sent_seqcount));
	}
	/* ret == 0 means successful so we continue. */
	ret = 0;
end:
	return ret;

hup:
	viewer_stream_put(vstream);
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
	struct lttng_viewer_get_next_index request_index;
	struct lttng_viewer_index viewer_index;
	struct ctf_packet_index packet_index;
	struct relay_viewer_stream *vstream = NULL;
	struct relay_stream *rstream = NULL;
	struct ctf_trace *ctf_trace = NULL;
	struct relay_viewer_stream *metadata_viewer_stream = NULL;

	assert(conn);

	DBG("Viewer get next index");

	memset(&viewer_index, 0, sizeof(viewer_index));
	health_code_update();

	ret = recv_request(conn->sock, &request_index, sizeof(request_index));
	if (ret < 0) {
		goto end;
	}
	health_code_update();

	vstream = viewer_stream_get_by_id(be64toh(request_index.stream_id));
	if (!vstream) {
		DBG("Client requested index of unknown stream id %" PRIu64,
				be64toh(request_index.stream_id));
		viewer_index.status = htobe32(LTTNG_VIEWER_INDEX_ERR);
		goto send_reply;
	}

	/* Use back. ref. Protected by refcounts. */
	rstream = vstream->stream;
	ctf_trace = rstream->trace;

	/* metadata_viewer_stream may be NULL. */
	metadata_viewer_stream =
			ctf_trace_get_viewer_metadata_stream(ctf_trace);

	pthread_mutex_lock(&rstream->lock);

	/*
	 * The viewer should not ask for index on metadata stream.
	 */
	if (rstream->is_metadata) {
		viewer_index.status = htobe32(LTTNG_VIEWER_INDEX_HUP);
		goto send_reply;
	}

	/* Try to open an index if one is needed for that stream. */
	ret = try_open_index(vstream, rstream);
	if (ret < 0) {
		if (ret == -ENOENT) {
			/*
			 * The index is created only when the first data
			 * packet arrives, it might not be ready at the
			 * beginning of the session
			 */
			viewer_index.status = htobe32(LTTNG_VIEWER_INDEX_RETRY);
		} else {
			/* Unhandled error. */
			viewer_index.status = htobe32(LTTNG_VIEWER_INDEX_ERR);
		}
		goto send_reply;
	}

	ret = check_index_status(vstream, rstream, ctf_trace, &viewer_index);
	if (ret < 0) {
		goto error_put;
	} else if (ret == 1) {
		/*
		 * We have no index to send and check_index_status has populated
		 * viewer_index's status.
		 */
		goto send_reply;
	}
	/* At this point, ret is 0 thus we will be able to read the index. */
	assert(!ret);

	/*
	 * vstream->stream_fd may be NULL if it has been closed by
	 * tracefile rotation, or if we are at the beginning of the
	 * stream. We open the data stream file here to protect against
	 * overwrite caused by tracefile rotation (in association with
	 * unlink performed before overwrite).
	 */
	if (!vstream->stream_fd) {
		char fullpath[PATH_MAX];

		if (vstream->stream->tracefile_count > 0) {
			ret = snprintf(fullpath, PATH_MAX, "%s/%s_%" PRIu64,
					vstream->path_name,
					vstream->channel_name,
					vstream->current_tracefile_id);
		} else {
			ret = snprintf(fullpath, PATH_MAX, "%s/%s",
					vstream->path_name,
					vstream->channel_name);
		}
		if (ret < 0) {
			goto error_put;
		}
		ret = open(fullpath, O_RDONLY);
		if (ret < 0) {
			PERROR("Relay opening trace file");
			goto error_put;
		}
		vstream->stream_fd = stream_fd_create(ret);
		if (!vstream->stream_fd) {
			if (close(ret)) {
				PERROR("close");
			}
			goto error_put;
		}
	}

	ret = check_new_streams(conn);
	if (ret < 0) {
		viewer_index.status = htobe32(LTTNG_VIEWER_INDEX_ERR);
		goto send_reply;
	} else if (ret == 1) {
		viewer_index.flags |= LTTNG_VIEWER_FLAG_NEW_STREAM;
	}

	ret = lttng_index_file_read(vstream->index_file, &packet_index);
	if (ret) {
		ERR("Relay error reading index file %d",
				vstream->index_file->fd);
		viewer_index.status = htobe32(LTTNG_VIEWER_INDEX_ERR);
		goto send_reply;
	} else {
		viewer_index.status = htobe32(LTTNG_VIEWER_INDEX_OK);
		vstream->index_sent_seqcount++;
	}

	/*
	 * Indexes are stored in big endian, no need to switch before sending.
	 */
	DBG("Sending viewer index for stream %" PRIu64 " offset %" PRIu64,
		rstream->stream_handle,
		be64toh(packet_index.offset));
	viewer_index.offset = packet_index.offset;
	viewer_index.packet_size = packet_index.packet_size;
	viewer_index.content_size = packet_index.content_size;
	viewer_index.timestamp_begin = packet_index.timestamp_begin;
	viewer_index.timestamp_end = packet_index.timestamp_end;
	viewer_index.events_discarded = packet_index.events_discarded;
	viewer_index.stream_id = packet_index.stream_id;

send_reply:
	if (rstream) {
		pthread_mutex_unlock(&rstream->lock);
	}

	if (metadata_viewer_stream) {
		pthread_mutex_lock(&metadata_viewer_stream->stream->lock);
		DBG("get next index metadata check: recv %" PRIu64
				" sent %" PRIu64,
			metadata_viewer_stream->stream->metadata_received,
			metadata_viewer_stream->metadata_sent);
		if (!metadata_viewer_stream->stream->metadata_received ||
				metadata_viewer_stream->stream->metadata_received >
					metadata_viewer_stream->metadata_sent) {
			viewer_index.flags |= LTTNG_VIEWER_FLAG_NEW_METADATA;
		}
		pthread_mutex_unlock(&metadata_viewer_stream->stream->lock);
	}

	viewer_index.flags = htobe32(viewer_index.flags);
	health_code_update();

	ret = send_response(conn->sock, &viewer_index, sizeof(viewer_index));
	if (ret < 0) {
		goto end;
	}
	health_code_update();

	if (vstream) {
		DBG("Index %" PRIu64 " for stream %" PRIu64 " sent",
				vstream->index_sent_seqcount,
				vstream->stream->stream_handle);
	}
end:
	if (metadata_viewer_stream) {
		viewer_stream_put(metadata_viewer_stream);
	}
	if (vstream) {
		viewer_stream_put(vstream);
	}
	return ret;

error_put:
	pthread_mutex_unlock(&rstream->lock);
	if (metadata_viewer_stream) {
		viewer_stream_put(metadata_viewer_stream);
	}
	viewer_stream_put(vstream);
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
	int ret;
	char *reply = NULL;
	struct lttng_viewer_get_packet get_packet_info;
	struct lttng_viewer_trace_packet reply_header;
	struct relay_viewer_stream *vstream = NULL;
	uint32_t reply_size = sizeof(reply_header);
	uint32_t packet_data_len = 0;
	ssize_t read_len;

	DBG2("Relay get data packet");

	health_code_update();

	ret = recv_request(conn->sock, &get_packet_info,
			sizeof(get_packet_info));
	if (ret < 0) {
		goto end;
	}
	health_code_update();

	/* From this point on, the error label can be reached. */
	memset(&reply_header, 0, sizeof(reply_header));

	vstream = viewer_stream_get_by_id(be64toh(get_packet_info.stream_id));
	if (!vstream) {
		DBG("Client requested packet of unknown stream id %" PRIu64,
				be64toh(get_packet_info.stream_id));
		reply_header.status = htobe32(LTTNG_VIEWER_GET_PACKET_ERR);
		goto send_reply_nolock;
	} else {
		packet_data_len = be32toh(get_packet_info.len);
		reply_size += packet_data_len;
	}

	reply = zmalloc(reply_size);
	if (!reply) {
		PERROR("packet reply zmalloc");
		reply_size = sizeof(reply_header);
		goto error;
	}

	pthread_mutex_lock(&vstream->stream->lock);
	ret = lseek(vstream->stream_fd->fd, be64toh(get_packet_info.offset),
			SEEK_SET);
	if (ret < 0) {
		PERROR("lseek fd %d to offset %" PRIu64, vstream->stream_fd->fd,
			be64toh(get_packet_info.offset));
		goto error;
	}
	read_len = lttng_read(vstream->stream_fd->fd,
			reply + sizeof(reply_header),
			packet_data_len);
	if (read_len < packet_data_len) {
		PERROR("Relay reading trace file, fd: %d, offset: %" PRIu64,
				vstream->stream_fd->fd,
				be64toh(get_packet_info.offset));
		goto error;
	}
	reply_header.status = htobe32(LTTNG_VIEWER_GET_PACKET_OK);
	reply_header.len = htobe32(packet_data_len);
	goto send_reply;

error:
	reply_header.status = htobe32(LTTNG_VIEWER_GET_PACKET_ERR);

send_reply:
	if (vstream) {
		pthread_mutex_unlock(&vstream->stream->lock);
	}
send_reply_nolock:

	health_code_update();

	if (reply) {
		memcpy(reply, &reply_header, sizeof(reply_header));
		ret = send_response(conn->sock, reply, reply_size);
	} else {
		/* No reply to send. */
		ret = send_response(conn->sock, &reply_header,
				reply_size);
	}

	health_code_update();
	if (ret < 0) {
		PERROR("sendmsg of packet data failed");
		goto end_free;
	}

	DBG("Sent %u bytes for stream %" PRIu64, reply_size,
			be64toh(get_packet_info.stream_id));

end_free:
	free(reply);
end:
	if (vstream) {
		viewer_stream_put(vstream);
	}
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
	struct relay_viewer_stream *vstream = NULL;

	assert(conn);

	DBG("Relay get metadata");

	health_code_update();

	ret = recv_request(conn->sock, &request, sizeof(request));
	if (ret < 0) {
		goto end;
	}
	health_code_update();

	memset(&reply, 0, sizeof(reply));

	vstream = viewer_stream_get_by_id(be64toh(request.stream_id));
	if (!vstream) {
		/*
		 * The metadata stream can be closed by a CLOSE command
		 * just before we attach. It can also be closed by
		 * per-pid tracing during tracing. Therefore, it is
		 * possible that we cannot find this viewer stream.
		 * Reply back to the client with an error if we cannot
		 * find it.
		 */
		DBG("Client requested metadata of unknown stream id %" PRIu64,
				be64toh(request.stream_id));
		reply.status = htobe32(LTTNG_VIEWER_METADATA_ERR);
		goto send_reply;
	}
	pthread_mutex_lock(&vstream->stream->lock);
	if (!vstream->stream->is_metadata) {
		ERR("Invalid metadata stream");
		goto error;
	}

	assert(vstream->metadata_sent <= vstream->stream->metadata_received);

	len = vstream->stream->metadata_received - vstream->metadata_sent;
	if (len == 0) {
		reply.status = htobe32(LTTNG_VIEWER_NO_NEW_METADATA);
		goto send_reply;
	}

	/* first time, we open the metadata file */
	if (!vstream->stream_fd) {
		char fullpath[PATH_MAX];

		ret = snprintf(fullpath, PATH_MAX, "%s/%s", vstream->path_name,
				vstream->channel_name);
		if (ret < 0) {
			goto error;
		}
		ret = open(fullpath, O_RDONLY);
		if (ret < 0) {
			PERROR("Relay opening metadata file");
			goto error;
		}
		vstream->stream_fd = stream_fd_create(ret);
		if (!vstream->stream_fd) {
			if (close(ret)) {
				PERROR("close");
			}
			goto error;
		}
	}

	reply.len = htobe64(len);
	data = zmalloc(len);
	if (!data) {
		PERROR("viewer metadata zmalloc");
		goto error;
	}

	read_len = lttng_read(vstream->stream_fd->fd, data, len);
	if (read_len < len) {
		PERROR("Relay reading metadata file");
		goto error;
	}
	vstream->metadata_sent += read_len;
	if (vstream->metadata_sent == vstream->stream->metadata_received
			&& vstream->stream->closed) {
		/* Release ownership for the viewer metadata stream. */
		viewer_stream_put(vstream);
	}

	reply.status = htobe32(LTTNG_VIEWER_METADATA_OK);

	goto send_reply;

error:
	reply.status = htobe32(LTTNG_VIEWER_METADATA_ERR);

send_reply:
	health_code_update();
	if (vstream) {
		pthread_mutex_unlock(&vstream->stream->lock);
	}
	ret = send_response(conn->sock, &reply, sizeof(reply));
	if (ret < 0) {
		goto end_free;
	}
	health_code_update();

	if (len > 0) {
		ret = send_response(conn->sock, data, len);
		if (ret < 0) {
			goto end_free;
		}
	}

	DBG("Sent %" PRIu64 " bytes of metadata for stream %" PRIu64, len,
			be64toh(request.stream_id));

	DBG("Metadata sent");

end_free:
	free(data);
end:
	if (vstream) {
		viewer_stream_put(vstream);
	}
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
	conn->viewer_session = viewer_session_create();
	if (!conn->viewer_session) {
		ERR("Allocation viewer session");
		resp.status = htobe32(LTTNG_VIEWER_CREATE_SESSION_ERR);
		goto send_reply;
	}

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
 * Detach a viewer session.
 *
 * Return 0 on success or else a negative value.
 */
static
int viewer_detach_session(struct relay_connection *conn)
{
	int ret;
	struct lttng_viewer_detach_session_response response;
	struct lttng_viewer_detach_session_request request;
	struct relay_session *session = NULL;
	uint64_t viewer_session_to_close;

	DBG("Viewer detach session received");

	assert(conn);

	health_code_update();

	/* Receive the request from the connected client. */
	ret = recv_request(conn->sock, &request, sizeof(request));
	if (ret < 0) {
		goto end;
	}
	viewer_session_to_close = be64toh(request.session_id);

	if (!conn->viewer_session) {
		DBG("Client trying to detach before creating a live viewer session");
		response.status = htobe32(LTTNG_VIEWER_DETACH_SESSION_ERR);
		goto send_reply;
	}

	health_code_update();

	memset(&response, 0, sizeof(response));
	DBG("Detaching from session ID %" PRIu64, viewer_session_to_close);

	session = session_get_by_id(be64toh(request.session_id));
	if (!session) {
		DBG("Relay session %" PRIu64 " not found",
				be64toh(request.session_id));
		response.status = htobe32(LTTNG_VIEWER_DETACH_SESSION_UNK);
		goto send_reply;
	}

	ret = viewer_session_is_attached(conn->viewer_session, session);
	if (ret != 1) {
		DBG("Not attached to this session");
		response.status = htobe32(LTTNG_VIEWER_DETACH_SESSION_ERR);
		goto send_reply_put;
	}

	viewer_session_close_one_session(conn->viewer_session, session);
	response.status = htobe32(LTTNG_VIEWER_DETACH_SESSION_OK);
	DBG("Session %" PRIu64 " detached.", viewer_session_to_close);

send_reply_put:
	session_put(session);

send_reply:
	health_code_update();
	ret = send_response(conn->sock, &response, sizeof(response));
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
	case LTTNG_VIEWER_DETACH_SESSION:
		ret = viewer_detach_session(conn);
		break;
	default:
		ERR("Received unknown viewer command (%u)",
				be32toh(recv_hdr->cmd));
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

	(void) lttng_poll_del(events, pollfd);

	ret = close(pollfd);
	if (ret < 0) {
		ERR("Closing pollfd %d", pollfd);
	}
}

/*
 * This thread does the actual work
 */
static
void *thread_worker(void *data)
{
	int ret, err = -1;
	uint32_t nb_fd;
	struct lttng_poll_event events;
	struct lttng_ht *viewer_connections_ht;
	struct lttng_ht_iter iter;
	struct lttng_viewer_cmd recv_hdr;
	struct relay_connection *destroy_conn;

	DBG("[thread] Live viewer relay worker started");

	rcu_register_thread();

	health_register(health_relayd, HEALTH_RELAYD_TYPE_LIVE_WORKER);

	if (testpoint(relayd_thread_live_worker)) {
		goto error_testpoint;
	}

	/* table of connections indexed on socket */
	viewer_connections_ht = lttng_ht_new(0, LTTNG_HT_TYPE_ULONG);
	if (!viewer_connections_ht) {
		goto viewer_connections_ht_error;
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

			/* Inspect the relay conn pipe for new connection. */
			if (pollfd == live_conn_pipe[0]) {
				if (revents & LPOLLIN) {
					struct relay_connection *conn;

					ret = lttng_read(live_conn_pipe[0],
							&conn, sizeof(conn));
					if (ret < 0) {
						goto error;
					}
					lttng_poll_add(&events, conn->sock->fd,
							LPOLLIN | LPOLLRDHUP);
					connection_ht_add(viewer_connections_ht, conn);
					DBG("Connection socket %d added to poll", conn->sock->fd);
				} else if (revents & (LPOLLERR | LPOLLHUP | LPOLLRDHUP)) {
					ERR("Relay live pipe error");
					goto error;
				} else {
					ERR("Unexpected poll events %u for sock %d", revents, pollfd);
					goto error;
				}
			} else {
				/* Connection activity. */
				struct relay_connection *conn;

				conn = connection_get_by_sock(viewer_connections_ht, pollfd);
				if (!conn) {
					continue;
				}

				if (revents & LPOLLIN) {
					ret = conn->sock->ops->recvmsg(conn->sock, &recv_hdr,
							sizeof(recv_hdr), 0);
					if (ret <= 0) {
						/* Connection closed. */
						cleanup_connection_pollfd(&events, pollfd);
						/* Put "create" ownership reference. */
						connection_put(conn);
						DBG("Viewer control conn closed with %d", pollfd);
					} else {
						ret = process_control(&recv_hdr, conn);
						if (ret < 0) {
							/* Clear the session on error. */
							cleanup_connection_pollfd(&events, pollfd);
							/* Put "create" ownership reference. */
							connection_put(conn);
							DBG("Viewer connection closed with %d", pollfd);
						}
					}
				} else if (revents & (LPOLLERR | LPOLLHUP | LPOLLRDHUP)) {
					cleanup_connection_pollfd(&events, pollfd);
					/* Put "create" ownership reference. */
					connection_put(conn);
				} else {
					ERR("Unexpected poll events %u for sock %d", revents, pollfd);
					connection_put(conn);
					goto error;
				}
				/* Put local "get_by_sock" reference. */
				connection_put(conn);
			}
		}
	}

exit:
error:
	lttng_poll_clean(&events);

	/* Cleanup reamaining connection object. */
	rcu_read_lock();
	cds_lfht_for_each_entry(viewer_connections_ht->ht, &iter.iter,
			destroy_conn,
			sock_n.node) {
		health_code_update();
		connection_put(destroy_conn);
	}
	rcu_read_unlock();
error_poll_create:
	lttng_ht_destroy(viewer_connections_ht);
viewer_connections_ht_error:
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
int relayd_live_create(struct lttng_uri *uri)
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
	if (lttng_poll_set_max_size()) {
		retval = -1;
		goto exit_init_data;
	}

	/* Setup the dispatcher thread */
	ret = pthread_create(&live_dispatcher_thread, default_pthread_attr(),
			thread_dispatcher, (void *) NULL);
	if (ret) {
		errno = ret;
		PERROR("pthread_create viewer dispatcher");
		retval = -1;
		goto exit_dispatcher_thread;
	}

	/* Setup the worker thread */
	ret = pthread_create(&live_worker_thread, default_pthread_attr(),
			thread_worker, NULL);
	if (ret) {
		errno = ret;
		PERROR("pthread_create viewer worker");
		retval = -1;
		goto exit_worker_thread;
	}

	/* Setup the listener thread */
	ret = pthread_create(&live_listener_thread, default_pthread_attr(),
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

	/*
	 * Join on the live_listener_thread should anything be added after
	 * the live_listener thread's creation.
	 */

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
