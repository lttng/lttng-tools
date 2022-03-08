/*
 * Copyright (C) 2013 Julien Desfossez <jdesfossez@efficios.com>
 * Copyright (C) 2013 David Goulet <dgoulet@efficios.com>
 * Copyright (C) 2015 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include <fcntl.h>
#include <getopt.h>
#include <grp.h>
#include <inttypes.h>
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
#include <unistd.h>
#include <urcu/futex.h>
#include <urcu/rculist.h>
#include <urcu/uatomic.h>
#include <string>

#include <common/common.h>
#include <common/compat/endian.h>
#include <common/compat/poll.h>
#include <common/compat/socket.h>
#include <common/defaults.h>
#include <common/fd-tracker/utils.h>
#include <common/fs-handle.h>
#include <common/futex.h>
#include <common/index/index.h>
#include <common/sessiond-comm/inet.h>
#include <common/sessiond-comm/relayd.h>
#include <common/sessiond-comm/sessiond-comm.h>
#include <common/uri.h>
#include <common/utils.h>
#include <lttng/lttng.h>

#include "cmd.h"
#include "connection.h"
#include "ctf-trace.h"
#include "health-relayd.h"
#include "live.h"
#include "lttng-relayd.h"
#include "session.h"
#include "stream.h"
#include "testpoint.h"
#include "utils.h"
#include "viewer-session.h"
#include "viewer-stream.h"

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

static
const char *lttng_viewer_command_str(lttng_viewer_command cmd)
{
	switch (cmd) {
	case LTTNG_VIEWER_CONNECT:
		return "CONNECT";
	case LTTNG_VIEWER_LIST_SESSIONS:
		return "LIST_SESSIONS";
	case LTTNG_VIEWER_ATTACH_SESSION:
		return "ATTACH_SESSION";
	case LTTNG_VIEWER_GET_NEXT_INDEX:
		return "GET_NEXT_INDEX";
	case LTTNG_VIEWER_GET_PACKET:
		return "GET_PACKET";
	case LTTNG_VIEWER_GET_METADATA:
		return "GET_METADATA";
	case LTTNG_VIEWER_GET_NEW_STREAMS:
		return "GET_NEW_STREAMS";
	case LTTNG_VIEWER_CREATE_SESSION:
		return "CREATE_SESSION";
	case LTTNG_VIEWER_DETACH_SESSION:
		return "DETACH_SESSION";
	default:
		abort();
	}
}

static
const char *lttng_viewer_next_index_return_code_str(
		enum lttng_viewer_next_index_return_code code)
{
	switch (code) {
	case LTTNG_VIEWER_INDEX_OK:
		return "INDEX_OK";
	case LTTNG_VIEWER_INDEX_RETRY:
		return "INDEX_RETRY";
	case LTTNG_VIEWER_INDEX_HUP:
		return "INDEX_HUP";
	case LTTNG_VIEWER_INDEX_ERR:
		return "INDEX_ERR";
	case LTTNG_VIEWER_INDEX_INACTIVE:
		return "INDEX_INACTIVE";
	case LTTNG_VIEWER_INDEX_EOF:
		return "INDEX_EOF";
	default:
		abort();
	}
}

static
const char *lttng_viewer_attach_return_code_str(
		enum lttng_viewer_attach_return_code code)
{
	switch (code) {
	case LTTNG_VIEWER_ATTACH_OK:
		return "ATTACH_OK";
	case LTTNG_VIEWER_ATTACH_ALREADY:
		return "ATTACH_ALREADY";
	case LTTNG_VIEWER_ATTACH_UNK:
		return "ATTACH_UNK";
	case LTTNG_VIEWER_ATTACH_NOT_LIVE:
		return "ATTACH_NOT_LIVE";
	case LTTNG_VIEWER_ATTACH_SEEK_ERR:
		return "ATTACH_SEEK_ERR";
	case LTTNG_VIEWER_ATTACH_NO_SESSION:
		return "ATTACH_NO_SESSION";
	default:
		abort();
	}
};

static
const char *lttng_viewer_get_packet_return_code_str(
		enum lttng_viewer_get_packet_return_code code)
{
	switch (code) {
	case LTTNG_VIEWER_GET_PACKET_OK:
		return "GET_PACKET_OK";
	case LTTNG_VIEWER_GET_PACKET_RETRY:
		return "GET_PACKET_RETRY";
	case LTTNG_VIEWER_GET_PACKET_ERR:
		return "GET_PACKET_ERR";
	case LTTNG_VIEWER_GET_PACKET_EOF:
		return "GET_PACKET_EOF";
	default:
		abort();
	}
};

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
		uint64_t session_id, unsigned int ignore_sent_flag)
{
	ssize_t ret;
	struct lttng_ht_iter iter;
	struct relay_viewer_stream *vstream;

	rcu_read_lock();

	cds_lfht_for_each_entry(viewer_streams_ht->ht, &iter.iter, vstream,
			stream_n.node) {
		struct ctf_trace *ctf_trace;
		struct lttng_viewer_stream send_stream = {};

		health_code_update();

		if (!viewer_stream_get(vstream)) {
			continue;
		}

		pthread_mutex_lock(&vstream->stream->lock);
		/* Ignore if not the same session. */
		if (vstream->stream->trace->session->id != session_id ||
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
 * session must be locked to ensure that we see either none or all initial
 * streams for a session, but no intermediate state..
 *
 * Return 0 on success or else a negative value.
 */
static int make_viewer_streams(struct relay_session *relay_session,
		struct relay_viewer_session *viewer_session,
		enum lttng_viewer_seek seek_t,
		uint32_t *nb_total,
		uint32_t *nb_unsent,
		uint32_t *nb_created,
		bool *closed)
{
	int ret;
	struct lttng_ht_iter iter;
	struct ctf_trace *ctf_trace;
	struct relay_stream *relay_stream = NULL;

	LTTNG_ASSERT(relay_session);
	ASSERT_LOCKED(relay_session->lock);

	if (relay_session->connection_closed) {
		*closed = true;
	}

	/*
	 * Create viewer streams for relay streams that are ready to be
	 * used for a the given session id only.
	 */
	rcu_read_lock();
	cds_lfht_for_each_entry (relay_session->ctf_traces_ht->ht, &iter.iter,
			ctf_trace, node.node) {
		bool trace_has_metadata_stream = false;

		health_code_update();

		if (!ctf_trace_get(ctf_trace)) {
			continue;
		}

		/*
		 * Iterate over all the streams of the trace to see if we have a
		 * metadata stream.
		 */
		cds_list_for_each_entry_rcu(relay_stream,
				&ctf_trace->stream_list, stream_node)
		{
			bool is_metadata_stream;

			pthread_mutex_lock(&relay_stream->lock);
			is_metadata_stream = relay_stream->is_metadata;
			pthread_mutex_unlock(&relay_stream->lock);

			if (is_metadata_stream) {
				trace_has_metadata_stream = true;
				break;
			}
		}

		relay_stream = NULL;

		/*
		 * If there is no metadata stream in this trace at the moment
		 * and we never sent one to the viewer, skip the trace. We
		 * accept that the viewer will not see this trace at all.
		 */
		if (!trace_has_metadata_stream &&
				!ctf_trace->metadata_stream_sent_to_viewer) {
			ctf_trace_put(ctf_trace);
			continue;
		}

		cds_list_for_each_entry_rcu(relay_stream,
				&ctf_trace->stream_list, stream_node)
		{
			struct relay_viewer_stream *viewer_stream;

			if (!stream_get(relay_stream)) {
				continue;
			}

			pthread_mutex_lock(&relay_stream->lock);
			/*
			 * stream published is protected by the session lock.
			 */
			if (!relay_stream->published) {
				goto next;
			}
			viewer_stream = viewer_stream_get_by_id(
					relay_stream->stream_handle);
			if (!viewer_stream) {
				struct lttng_trace_chunk *viewer_stream_trace_chunk = NULL;

				/*
				 * Save that we sent the metadata stream to the
				 * viewer. So that we know what trace the viewer
				 * is aware of.
				 */
				if (relay_stream->is_metadata) {
					ctf_trace->metadata_stream_sent_to_viewer = true;
				}

				/*
				 * If a rotation is ongoing, use a copy of the
				 * relay stream's chunk to ensure the stream
				 * files exist.
				 *
				 * Otherwise, the viewer session's current trace
				 * chunk can be used safely.
				 */
				if ((relay_stream->ongoing_rotation.is_set ||
						session_has_ongoing_rotation(relay_session)) &&
						relay_stream->trace_chunk) {
					viewer_stream_trace_chunk = lttng_trace_chunk_copy(
							relay_stream->trace_chunk);
					if (!viewer_stream_trace_chunk) {
						ret = -1;
						ctf_trace_put(ctf_trace);
						goto error_unlock;
					}
				} else {
					/*
					 * Transition the viewer session into the newest trace chunk available.
					 */
					if (!lttng_trace_chunk_ids_equal(viewer_session->current_trace_chunk,
							relay_stream->trace_chunk)) {

						ret = viewer_session_set_trace_chunk_copy(
								viewer_session,
								relay_stream->trace_chunk);
						if (ret) {
							ret = -1;
							ctf_trace_put(ctf_trace);
							goto error_unlock;
						}
					}

					if (relay_stream->trace_chunk) {
						/*
						 * If the corresponding relay
						 * stream's trace chunk is set,
						 * the viewer stream will be
						 * created under it.
						 *
						 * Note that a relay stream can
						 * have a NULL output trace
						 * chunk (for instance, after a
						 * clear against a stopped
						 * session).
						 */
						const bool reference_acquired = lttng_trace_chunk_get(
								viewer_session->current_trace_chunk);

						LTTNG_ASSERT(reference_acquired);
						viewer_stream_trace_chunk =
								viewer_session->current_trace_chunk;
					}
				}

				viewer_stream = viewer_stream_create(
						relay_stream,
						viewer_stream_trace_chunk,
						seek_t);
				lttng_trace_chunk_put(viewer_stream_trace_chunk);
				viewer_stream_trace_chunk = NULL;
				if (!viewer_stream) {
					ret = -1;
					ctf_trace_put(ctf_trace);
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
				if (!viewer_stream_get(viewer_stream)) {
					ERR("Unable to get self-reference on viewer stream, logic error.");
					abort();
				}
			} else {
				if (!viewer_stream->sent_flag && nb_unsent) {
					/* Update number of unsent stream counter. */
					(*nb_unsent)++;
				}
			}
			/* Update number of total stream counter. */
			if (nb_total) {
				if (relay_stream->is_metadata) {
					if (!relay_stream->closed ||
							relay_stream->metadata_received >
									viewer_stream->metadata_sent) {
						(*nb_total)++;
					}
				} else {
					if (!relay_stream->closed ||
							!(((int64_t)(relay_stream->prev_data_seq -
									  relay_stream->last_net_seq_num)) >=
									0)) {
						(*nb_total)++;
					}
				}
			}
			/* Put local reference. */
			viewer_stream_put(viewer_stream);
		next:
			pthread_mutex_unlock(&relay_stream->lock);
			stream_put(relay_stream);
		}
		relay_stream = NULL;
		ctf_trace_put(ctf_trace);
	}

	ret = 0;

error_unlock:
	rcu_read_unlock();

	if (relay_stream) {
		pthread_mutex_unlock(&relay_stream->lock);
		stream_put(relay_stream);
	}

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
int create_named_thread_poll_set(struct lttng_poll_event *events,
		int size, const char *name)
{
	int ret;

	if (events == NULL || size == 0) {
		ret = -1;
		goto error;
	}

	ret = fd_tracker_util_poll_create(the_fd_tracker,
		        name, events, 1, LTTNG_CLOEXEC);
	if (ret) {
		PERROR("Failed to create \"%s\" poll file descriptor", name);
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

static
int create_sock(void *data, int *out_fd)
{
	int ret;
	struct lttcomm_sock *sock = (lttcomm_sock *) data;

	ret = lttcomm_create_sock(sock);
	if (ret < 0) {
		goto end;
	}

	*out_fd = sock->fd;
end:
	return ret;
}

static
int close_sock(void *data, int *in_fd __attribute__((unused)))
{
	struct lttcomm_sock *sock = (lttcomm_sock *) data;

	return sock->ops->close(sock);
}

static int accept_sock(void *data, int *out_fd)
{
	int ret = 0;
	/* Socks is an array of in_sock, out_sock. */
	struct lttcomm_sock **socks = (lttcomm_sock **) data;
	struct lttcomm_sock *in_sock = socks[0];

	socks[1] = in_sock->ops->accept(in_sock);
	if (!socks[1]) {
		ret = -1;
		goto end;
	}
	*out_fd = socks[1]->fd;
end:
	return ret;
}

static
struct lttcomm_sock *accept_live_sock(struct lttcomm_sock *listening_sock,
		const char *name)
{
	int out_fd, ret;
	struct lttcomm_sock *socks[2] = { listening_sock, NULL };
	struct lttcomm_sock *new_sock = NULL;

	ret = fd_tracker_open_unsuspendable_fd(the_fd_tracker, &out_fd,
			(const char **) &name, 1, accept_sock, &socks);
	if (ret) {
		goto end;
	}
	new_sock = socks[1];
	DBG("%s accepted, socket %d", name, new_sock->fd);
end:
	return new_sock;
}

/*
 * Create and init socket from uri.
 */
static
struct lttcomm_sock *init_socket(struct lttng_uri *uri, const char *name)
{
	int ret, sock_fd;
	struct lttcomm_sock *sock = NULL;
	char uri_str[LTTNG_PATH_MAX];
	char *formated_name = NULL;

	sock = lttcomm_alloc_sock_from_uri(uri);
	if (sock == NULL) {
		ERR("Allocating socket");
		goto error;
	}

	/*
	 * Don't fail to create the socket if the name can't be built as it is
	 * only used for debugging purposes.
	 */
	ret = uri_to_str_url(uri, uri_str, sizeof(uri_str));
	uri_str[sizeof(uri_str) - 1] = '\0';
	if (ret >= 0) {
		ret = asprintf(&formated_name, "%s socket @ %s", name,
				uri_str);
		if (ret < 0) {
			formated_name = NULL;
		}
	}

	ret = fd_tracker_open_unsuspendable_fd(the_fd_tracker, &sock_fd,
			(const char **) (formated_name ? &formated_name : NULL),
			1, create_sock, sock);
	if (ret) {
		PERROR("Failed to create \"%s\" socket",
				formated_name ?: "Unknown");
		goto error;
	}
	DBG("Listening on %s socket %d", name, sock->fd);

	ret = sock->ops->bind(sock);
	if (ret < 0) {
		PERROR("Failed to bind lttng-live socket");
		goto error;
	}

	ret = sock->ops->listen(sock, -1);
	if (ret < 0) {
		goto error;

	}

	free(formated_name);
	return sock;

error:
	if (sock) {
		lttcomm_destroy_sock(sock);
	}
	free(formated_name);
	return NULL;
}

/*
 * This thread manages the listening for new connections on the network
 */
static
void *thread_listener(void *data __attribute__((unused)))
{
	int i, ret, pollfd, err = -1;
	uint32_t revents, nb_fd;
	struct lttng_poll_event events;
	struct lttcomm_sock *live_control_sock;

	DBG("[thread] Relay live listener started");

	rcu_register_thread();
	health_register(health_relayd, HEALTH_RELAYD_TYPE_LIVE_LISTENER);

	health_code_update();

	live_control_sock = init_socket(live_uri, "Live listener");
	if (!live_control_sock) {
		goto error_sock_control;
	}

	/* Pass 2 as size here for the thread quit pipe and control sockets. */
	ret = create_named_thread_poll_set(&events, 2,
			"Live listener thread epoll");
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

				newsock = accept_live_sock(live_control_sock,
						"Live socket to client");
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
				cds_wfcq_head_ptr_t head;
				head.h = &viewer_conn_queue.head;
				cds_wfcq_enqueue(head, &viewer_conn_queue.tail,
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
	(void) fd_tracker_util_poll_clean(the_fd_tracker, &events);
error_create_poll:
	if (live_control_sock->fd >= 0) {
		int sock_fd = live_control_sock->fd;

		ret = fd_tracker_close_unsuspendable_fd(the_fd_tracker,
				&sock_fd, 1, close_sock,
				live_control_sock);
		if (ret) {
			PERROR("close");
		}
		live_control_sock->fd = -1;
	}
	lttcomm_destroy_sock(live_control_sock);
error_sock_control:
	if (err) {
		health_error();
		DBG("Live viewer listener thread exited with error");
	}
	health_unregister(health_relayd);
	rcu_unregister_thread();
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
void *thread_dispatcher(void *data __attribute__((unused)))
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

	send_session_buf = (lttng_viewer_session *) zmalloc(SESSION_BUF_DEFAULT_COUNT * sizeof(*send_session_buf));
	if (!send_session_buf) {
		return -1;
	}

	rcu_read_lock();
	cds_lfht_for_each_entry(sessions_ht->ht, &iter.iter, session,
			session_n.node) {
		struct lttng_viewer_session *send_session;

		health_code_update();

		pthread_mutex_lock(&session->lock);
		if (session->connection_closed) {
			/* Skip closed session */
			goto next_session;
		}

		if (count >= buf_count) {
			struct lttng_viewer_session *newbuf;
			uint32_t new_buf_count = buf_count << 1;

			newbuf = (lttng_viewer_session *) realloc(send_session_buf,
				new_buf_count * sizeof(*send_session_buf));
			if (!newbuf) {
				ret = -1;
				goto break_loop;
			}
			send_session_buf = newbuf;
			buf_count = new_buf_count;
		}
		send_session = &send_session_buf[count];
		if (lttng_strncpy(send_session->session_name,
				session->session_name,
				sizeof(send_session->session_name))) {
			ret = -1;
			goto break_loop;
		}
		if (lttng_strncpy(send_session->hostname, session->hostname,
				sizeof(send_session->hostname))) {
			ret = -1;
			goto break_loop;
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
	next_session:
		pthread_mutex_unlock(&session->lock);
		continue;
	break_loop:
		pthread_mutex_unlock(&session->lock);
		break;
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
	struct relay_session *session = NULL;
	uint64_t session_id;
	bool closed = false;

	LTTNG_ASSERT(conn);

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
		response.status = htobe32(LTTNG_VIEWER_NEW_STREAMS_ERR);
		goto send_reply;
	}

	/*
	 * For any new stream, create it with LTTNG_VIEWER_SEEK_BEGINNING since
	 * that at this point the client is already attached to the session.Aany
	 * initial stream will have been created with the seek type at attach
	 * time (for now most readers use the LTTNG_VIEWER_SEEK_LAST on attach).
	 * Otherwise any event happening in a new stream between the attach and
	 * a call to viewer_get_new_streams will be "lost" (never received) from
	 * the viewer's point of view.
	 */
	pthread_mutex_lock(&session->lock);
	/*
	 * If a session rotation is ongoing, do not attempt to open any
	 * stream, because the chunk can be in an intermediate state
	 * due to directory renaming.
	 */
	if (session_has_ongoing_rotation(session)) {
		DBG("Relay session %" PRIu64 " rotation ongoing", session_id);
		response.status = htobe32(LTTNG_VIEWER_NEW_STREAMS_NO_NEW);
		goto send_reply_unlock;
	}
	ret = make_viewer_streams(session,
			conn->viewer_session,
			LTTNG_VIEWER_SEEK_BEGINNING, &nb_total, &nb_unsent,
			&nb_created, &closed);
	if (ret < 0) {
		/*
		 * This is caused by an internal error; propagate the negative
		 * 'ret' to close the connection.
		 */
		response.status = htobe32(LTTNG_VIEWER_NEW_STREAMS_ERR);
		goto send_reply;
	}
	send_streams = 1;
	response.status = htobe32(LTTNG_VIEWER_NEW_STREAMS_OK);

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
		goto send_reply_unlock;
	}
send_reply_unlock:
	pthread_mutex_unlock(&session->lock);

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
	ret = send_viewer_streams(conn->sock, session_id, 0);
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
	enum lttng_viewer_attach_return_code viewer_attach_status;
	bool closed = false;
	uint64_t session_id;

	LTTNG_ASSERT(conn);

	health_code_update();

	/* Receive the request from the connected client. */
	ret = recv_request(conn->sock, &request, sizeof(request));
	if (ret < 0) {
		goto error;
	}

	session_id = be64toh(request.session_id);

	health_code_update();

	memset(&response, 0, sizeof(response));

	if (!conn->viewer_session) {
		viewer_attach_status = LTTNG_VIEWER_ATTACH_NO_SESSION;
		DBG("Client trying to attach before creating a live viewer session, returning status=%s",
				lttng_viewer_attach_return_code_str(viewer_attach_status));
		goto send_reply;
	}

	session = session_get_by_id(session_id);
	if (!session) {
		viewer_attach_status = LTTNG_VIEWER_ATTACH_UNK;
		DBG("Relay session %" PRIu64 " not found, returning status=%s",
				session_id,
				lttng_viewer_attach_return_code_str(viewer_attach_status));
		goto send_reply;
	}
	DBG("Attach relay session ID %" PRIu64 " received", session_id);

	pthread_mutex_lock(&session->lock);
	if (session->live_timer == 0) {
		viewer_attach_status = LTTNG_VIEWER_ATTACH_NOT_LIVE;
		DBG("Relay session ID %" PRIu64 " is not a live session, returning status=%s",
				session_id,
				lttng_viewer_attach_return_code_str(viewer_attach_status));
		goto send_reply;
	}

	send_streams = 1;
	viewer_attach_status = viewer_session_attach(conn->viewer_session,
			session);
	if (viewer_attach_status != LTTNG_VIEWER_ATTACH_OK) {
		DBG("Error attaching to relay session %" PRIu64 ", returning status=%s",
				session_id,
				lttng_viewer_attach_return_code_str(viewer_attach_status));
		goto send_reply;
	}

	switch (be32toh(request.seek)) {
	case LTTNG_VIEWER_SEEK_BEGINNING:
	case LTTNG_VIEWER_SEEK_LAST:
		viewer_attach_status = LTTNG_VIEWER_ATTACH_OK;
		seek_type = (lttng_viewer_seek) be32toh(request.seek);
		break;
	default:
		ERR("Wrong seek parameter for relay session %" PRIu64
				", returning status=%s", session_id,
				lttng_viewer_attach_return_code_str(viewer_attach_status));
		viewer_attach_status = LTTNG_VIEWER_ATTACH_SEEK_ERR;
		send_streams = 0;
		goto send_reply;
	}

	/*
	 * If a session rotation is ongoing, do not attempt to open any
	 * stream, because the chunk can be in an intermediate state
	 * due to directory renaming.
	 */
	if (session_has_ongoing_rotation(session)) {
		DBG("Relay session %" PRIu64 " rotation ongoing", session_id);
		send_streams = 0;
		goto send_reply;
	}

	ret = make_viewer_streams(session,
			conn->viewer_session, seek_type,
			&nb_streams, NULL, NULL, &closed);
	if (ret < 0) {
		goto end_put_session;
	}
	pthread_mutex_unlock(&session->lock);
	session_put(session);
	session = NULL;

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
		viewer_attach_status = LTTNG_VIEWER_ATTACH_UNK;
		ERR("Session %" PRIu64 " is closed, returning status=%s",
				session_id,
				lttng_viewer_attach_return_code_str(viewer_attach_status));
		goto send_reply;
	}

send_reply:
	health_code_update();

	response.status = htobe32((uint32_t) viewer_attach_status);

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
	ret = send_viewer_streams(conn->sock, session_id, 1);
	if (ret < 0) {
		goto end_put_session;
	}

end_put_session:
	if (session) {
		pthread_mutex_unlock(&session->lock);
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
	const uint32_t connection_major = rstream->trace->session->major;
	const uint32_t connection_minor = rstream->trace->session->minor;
	enum lttng_trace_chunk_status chunk_status;

	if (vstream->index_file) {
		goto end;
	}

	/*
	 * First time, we open the index file and at least one index is ready.
	 */
	if (rstream->index_received_seqcount == 0 ||
			!vstream->stream_file.trace_chunk) {
		ret = -ENOENT;
		goto end;
	}

	chunk_status = lttng_index_file_create_from_trace_chunk_read_only(
			vstream->stream_file.trace_chunk, rstream->path_name,
			rstream->channel_name, rstream->tracefile_size,
			vstream->current_tracefile_id,
			lttng_to_index_major(connection_major, connection_minor),
			lttng_to_index_minor(connection_major, connection_minor),
			true, &vstream->index_file);
	if (chunk_status != LTTNG_TRACE_CHUNK_STATUS_OK) {
		if (chunk_status == LTTNG_TRACE_CHUNK_STATUS_NO_FILE) {
			ret = -ENOENT;
		} else {
			ret = -1;
		}
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

	DBG("Check index status: index_received_seqcount %" PRIu64 " "
				"index_sent_seqcount %" PRIu64 " "
				"for stream %" PRIu64,
				rstream->index_received_seqcount,
				vstream->index_sent_seqcount,
				vstream->stream->stream_handle);
	if ((trace->session->connection_closed || rstream->closed)
			&& rstream->index_received_seqcount
				== vstream->index_sent_seqcount) {
		/*
		 * Last index sent and session connection or relay
		 * stream are closed.
		 */
		index->status = LTTNG_VIEWER_INDEX_HUP;
		DBG("Check index status: Connection or stream are closed, stream %" PRIu64
			",connection-closed=%d, relay-stream-closed=%d, returning status=%s",
			vstream->stream->stream_handle,
			trace->session->connection_closed, rstream->closed,
			lttng_viewer_next_index_return_code_str(
				(enum lttng_viewer_next_index_return_code) index->status));
		goto hup;
	} else if (rstream->beacon_ts_end != -1ULL &&
			(rstream->index_received_seqcount == 0 ||
			(vstream->index_sent_seqcount != 0 &&
			rstream->index_received_seqcount
				<= vstream->index_sent_seqcount))) {
		/*
		 * We've received a synchronization beacon and the last index
		 * available has been sent, the index for now is inactive.
		 *
		 * In this case, we have received a beacon which allows us to
		 * inform the client of a time interval during which we can
		 * guarantee that there are no events to read (and never will
		 * be).
		 *
		 * The sent seqcount can grow higher than receive seqcount on
		 * clear because the rotation performed by clear will push
		 * the index_sent_seqcount ahead (see
		 * viewer_stream_sync_tracefile_array_tail) and skip over
		 * packet sequence numbers.
		 */
		index->status = LTTNG_VIEWER_INDEX_INACTIVE;
		index->timestamp_end = htobe64(rstream->beacon_ts_end);
		index->stream_id = htobe64(rstream->ctf_stream_id);
		DBG("Check index status: inactive with beacon, for stream %" PRIu64
			", returning status=%s",
			vstream->stream->stream_handle,
			lttng_viewer_next_index_return_code_str(
				(enum lttng_viewer_next_index_return_code) index->status));
		goto index_ready;
	} else if (rstream->index_received_seqcount == 0 ||
			(vstream->index_sent_seqcount != 0 &&
			rstream->index_received_seqcount
				<= vstream->index_sent_seqcount)) {
		/*
		 * This checks whether received <= sent seqcount. In
		 * this case, we have not received a beacon. Therefore,
		 * we can only ask the client to retry later.
		 *
		 * The sent seqcount can grow higher than receive seqcount on
		 * clear because the rotation performed by clear will push
		 * the index_sent_seqcount ahead (see
		 * viewer_stream_sync_tracefile_array_tail) and skip over
		 * packet sequence numbers.
		 */
		index->status = LTTNG_VIEWER_INDEX_RETRY;
		DBG("Check index status:"
			"did not received beacon for stream %" PRIu64
			", returning status=%s",
			vstream->stream->stream_handle,
			lttng_viewer_next_index_return_code_str(
				(enum lttng_viewer_next_index_return_code) index->status));
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
		if (ret == 1) {
			/* EOF across entire stream. */
			index->status = LTTNG_VIEWER_INDEX_HUP;
			DBG("Check index status:"
				"reached end of file for stream %" PRIu64
				", returning status=%s",
				vstream->stream->stream_handle,
				lttng_viewer_next_index_return_code_str(
					(enum lttng_viewer_next_index_return_code) index->status));
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
			index->status = LTTNG_VIEWER_INDEX_RETRY;
			DBG("Check index status:"
				"tracefile array sequence number %" PRIu64
				" not in file for stream %" PRIu64
				", returning status=%s",
				vstream->index_sent_seqcount,
				vstream->stream->stream_handle,
				lttng_viewer_next_index_return_code_str(
					(enum lttng_viewer_next_index_return_code) index->status));
			goto index_ready;
		}
		LTTNG_ASSERT(tracefile_array_seq_in_file(rstream->tfa,
				vstream->current_tracefile_id,
				vstream->index_sent_seqcount));
	}
	/* ret == 0 means successful so we continue. */
	ret = 0;
	return ret;

hup:
	viewer_stream_put(vstream);
index_ready:
	return 1;
}

static
void viewer_stream_rotate_to_trace_chunk(struct relay_viewer_stream *vstream,
		 struct lttng_trace_chunk *new_trace_chunk)
{
	lttng_trace_chunk_put(vstream->stream_file.trace_chunk);

	if (new_trace_chunk) {
		const bool acquired_reference = lttng_trace_chunk_get(
				new_trace_chunk);

		LTTNG_ASSERT(acquired_reference);
	}

	vstream->stream_file.trace_chunk = new_trace_chunk;
	viewer_stream_sync_tracefile_array_tail(vstream);
	viewer_stream_close_files(vstream);
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
	bool viewer_stream_and_session_in_same_chunk, viewer_stream_one_rotation_behind;
	uint64_t stream_file_chunk_id = -1ULL, viewer_session_chunk_id = -1ULL;
	enum lttng_trace_chunk_status status;

	LTTNG_ASSERT(conn);

	memset(&viewer_index, 0, sizeof(viewer_index));
	health_code_update();

	ret = recv_request(conn->sock, &request_index, sizeof(request_index));
	if (ret < 0) {
		goto end;
	}
	health_code_update();

	vstream = viewer_stream_get_by_id(be64toh(request_index.stream_id));
	if (!vstream) {
		viewer_index.status = LTTNG_VIEWER_INDEX_ERR;
		DBG("Client requested index of unknown stream id %" PRIu64", returning status=%s",
				(uint64_t) be64toh(request_index.stream_id),
				lttng_viewer_next_index_return_code_str(
					(enum lttng_viewer_next_index_return_code) viewer_index.status));
		goto send_reply;
	}

	/* Use back. ref. Protected by refcounts. */
	rstream = vstream->stream;
	ctf_trace = rstream->trace;

	/* metadata_viewer_stream may be NULL. */
	metadata_viewer_stream =
			ctf_trace_get_viewer_metadata_stream(ctf_trace);

	/*
	 * Hold the session lock to protect against concurrent changes
	 * to the chunk files (e.g. rename done by clear), which are
	 * protected by the session ongoing rotation state. Those are
	 * synchronized with the session lock.
	 */
	pthread_mutex_lock(&rstream->trace->session->lock);
	pthread_mutex_lock(&rstream->lock);

	/*
	 * The viewer should not ask for index on metadata stream.
	 */
	if (rstream->is_metadata) {
		viewer_index.status = LTTNG_VIEWER_INDEX_HUP;
		DBG("Client requested index of a metadata stream id %" PRIu64", returning status=%s",
				(uint64_t) be64toh(request_index.stream_id),
				lttng_viewer_next_index_return_code_str(
					(enum lttng_viewer_next_index_return_code) viewer_index.status));
		goto send_reply;
	}

	if (rstream->ongoing_rotation.is_set) {
		/* Rotation is ongoing, try again later. */
		viewer_index.status = LTTNG_VIEWER_INDEX_RETRY;
		DBG("Client requested index for stream id %" PRIu64" while a stream rotation is ongoing, returning status=%s",
				(uint64_t) be64toh(request_index.stream_id),
				lttng_viewer_next_index_return_code_str(
					(enum lttng_viewer_next_index_return_code) viewer_index.status));
		goto send_reply;
	}

	if (session_has_ongoing_rotation(rstream->trace->session)) {
		/* Rotation is ongoing, try again later. */
		viewer_index.status = LTTNG_VIEWER_INDEX_RETRY;
		DBG("Client requested index for stream id %" PRIu64" while a session rotation is ongoing, returning status=%s",
				(uint64_t) be64toh(request_index.stream_id),
				lttng_viewer_next_index_return_code_str(
					(enum lttng_viewer_next_index_return_code) viewer_index.status));
		goto send_reply;
	}

	/*
	 * Transition the viewer session into the newest trace chunk available.
	 */
	if (!lttng_trace_chunk_ids_equal(
			conn->viewer_session->current_trace_chunk,
			rstream->trace_chunk)) {
		DBG("Relay stream and viewer chunk ids differ");

		ret = viewer_session_set_trace_chunk_copy(
				conn->viewer_session,
				rstream->trace_chunk);
		if (ret) {
			viewer_index.status = LTTNG_VIEWER_INDEX_ERR;
			ERR("Error copying trace chunk for stream id %" PRIu64
				", returning status=%s",
				(uint64_t) be64toh(request_index.stream_id),
				lttng_viewer_next_index_return_code_str(
					(enum lttng_viewer_next_index_return_code) viewer_index.status));
			goto send_reply;
		}
	}

	/*
	 * Transition the viewer stream into the latest trace chunk available.
	 *
	 * Note that the stream must _not_ rotate in one precise condition:
	 * the relay stream has rotated to a NULL trace chunk and the viewer
	 * stream is consuming the trace chunk that was active just before
	 * that rotation to NULL.
	 *
	 * This allows clients to consume all the packets of a trace chunk
	 * after a session's destruction.
	 */
	if (vstream->stream_file.trace_chunk) {
		status = lttng_trace_chunk_get_id(
				vstream->stream_file.trace_chunk,
				&stream_file_chunk_id);
		LTTNG_ASSERT(status == LTTNG_TRACE_CHUNK_STATUS_OK);
	}
	if (conn->viewer_session->current_trace_chunk) {
		status = lttng_trace_chunk_get_id(
				conn->viewer_session->current_trace_chunk,
				&viewer_session_chunk_id);
		LTTNG_ASSERT(status == LTTNG_TRACE_CHUNK_STATUS_OK);
	}

	viewer_stream_and_session_in_same_chunk = lttng_trace_chunk_ids_equal(
			conn->viewer_session->current_trace_chunk,
			vstream->stream_file.trace_chunk);
	viewer_stream_one_rotation_behind = rstream->completed_rotation_count ==
			vstream->last_seen_rotation_count + 1;

	if (viewer_stream_and_session_in_same_chunk) {
		DBG("Transition to latest chunk check (%s -> %s): Same chunk, no need to rotate",
				vstream->stream_file.trace_chunk ?
						std::to_string(stream_file_chunk_id).c_str() :
						"None",
				conn->viewer_session->current_trace_chunk ?
						std::to_string(viewer_session_chunk_id).c_str() :
						"None");
	} else if (viewer_stream_one_rotation_behind && !rstream->trace_chunk) {
		DBG("Transition to latest chunk check (%s -> %s): One chunk behind relay stream which is being destroyed, no need to rotate",
				vstream->stream_file.trace_chunk ?
						std::to_string(stream_file_chunk_id).c_str() :
						"None",
				conn->viewer_session->current_trace_chunk ?
						std::to_string(viewer_session_chunk_id).c_str() :
						"None");
	} else {
		DBG("Transition to latest chunk check (%s -> %s): Viewer stream chunk ID and viewer session chunk ID differ, rotating viewer stream",
				vstream->stream_file.trace_chunk ?
						std::to_string(stream_file_chunk_id).c_str() :
						"None",
				conn->viewer_session->current_trace_chunk ?
						std::to_string(viewer_session_chunk_id).c_str() :
						"None");

		viewer_stream_rotate_to_trace_chunk(vstream,
				conn->viewer_session->current_trace_chunk);
		vstream->last_seen_rotation_count =
				rstream->completed_rotation_count;
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
	LTTNG_ASSERT(!ret);

	/* Try to open an index if one is needed for that stream. */
	ret = try_open_index(vstream, rstream);
	if (ret == -ENOENT) {
	       if (rstream->closed) {
			viewer_index.status = LTTNG_VIEWER_INDEX_HUP;
			DBG("Cannot open index for stream id %" PRIu64
				"stream is closed, returning status=%s",
				(uint64_t) be64toh(request_index.stream_id),
				lttng_viewer_next_index_return_code_str(
					(enum lttng_viewer_next_index_return_code) viewer_index.status));
			goto send_reply;
	       } else {
			viewer_index.status = LTTNG_VIEWER_INDEX_RETRY;
			DBG("Cannot open index for stream id %" PRIu64
				", returning status=%s",
				(uint64_t) be64toh(request_index.stream_id),
				lttng_viewer_next_index_return_code_str(
					(enum lttng_viewer_next_index_return_code) viewer_index.status));
			goto send_reply;
	       }
	}
	if (ret < 0) {
		viewer_index.status = LTTNG_VIEWER_INDEX_ERR;
		ERR("Error opening index for stream id %" PRIu64
			", returning status=%s",
			(uint64_t) be64toh(request_index.stream_id),
			lttng_viewer_next_index_return_code_str(
				(enum lttng_viewer_next_index_return_code) viewer_index.status));
		goto send_reply;
	}

	/*
	 * vstream->stream_fd may be NULL if it has been closed by
	 * tracefile rotation, or if we are at the beginning of the
	 * stream. We open the data stream file here to protect against
	 * overwrite caused by tracefile rotation (in association with
	 * unlink performed before overwrite).
	 */
	if (!vstream->stream_file.handle) {
		char file_path[LTTNG_PATH_MAX];
		struct fs_handle *fs_handle;

		ret = utils_stream_file_path(rstream->path_name,
				rstream->channel_name, rstream->tracefile_size,
				vstream->current_tracefile_id, NULL, file_path,
				sizeof(file_path));
		if (ret < 0) {
			goto error_put;
		}

		/*
		 * It is possible the the file we are trying to open is
		 * missing if the stream has been closed (application exits with
		 * per-pid buffers) and a clear command has been performed.
		 */
		status = lttng_trace_chunk_open_fs_handle(
				vstream->stream_file.trace_chunk,
				file_path, O_RDONLY, 0, &fs_handle, true);
		if (status != LTTNG_TRACE_CHUNK_STATUS_OK) {
			if (status == LTTNG_TRACE_CHUNK_STATUS_NO_FILE &&
					rstream->closed) {
				viewer_index.status = LTTNG_VIEWER_INDEX_HUP;
				DBG("Cannot find trace chunk file and stream is closed for stream id %" PRIu64
					", returning status=%s",
					(uint64_t) be64toh(request_index.stream_id),
					lttng_viewer_next_index_return_code_str(
						(enum lttng_viewer_next_index_return_code) viewer_index.status));
				goto send_reply;
			}
			PERROR("Failed to open trace file for viewer stream");
			goto error_put;
		}
		vstream->stream_file.handle = fs_handle;
	}

	ret = check_new_streams(conn);
	if (ret < 0) {
		viewer_index.status = LTTNG_VIEWER_INDEX_ERR;
		ERR("Error checking for new streams before sending new index to stream id %" PRIu64
			", returning status=%s",
			(uint64_t) be64toh(request_index.stream_id),
			lttng_viewer_next_index_return_code_str(
				(enum lttng_viewer_next_index_return_code) viewer_index.status));
		goto send_reply;
	} else if (ret == 1) {
		viewer_index.flags |= LTTNG_VIEWER_FLAG_NEW_STREAM;
	}

	ret = lttng_index_file_read(vstream->index_file, &packet_index);
	if (ret) {
		viewer_index.status = LTTNG_VIEWER_INDEX_ERR;
		ERR("Relay error reading index file for stream id %" PRIu64
			", returning status=%s",
			(uint64_t) be64toh(request_index.stream_id),
			lttng_viewer_next_index_return_code_str(
				(enum lttng_viewer_next_index_return_code) viewer_index.status));
		goto send_reply;
	} else {
		viewer_index.status = LTTNG_VIEWER_INDEX_OK;
		DBG("Read index file for stream id %" PRIu64
			", returning status=%s",
			(uint64_t) be64toh(request_index.stream_id),
			lttng_viewer_next_index_return_code_str(
				(enum lttng_viewer_next_index_return_code) viewer_index.status));
		vstream->index_sent_seqcount++;
	}

	/*
	 * Indexes are stored in big endian, no need to switch before sending.
	 */
	DBG("Sending viewer index for stream %" PRIu64 " offset %" PRIu64,
		rstream->stream_handle,
		(uint64_t) be64toh(packet_index.offset));
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
		pthread_mutex_unlock(&rstream->trace->session->lock);
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
	viewer_index.status = htobe32(viewer_index.status);
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
	pthread_mutex_unlock(&rstream->trace->session->lock);
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
	off_t lseek_ret;
	char *reply = NULL;
	struct lttng_viewer_get_packet get_packet_info;
	struct lttng_viewer_trace_packet reply_header;
	struct relay_viewer_stream *vstream = NULL;
	uint32_t reply_size = sizeof(reply_header);
	uint32_t packet_data_len = 0;
	ssize_t read_len;
	uint64_t stream_id;
	enum lttng_viewer_get_packet_return_code get_packet_status;

	health_code_update();

	ret = recv_request(conn->sock, &get_packet_info,
			sizeof(get_packet_info));
	if (ret < 0) {
		goto end;
	}
	health_code_update();

	/* From this point on, the error label can be reached. */
	memset(&reply_header, 0, sizeof(reply_header));
	stream_id = (uint64_t) be64toh(get_packet_info.stream_id);

	vstream = viewer_stream_get_by_id(stream_id);
	if (!vstream) {
		get_packet_status = LTTNG_VIEWER_GET_PACKET_ERR;
		DBG("Client requested packet of unknown stream id %" PRIu64
			", returning status=%s", stream_id,
			lttng_viewer_get_packet_return_code_str(get_packet_status));
		goto send_reply_nolock;
	} else {
		packet_data_len = be32toh(get_packet_info.len);
		reply_size += packet_data_len;
	}

	reply = (char *) zmalloc(reply_size);
	if (!reply) {
		get_packet_status = LTTNG_VIEWER_GET_PACKET_ERR;
		PERROR("Falled to allocate reply, returning status=%s",
			lttng_viewer_get_packet_return_code_str(get_packet_status));
		goto error;
	}

	pthread_mutex_lock(&vstream->stream->lock);
	lseek_ret = fs_handle_seek(vstream->stream_file.handle,
			be64toh(get_packet_info.offset), SEEK_SET);
	if (lseek_ret < 0) {
		get_packet_status = LTTNG_VIEWER_GET_PACKET_ERR;
		PERROR("Failed to seek file system handle of viewer stream %" PRIu64
		       " to offset %" PRIu64", returning status=%s", stream_id,
			(uint64_t) be64toh(get_packet_info.offset),
			lttng_viewer_get_packet_return_code_str(get_packet_status));
		goto error;
	}
	read_len = fs_handle_read(vstream->stream_file.handle,
			reply + sizeof(reply_header), packet_data_len);
	if (read_len < packet_data_len) {
		get_packet_status = LTTNG_VIEWER_GET_PACKET_ERR;
		PERROR("Failed to read from file system handle of viewer stream id %" PRIu64
		       ", offset: %" PRIu64 ", returning status=%s", stream_id,
		       (uint64_t) be64toh(get_packet_info.offset),
			lttng_viewer_get_packet_return_code_str(get_packet_status));
		goto error;
	}

	get_packet_status = LTTNG_VIEWER_GET_PACKET_OK;
	reply_header.len = htobe32(packet_data_len);
	goto send_reply;

error:
	/* No payload to send on error. */
	reply_size = sizeof(reply_header);

send_reply:
	if (vstream) {
		pthread_mutex_unlock(&vstream->stream->lock);
	}
send_reply_nolock:

	health_code_update();

	reply_header.status = htobe32(get_packet_status);
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

	DBG("Sent %u bytes for stream %" PRIu64, reply_size, stream_id);

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
	int fd = -1;
	ssize_t read_len;
	uint64_t len = 0;
	char *data = NULL;
	struct lttng_viewer_get_metadata request;
	struct lttng_viewer_metadata_packet reply;
	struct relay_viewer_stream *vstream = NULL;

	LTTNG_ASSERT(conn);

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
				(uint64_t) be64toh(request.stream_id));
		reply.status = htobe32(LTTNG_VIEWER_METADATA_ERR);
		goto send_reply;
	}
	pthread_mutex_lock(&vstream->stream->lock);
	if (!vstream->stream->is_metadata) {
		ERR("Invalid metadata stream");
		goto error;
	}

	if (vstream->metadata_sent >= vstream->stream->metadata_received) {
		/*
		 * The live viewers expect to receive a NO_NEW_METADATA
		 * status before a stream disappears, otherwise they abort the
		 * entire live connection when receiving an error status.
		 *
		 * Clear feature resets the metadata_sent to 0 until the
		 * same metadata is received again.
		 */
		reply.status = htobe32(LTTNG_VIEWER_NO_NEW_METADATA);
		/*
		 * The live viewer considers a closed 0 byte metadata stream as
		 * an error.
		 */
		if (vstream->metadata_sent > 0) {
			if (vstream->stream->closed && vstream->stream->no_new_metadata_notified) {
				/*
				 * Release ownership for the viewer metadata
				 * stream. Note that this reference is the
				 * viewer's reference. The vstream still exists
				 * until the end of the function as
				 * viewer_stream_get_by_id() took a reference.
				 */
				viewer_stream_put(vstream);
			}

			vstream->stream->no_new_metadata_notified = true;
		}
		goto send_reply;
	}

	if (vstream->stream->trace_chunk &&
			!lttng_trace_chunk_ids_equal(
				conn->viewer_session->current_trace_chunk,
				vstream->stream->trace_chunk)) {
		/* A rotation has occurred on the relay stream. */
		DBG("Metadata relay stream and viewer chunk ids differ");

		ret = viewer_session_set_trace_chunk_copy(
				conn->viewer_session,
				vstream->stream->trace_chunk);
		if (ret) {
			reply.status = htobe32(LTTNG_VIEWER_METADATA_ERR);
			goto send_reply;
		}
	}

	if (conn->viewer_session->current_trace_chunk &&
			!lttng_trace_chunk_ids_equal(conn->viewer_session->current_trace_chunk,
					vstream->stream_file.trace_chunk)) {
		bool acquired_reference;

		DBG("Viewer session and viewer stream chunk differ: "
				"vsession chunk %p vstream chunk %p",
				conn->viewer_session->current_trace_chunk,
				vstream->stream_file.trace_chunk);
		lttng_trace_chunk_put(vstream->stream_file.trace_chunk);
		acquired_reference = lttng_trace_chunk_get(conn->viewer_session->current_trace_chunk);
		LTTNG_ASSERT(acquired_reference);
		vstream->stream_file.trace_chunk =
			conn->viewer_session->current_trace_chunk;
		viewer_stream_close_files(vstream);
	}

	len = vstream->stream->metadata_received - vstream->metadata_sent;

	if (!vstream->stream_file.trace_chunk) {
		reply.status = htobe32(LTTNG_VIEWER_NO_NEW_METADATA);
		len = 0;
		goto send_reply;
	} else if (vstream->stream_file.trace_chunk &&
			!vstream->stream_file.handle && len > 0) {
		/*
		 * Either this is the first time the metadata file is read, or a
		 * rotation of the corresponding relay stream has occurred.
		 */
		struct fs_handle *fs_handle;
		char file_path[LTTNG_PATH_MAX];
		enum lttng_trace_chunk_status status;
		struct relay_stream *rstream = vstream->stream;

		ret = utils_stream_file_path(rstream->path_name,
				rstream->channel_name, rstream->tracefile_size,
				vstream->current_tracefile_id, NULL, file_path,
				sizeof(file_path));
		if (ret < 0) {
			goto error;
		}

		/*
		 * It is possible the the metadata file we are trying to open is
		 * missing if the stream has been closed (application exits with
		 * per-pid buffers) and a clear command has been performed.
		 */
		status = lttng_trace_chunk_open_fs_handle(
				vstream->stream_file.trace_chunk,
				file_path, O_RDONLY, 0, &fs_handle, true);
		if (status != LTTNG_TRACE_CHUNK_STATUS_OK) {
			if (status == LTTNG_TRACE_CHUNK_STATUS_NO_FILE) {
				reply.status = htobe32(LTTNG_VIEWER_NO_NEW_METADATA);
				len = 0;
				if (vstream->stream->closed) {
					viewer_stream_put(vstream);
				}
				goto send_reply;
			}
			PERROR("Failed to open metadata file for viewer stream");
			goto error;
		}
		vstream->stream_file.handle = fs_handle;

		if (vstream->metadata_sent != 0) {
			/*
			 * The client does not expect to receive any metadata
			 * it has received and metadata files in successive
			 * chunks must be a strict superset of one another.
			 *
			 * Skip the first `metadata_sent` bytes to ensure
			 * they are not sent a second time to the client.
			 *
			 * Baring a block layer error or an internal error,
			 * this seek should not fail as
			 * `vstream->stream->metadata_received` is reset when
			 * a relay stream is rotated. If this is reached, it is
			 * safe to assume that
			 * `metadata_received` > `metadata_sent`.
			 */
			const off_t seek_ret = fs_handle_seek(fs_handle,
					vstream->metadata_sent, SEEK_SET);

			if (seek_ret < 0) {
				PERROR("Failed to seek metadata viewer stream file to `sent` position: pos = %" PRId64,
						vstream->metadata_sent);
				reply.status = htobe32(LTTNG_VIEWER_METADATA_ERR);
				goto send_reply;
			}
		}
	}

	reply.len = htobe64(len);
	data = (char *) zmalloc(len);
	if (!data) {
		PERROR("viewer metadata zmalloc");
		goto error;
	}

	fd = fs_handle_get_fd(vstream->stream_file.handle);
	if (fd < 0) {
		ERR("Failed to restore viewer stream file system handle");
		goto error;
	}
	read_len = lttng_read(fd, data, len);
	fs_handle_put_fd(vstream->stream_file.handle);
	fd = -1;
	if (read_len < len) {
		if (read_len < 0) {
			PERROR("Failed to read metadata file");
			goto error;
		} else {
			/*
			 * A clear has been performed which prevents the relay
			 * from sending `len` bytes of metadata.
			 *
			 * It is important not to send any metadata if we
			 * couldn't read all the available metadata in one shot:
			 * sending partial metadata can cause the client to
			 * attempt to parse an incomplete (incoherent) metadata
			 * stream, which would result in an error.
			 */
			const off_t seek_ret = fs_handle_seek(
					vstream->stream_file.handle, -read_len,
					SEEK_CUR);

			DBG("Failed to read metadata: requested = %" PRIu64 ", got = %zd",
					len, read_len);
			read_len = 0;
			len = 0;
			if (seek_ret < 0) {
				PERROR("Failed to restore metadata file position after partial read");
				ret = -1;
				goto error;
			}
		}
	}
	vstream->metadata_sent += read_len;
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
			(uint64_t) be64toh(request.stream_id));

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

	LTTNG_ASSERT(conn);

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
				(uint64_t) be64toh(request.session_id));
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
	lttng_viewer_command cmd =
			(lttng_viewer_command) be32toh(recv_hdr->cmd);

	/*
	 * Make sure we've done the version check before any command other then
	 * a new client connection.
	 */
	if (cmd != LTTNG_VIEWER_CONNECT && !conn->version_check_done) {
		ERR("Viewer on connection %d requested %s command before version check",
			conn->sock->fd, lttng_viewer_command_str(cmd));
		ret = -1;
		goto end;
	}

	DBG("Processing %s viewer command from connection %d",
			lttng_viewer_command_str(cmd), conn->sock->fd);

	switch (cmd) {
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

	ret = fd_tracker_close_unsuspendable_fd(the_fd_tracker, &pollfd, 1,
			fd_tracker_util_close_fd, NULL);
	if (ret < 0) {
		ERR("Closing pollfd %d", pollfd);
	}
}

/*
 * This thread does the actual work
 */
static
void *thread_worker(void *data __attribute__((unused)))
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

	ret = create_named_thread_poll_set(&events, 2,
			"Live viewer worker thread epoll");
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
					ret = lttng_poll_add(&events,
							conn->sock->fd,
							LPOLLIN | LPOLLRDHUP);
					if (ret) {
						ERR("Failed to add new live connection file descriptor to poll set");
						goto error;
					}
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
	(void) fd_tracker_util_poll_clean(the_fd_tracker, &events);

	/* Cleanup remaining connection object. */
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
	(void) fd_tracker_util_pipe_close(the_fd_tracker, live_conn_pipe);
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
	return fd_tracker_util_pipe_open_cloexec(the_fd_tracker,
			"Live connection pipe", live_conn_pipe);
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
