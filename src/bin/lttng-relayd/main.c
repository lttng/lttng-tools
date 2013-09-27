/*
 * Copyright (C) 2012 - Julien Desfossez <jdesfossez@efficios.com>
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
#include "ctf-trace.h"
#include "index.h"
#include "utils.h"
#include "lttng-relayd.h"
#include "live.h"

/* command line options */
char *opt_output_path;
static int opt_daemon;
static struct lttng_uri *control_uri;
static struct lttng_uri *data_uri;
static struct lttng_uri *live_uri;

const char *progname;

/*
 * Quit pipe for all threads. This permits a single cancellation point
 * for all threads when receiving an event on the pipe.
 */
static int thread_quit_pipe[2] = { -1, -1 };

/*
 * This pipe is used to inform the worker thread that a command is queued and
 * ready to be processed.
 */
static int relay_cmd_pipe[2] = { -1, -1 };

/* Shared between threads */
static int dispatch_thread_exit;

static pthread_t listener_thread;
static pthread_t dispatcher_thread;
static pthread_t worker_thread;

static uint64_t last_relay_stream_id;
static uint64_t last_relay_session_id;

/*
 * Relay command queue.
 *
 * The relay_thread_listener and relay_thread_dispatcher communicate with this
 * queue.
 */
static struct relay_cmd_queue relay_cmd_queue;

/* buffer allocated at startup, used to store the trace data */
static char *data_buffer;
static unsigned int data_buffer_size;

/* We need those values for the file/dir creation. */
static uid_t relayd_uid;
static gid_t relayd_gid;

/* Global relay stream hash table. */
struct lttng_ht *relay_streams_ht;

/* Global relay viewer stream hash table. */
struct lttng_ht *viewer_streams_ht;

/* Global hash table that stores relay index object. */
struct lttng_ht *indexes_ht;

/*
 * usage function on stderr
 */
static
void usage(void)
{
	fprintf(stderr, "Usage: %s OPTIONS\n\nOptions:\n", progname);
	fprintf(stderr, "  -h, --help                Display this usage.\n");
	fprintf(stderr, "  -d, --daemonize           Start as a daemon.\n");
	fprintf(stderr, "  -C, --control-port URL    Control port listening.\n");
	fprintf(stderr, "  -D, --data-port URL       Data port listening.\n");
	fprintf(stderr, "  -o, --output PATH         Output path for traces. Must use an absolute path.\n");
	fprintf(stderr, "  -v, --verbose             Verbose mode. Activate DBG() macro.\n");
}

static
int parse_args(int argc, char **argv)
{
	int c;
	int ret = 0;
	char *default_address;

	static struct option long_options[] = {
		{ "control-port", 1, 0, 'C', },
		{ "data-port", 1, 0, 'D', },
		{ "daemonize", 0, 0, 'd', },
		{ "help", 0, 0, 'h', },
		{ "output", 1, 0, 'o', },
		{ "verbose", 0, 0, 'v', },
		{ NULL, 0, 0, 0, },
	};

	while (1) {
		int option_index = 0;
		c = getopt_long(argc, argv, "dhv" "C:D:o:",
				long_options, &option_index);
		if (c == -1) {
			break;
		}

		switch (c) {
		case 0:
			fprintf(stderr, "option %s", long_options[option_index].name);
			if (optarg) {
				fprintf(stderr, " with arg %s\n", optarg);
			}
			break;
		case 'C':
			ret = uri_parse(optarg, &control_uri);
			if (ret < 0) {
				ERR("Invalid control URI specified");
				goto exit;
			}
			if (control_uri->port == 0) {
				control_uri->port = DEFAULT_NETWORK_CONTROL_PORT;
			}
			break;
		case 'D':
			ret = uri_parse(optarg, &data_uri);
			if (ret < 0) {
				ERR("Invalid data URI specified");
				goto exit;
			}
			if (data_uri->port == 0) {
				data_uri->port = DEFAULT_NETWORK_DATA_PORT;
			}
			break;
		case 'd':
			opt_daemon = 1;
			break;
		case 'h':
			usage();
			exit(EXIT_FAILURE);
		case 'o':
			ret = asprintf(&opt_output_path, "%s", optarg);
			if (ret < 0) {
				PERROR("asprintf opt_output_path");
				goto exit;
			}
			break;
		case 'v':
			/* Verbose level can increase using multiple -v */
			lttng_opt_verbose += 1;
			break;
		default:
			/* Unknown option or other error.
			 * Error is printed by getopt, just return */
			ret = -1;
			goto exit;
		}
	}

	/* assign default values */
	if (control_uri == NULL) {
		ret = asprintf(&default_address, "tcp://0.0.0.0:%d",
				DEFAULT_NETWORK_CONTROL_PORT);
		if (ret < 0) {
			PERROR("asprintf default data address");
			goto exit;
		}

		ret = uri_parse(default_address, &control_uri);
		free(default_address);
		if (ret < 0) {
			ERR("Invalid control URI specified");
			goto exit;
		}
	}
	if (data_uri == NULL) {
		ret = asprintf(&default_address, "tcp://0.0.0.0:%d",
				DEFAULT_NETWORK_DATA_PORT);
		if (ret < 0) {
			PERROR("asprintf default data address");
			goto exit;
		}

		ret = uri_parse(default_address, &data_uri);
		free(default_address);
		if (ret < 0) {
			ERR("Invalid data URI specified");
			goto exit;
		}
	}
	if (live_uri == NULL) {
		ret = asprintf(&default_address, "tcp://0.0.0.0:%d",
				DEFAULT_NETWORK_VIEWER_PORT);
		if (ret < 0) {
			PERROR("asprintf default viewer control address");
			goto exit;
		}

		ret = uri_parse(default_address, &live_uri);
		free(default_address);
		if (ret < 0) {
			ERR("Invalid viewer control URI specified");
			goto exit;
		}
	}

exit:
	return ret;
}

/*
 * Cleanup the daemon
 */
static
void cleanup(void)
{
	DBG("Cleaning up");

	/* free the dynamically allocated opt_output_path */
	free(opt_output_path);

	/* Close thread quit pipes */
	utils_close_pipe(thread_quit_pipe);

	uri_free(control_uri);
	uri_free(data_uri);
}

/*
 * Write to writable pipe used to notify a thread.
 */
static
int notify_thread_pipe(int wpipe)
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
void stop_threads(void)
{
	int ret;

	/* Stopping all threads */
	DBG("Terminating all threads");
	ret = notify_thread_pipe(thread_quit_pipe[1]);
	if (ret < 0) {
		ERR("write error on thread quit pipe");
	}

	/* Dispatch thread */
	CMM_STORE_SHARED(dispatch_thread_exit, 1);
	futex_nto1_wake(&relay_cmd_queue.futex);
}

/*
 * Signal handler for the daemon
 *
 * Simply stop all worker threads, leaving main() return gracefully after
 * joining all threads and calling cleanup().
 */
static
void sighandler(int sig)
{
	switch (sig) {
	case SIGPIPE:
		DBG("SIGPIPE caught");
		return;
	case SIGINT:
		DBG("SIGINT caught");
		stop_threads();
		break;
	case SIGTERM:
		DBG("SIGTERM caught");
		stop_threads();
		break;
	default:
		break;
	}
}

/*
 * Setup signal handler for :
 *		SIGINT, SIGTERM, SIGPIPE
 */
static
int set_signal_handler(void)
{
	int ret = 0;
	struct sigaction sa;
	sigset_t sigset;

	if ((ret = sigemptyset(&sigset)) < 0) {
		PERROR("sigemptyset");
		return ret;
	}

	sa.sa_handler = sighandler;
	sa.sa_mask = sigset;
	sa.sa_flags = 0;
	if ((ret = sigaction(SIGTERM, &sa, NULL)) < 0) {
		PERROR("sigaction");
		return ret;
	}

	if ((ret = sigaction(SIGINT, &sa, NULL)) < 0) {
		PERROR("sigaction");
		return ret;
	}

	if ((ret = sigaction(SIGPIPE, &sa, NULL)) < 0) {
		PERROR("sigaction");
		return ret;
	}

	DBG("Signal handler set for SIGTERM, SIGPIPE and SIGINT");

	return ret;
}

/*
 * Init thread quit pipe.
 *
 * Return -1 on error or 0 if all pipes are created.
 */
static
int init_thread_quit_pipe(void)
{
	int ret;

	ret = utils_create_pipe_cloexec(thread_quit_pipe);

	return ret;
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
	ret = lttng_poll_add(events, thread_quit_pipe[0], LPOLLIN);
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
struct lttcomm_sock *relay_init_sock(struct lttng_uri *uri)
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
	DBG("Listening on sock %d", sock->fd);

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
 * Return nonzero if stream needs to be closed.
 */
static
int close_stream_check(struct relay_stream *stream)
{

	if (stream->close_flag && stream->prev_seq == stream->last_net_seq_num) {
		/*
		 * We are about to close the stream so set the data pending flag to 1
		 * which will make the end data pending command skip the stream which
		 * is now closed and ready. Note that after proceeding to a file close,
		 * the written file is ready for reading.
		 */
		stream->data_pending_check_done = 1;
		return 1;
	}
	return 0;
}

/*
 * This thread manages the listening for new connections on the network
 */
static
void *relay_thread_listener(void *data)
{
	int i, ret, pollfd, err = -1;
	int val = 1;
	uint32_t revents, nb_fd;
	struct lttng_poll_event events;
	struct lttcomm_sock *control_sock, *data_sock;

	DBG("[thread] Relay listener started");

	control_sock = relay_init_sock(control_uri);
	if (!control_sock) {
		goto error_sock_control;
	}

	data_sock = relay_init_sock(data_uri);
	if (!data_sock) {
		goto error_sock_relay;
	}

	/*
	 * Pass 3 as size here for the thread quit pipe, control and data socket.
	 */
	ret = create_thread_poll_set(&events, 3);
	if (ret < 0) {
		goto error_create_poll;
	}

	/* Add the control socket */
	ret = lttng_poll_add(&events, control_sock->fd, LPOLLIN | LPOLLRDHUP);
	if (ret < 0) {
		goto error_poll_add;
	}

	/* Add the data socket */
	ret = lttng_poll_add(&events, data_sock->fd, LPOLLIN | LPOLLRDHUP);
	if (ret < 0) {
		goto error_poll_add;
	}

	while (1) {
		DBG("Listener accepting connections");

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

		DBG("Relay new connection received");
		for (i = 0; i < nb_fd; i++) {
			/* Fetch once the poll data */
			revents = LTTNG_POLL_GETEV(&events, i);
			pollfd = LTTNG_POLL_GETFD(&events, i);

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

				if (pollfd == data_sock->fd) {
					newsock = data_sock->ops->accept(data_sock);
					if (!newsock) {
						PERROR("accepting data sock");
						free(relay_cmd);
						goto error;
					}
					relay_cmd->type = RELAY_DATA;
					DBG("Relay data connection accepted, socket %d", newsock->fd);
				} else {
					assert(pollfd == control_sock->fd);
					newsock = control_sock->ops->accept(control_sock);
					if (!newsock) {
						PERROR("accepting control sock");
						free(relay_cmd);
						goto error;
					}
					relay_cmd->type = RELAY_CONTROL;
					DBG("Relay control connection accepted, socket %d", newsock->fd);
				}
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
				cds_wfq_enqueue(&relay_cmd_queue.queue, &relay_cmd->node);

				/*
				 * Wake the dispatch queue futex. Implicit memory
				 * barrier with the exchange in cds_wfq_enqueue.
				 */
				futex_nto1_wake(&relay_cmd_queue.futex);
			}
		}
	}

exit:
error:
error_poll_add:
	lttng_poll_clean(&events);
error_create_poll:
	if (data_sock->fd >= 0) {
		ret = data_sock->ops->close(data_sock);
		if (ret) {
			PERROR("close");
		}
	}
	lttcomm_destroy_sock(data_sock);
error_sock_relay:
	if (control_sock->fd >= 0) {
		ret = control_sock->ops->close(control_sock);
		if (ret) {
			PERROR("close");
		}
	}
	lttcomm_destroy_sock(control_sock);
error_sock_control:
	if (err) {
		DBG("Thread exited with error");
	}
	DBG("Relay listener thread cleanup complete");
	stop_threads();
	return NULL;
}

/*
 * This thread manages the dispatching of the requests to worker threads
 */
static
void *relay_thread_dispatcher(void *data)
{
	int ret;
	struct cds_wfq_node *node;
	struct relay_command *relay_cmd = NULL;

	DBG("[thread] Relay dispatcher started");

	while (!CMM_LOAD_SHARED(dispatch_thread_exit)) {
		/* Atomically prepare the queue futex */
		futex_nto1_prepare(&relay_cmd_queue.futex);

		do {
			/* Dequeue commands */
			node = cds_wfq_dequeue_blocking(&relay_cmd_queue.queue);
			if (node == NULL) {
				DBG("Woken up but nothing in the relay command queue");
				/* Continue thread execution */
				break;
			}

			relay_cmd = caa_container_of(node, struct relay_command, node);
			DBG("Dispatching request waiting on sock %d", relay_cmd->sock->fd);

			/*
			 * Inform worker thread of the new request. This
			 * call is blocking so we can be assured that the data will be read
			 * at some point in time or wait to the end of the world :)
			 */
			do {
				ret = write(relay_cmd_pipe[1], relay_cmd,
						sizeof(struct relay_command));
			} while (ret < 0 && errno == EINTR);
			free(relay_cmd);
			if (ret < 0 || ret != sizeof(struct relay_command)) {
				PERROR("write cmd pipe");
				goto error;
			}
		} while (node != NULL);

		/* Futex wait on queue. Blocking call on futex() */
		futex_nto1_wait(&relay_cmd_queue.futex);
	}

error:
	DBG("Dispatch thread dying");
	stop_threads();
	return NULL;
}

/*
 * Get stream from stream id.
 * Need to be called with RCU read-side lock held.
 */
struct relay_stream *relay_stream_find_by_id(uint64_t stream_id)
{
	struct lttng_ht_node_ulong *node;
	struct lttng_ht_iter iter;
	struct relay_stream *ret;

	lttng_ht_lookup(relay_streams_ht,
			(void *)((unsigned long) stream_id),
			&iter);
	node = lttng_ht_iter_get_node_ulong(&iter);
	if (node == NULL) {
		DBG("Relay stream %" PRIu64 " not found", stream_id);
		ret = NULL;
		goto end;
	}

	ret = caa_container_of(node, struct relay_stream, stream_n);

end:
	return ret;
}

static
void deferred_free_stream(struct rcu_head *head)
{
	struct relay_stream *stream =
		caa_container_of(head, struct relay_stream, rcu_node);

	ctf_trace_try_destroy(stream->ctf_trace);

	free(stream->path_name);
	free(stream->channel_name);
	free(stream);
}

static
void deferred_free_session(struct rcu_head *head)
{
	struct relay_session *session =
		caa_container_of(head, struct relay_session, rcu_node);
	free(session);
}

/*
 * Close a given stream. The stream is freed using a call RCU.
 *
 * RCU read side lock MUST be acquired. If NO close_stream_check() was called
 * BEFORE the stream lock MUST be acquired.
 */
static void destroy_stream(struct relay_stream *stream,
		struct lttng_ht *ctf_traces_ht)
{
	int delret;
	struct relay_viewer_stream *vstream;
	struct lttng_ht_iter iter;

	assert(stream);

	delret = close(stream->fd);
	if (delret < 0) {
		PERROR("close stream");
	}

	if (stream->index_fd >= 0) {
		delret = close(stream->index_fd);
		if (delret < 0) {
			PERROR("close stream index_fd");
		}
	}

	vstream = live_find_viewer_stream_by_id(stream->stream_handle);
	if (vstream) {
		/*
		 * Set the last good value into the viewer stream. This is done
		 * right before the stream gets deleted from the hash table. The
		 * lookup failure on the live thread side of a stream indicates
		 * that the viewer stream index received value should be used.
		 */
		vstream->total_index_received = stream->total_index_received;
	}

	/* Cleanup index of that stream. */
	relay_index_destroy_by_stream_id(stream->stream_handle);

	iter.iter.node = &stream->stream_n.node;
	delret = lttng_ht_del(relay_streams_ht, &iter);
	assert(!delret);
	iter.iter.node = &stream->ctf_trace_node.node;
	delret = lttng_ht_del(ctf_traces_ht, &iter);
	assert(!delret);
	call_rcu(&stream->rcu_node, deferred_free_stream);
	DBG("Closed tracefile %d from close stream", stream->fd);
}

/*
 * relay_delete_session: Free all memory associated with a session and
 * close all the FDs
 */
static
void relay_delete_session(struct relay_command *cmd,
		struct lttng_ht *sessions_ht)
{
	struct lttng_ht_iter iter;
	struct lttng_ht_node_ulong *node;
	struct relay_stream *stream;
	int ret;

	if (!cmd->session) {
		return;
	}

	DBG("Relay deleting session %" PRIu64, cmd->session->id);

	rcu_read_lock();
	cds_lfht_for_each_entry(relay_streams_ht->ht, &iter.iter, node, node) {
		node = lttng_ht_iter_get_node_ulong(&iter);
		if (!node) {
			continue;
		}
		stream = caa_container_of(node, struct relay_stream, stream_n);
		if (stream->session == cmd->session) {
			destroy_stream(stream, cmd->ctf_traces_ht);
		}
	}

	/* Make this session not visible anymore. */
	iter.iter.node = &cmd->session->session_n.node;
	ret = lttng_ht_del(sessions_ht, &iter);
	assert(!ret);
	call_rcu(&cmd->session->rcu_node, deferred_free_session);
	rcu_read_unlock();
}

/*
 * Copy index data from the control port to a given index object.
 */
static void copy_index_control_data(struct relay_index *index,
		struct lttcomm_relayd_index *data)
{
	assert(index);
	assert(data);

	/*
	 * The index on disk is encoded in big endian, so we don't need to convert
	 * the data received on the network. The data_offset value is NEVER
	 * modified here and is updated by the data thread.
	 */
	index->index_data.packet_size = data->packet_size;
	index->index_data.content_size = data->content_size;
	index->index_data.timestamp_begin = data->timestamp_begin;
	index->index_data.timestamp_end = data->timestamp_end;
	index->index_data.events_discarded = data->events_discarded;
	index->index_data.stream_id = data->stream_id;
}

/*
 * Handle the RELAYD_CREATE_SESSION command.
 *
 * On success, send back the session id or else return a negative value.
 */
static
int relay_create_session(struct lttcomm_relayd_hdr *recv_hdr,
		struct relay_command *cmd,
		struct lttng_ht *sessions_ht)
{
	int ret = 0, send_ret;
	struct relay_session *session;
	struct lttcomm_relayd_status_session reply;

	assert(recv_hdr);
	assert(cmd);

	memset(&reply, 0, sizeof(reply));

	session = zmalloc(sizeof(struct relay_session));
	if (session == NULL) {
		PERROR("relay session zmalloc");
		ret = -1;
		goto error;
	}

	session->id = ++last_relay_session_id;
	session->sock = cmd->sock;
	cmd->session = session;

	reply.session_id = htobe64(session->id);

	switch (cmd->minor) {
		case 4: /* LTTng sessiond 2.4 */
		default:
			ret = cmd_create_session_2_4(cmd, session);
			break;
	}

	lttng_ht_node_init_ulong(&session->session_n,
			(unsigned long) session->id);
	lttng_ht_add_unique_ulong(sessions_ht,
			&session->session_n);

	DBG("Created session %" PRIu64, session->id);

error:
	if (ret < 0) {
		reply.ret_code = htobe32(LTTNG_ERR_FATAL);
	} else {
		reply.ret_code = htobe32(LTTNG_OK);
	}

	send_ret = cmd->sock->ops->sendmsg(cmd->sock, &reply, sizeof(reply), 0);
	if (send_ret < 0) {
		ERR("Relayd sending session id");
		ret = send_ret;
	}

	return ret;
}

/*
 * relay_add_stream: allocate a new stream for a session
 */
static
int relay_add_stream(struct lttcomm_relayd_hdr *recv_hdr,
		struct relay_command *cmd, struct lttng_ht *sessions_ht)
{
	struct relay_session *session = cmd->session;
	struct relay_stream *stream = NULL;
	struct lttcomm_relayd_status_stream reply;
	int ret, send_ret;

	if (!session || cmd->version_check_done == 0) {
		ERR("Trying to add a stream before version check");
		ret = -1;
		goto end_no_session;
	}

	stream = zmalloc(sizeof(struct relay_stream));
	if (stream == NULL) {
		PERROR("relay stream zmalloc");
		ret = -1;
		goto end_no_session;
	}

	switch (cmd->minor) {
	case 1: /* LTTng sessiond 2.1 */
		ret = cmd_recv_stream_2_1(cmd, stream);
		break;
	case 2: /* LTTng sessiond 2.2 */
	default:
		ret = cmd_recv_stream_2_2(cmd, stream);
		break;
	}
	if (ret < 0) {
		goto err_free_stream;
	}

	rcu_read_lock();
	stream->stream_handle = ++last_relay_stream_id;
	stream->prev_seq = -1ULL;
	stream->session = session;
	stream->index_fd = -1;
	stream->read_index_fd = -1;
	stream->ctf_trace = NULL;
	pthread_mutex_init(&stream->lock, NULL);

	ret = utils_mkdir_recursive(stream->path_name, S_IRWXU | S_IRWXG);
	if (ret < 0) {
		ERR("relay creating output directory");
		goto end;
	}

	/*
	 * No need to use run_as API here because whatever we receives, the relayd
	 * uses its own credentials for the stream files.
	 */
	ret = utils_create_stream_file(stream->path_name, stream->channel_name,
			stream->tracefile_size, 0, relayd_uid, relayd_gid, NULL);
	if (ret < 0) {
		ERR("Create output file");
		goto end;
	}
	stream->fd = ret;
	if (stream->tracefile_size) {
		DBG("Tracefile %s/%s_0 created", stream->path_name, stream->channel_name);
	} else {
		DBG("Tracefile %s/%s created", stream->path_name, stream->channel_name);
	}

	if (!strncmp(stream->channel_name, DEFAULT_METADATA_NAME, NAME_MAX)) {
		stream->metadata_flag = 1;
		/*
		 * When we receive a new metadata stream, we create a new
		 * ctf_trace and we assign this ctf_trace to all streams with
		 * the same path.
		 *
		 * If later on we receive a new stream for the same ctf_trace,
		 * we copy the information from the first hit in the HT to the
		 * new stream.
		 */
		stream->ctf_trace = ctf_trace_create();
		if (!stream->ctf_trace) {
			ret = -1;
			goto end;
		}
		stream->ctf_trace->refcount++;
		stream->ctf_trace->metadata_stream = stream;
	}
	ctf_trace_assign(cmd->ctf_traces_ht, stream);

	lttng_ht_node_init_ulong(&stream->stream_n,
			(unsigned long) stream->stream_handle);
	lttng_ht_add_unique_ulong(relay_streams_ht,
			&stream->stream_n);

	lttng_ht_node_init_str(&stream->ctf_trace_node, stream->path_name);
	lttng_ht_add_str(cmd->ctf_traces_ht, &stream->ctf_trace_node);

	DBG("Relay new stream added %s with ID %" PRIu64, stream->channel_name,
			stream->stream_handle);

end:
	reply.handle = htobe64(stream->stream_handle);
	/* send the session id to the client or a negative return code on error */
	if (ret < 0) {
		reply.ret_code = htobe32(LTTNG_ERR_UNK);
		/* stream was not properly added to the ht, so free it */
		free(stream);
	} else {
		reply.ret_code = htobe32(LTTNG_OK);
	}

	send_ret = cmd->sock->ops->sendmsg(cmd->sock, &reply,
			sizeof(struct lttcomm_relayd_status_stream), 0);
	if (send_ret < 0) {
		ERR("Relay sending stream id");
		ret = send_ret;
	}
	rcu_read_unlock();

end_no_session:
	return ret;

err_free_stream:
	free(stream->path_name);
	free(stream->channel_name);
	free(stream);
	return ret;
}

/*
 * relay_close_stream: close a specific stream
 */
static
int relay_close_stream(struct lttcomm_relayd_hdr *recv_hdr,
		struct relay_command *cmd)
{
	int ret, send_ret;
	struct relay_session *session = cmd->session;
	struct lttcomm_relayd_close_stream stream_info;
	struct lttcomm_relayd_generic_reply reply;
	struct relay_stream *stream;

	DBG("Close stream received");

	if (!session || cmd->version_check_done == 0) {
		ERR("Trying to close a stream before version check");
		ret = -1;
		goto end_no_session;
	}

	ret = cmd->sock->ops->recvmsg(cmd->sock, &stream_info,
			sizeof(struct lttcomm_relayd_close_stream), 0);
	if (ret < sizeof(struct lttcomm_relayd_close_stream)) {
		if (ret == 0) {
			/* Orderly shutdown. Not necessary to print an error. */
			DBG("Socket %d did an orderly shutdown", cmd->sock->fd);
		} else {
			ERR("Relay didn't receive valid add_stream struct size : %d", ret);
		}
		ret = -1;
		goto end_no_session;
	}

	rcu_read_lock();
	stream = relay_stream_find_by_id(be64toh(stream_info.stream_id));
	if (!stream) {
		ret = -1;
		goto end_unlock;
	}

	stream->last_net_seq_num = be64toh(stream_info.last_net_seq_num);
	stream->close_flag = 1;

	if (close_stream_check(stream)) {
		destroy_stream(stream, cmd->ctf_traces_ht);
	}

end_unlock:
	rcu_read_unlock();

	if (ret < 0) {
		reply.ret_code = htobe32(LTTNG_ERR_UNK);
	} else {
		reply.ret_code = htobe32(LTTNG_OK);
	}
	send_ret = cmd->sock->ops->sendmsg(cmd->sock, &reply,
			sizeof(struct lttcomm_relayd_generic_reply), 0);
	if (send_ret < 0) {
		ERR("Relay sending stream id");
		ret = send_ret;
	}

end_no_session:
	return ret;
}

/*
 * relay_unknown_command: send -1 if received unknown command
 */
static
void relay_unknown_command(struct relay_command *cmd)
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
 * relay_start: send an acknowledgment to the client to tell if we are
 * ready to receive data. We are ready if a session is established.
 */
static
int relay_start(struct lttcomm_relayd_hdr *recv_hdr,
		struct relay_command *cmd)
{
	int ret = htobe32(LTTNG_OK);
	struct lttcomm_relayd_generic_reply reply;
	struct relay_session *session = cmd->session;

	if (!session) {
		DBG("Trying to start the streaming without a session established");
		ret = htobe32(LTTNG_ERR_UNK);
	}

	reply.ret_code = ret;
	ret = cmd->sock->ops->sendmsg(cmd->sock, &reply,
			sizeof(struct lttcomm_relayd_generic_reply), 0);
	if (ret < 0) {
		ERR("Relay sending start ack");
	}

	return ret;
}

/*
 * Append padding to the file pointed by the file descriptor fd.
 */
static int write_padding_to_file(int fd, uint32_t size)
{
	int ret = 0;
	char *zeros;

	if (size == 0) {
		goto end;
	}

	zeros = zmalloc(size);
	if (zeros == NULL) {
		PERROR("zmalloc zeros for padding");
		ret = -1;
		goto end;
	}

	do {
		ret = write(fd, zeros, size);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0 || ret != size) {
		PERROR("write padding to file");
	}

	free(zeros);

end:
	return ret;
}

/*
 * relay_recv_metadata: receive the metada for the session.
 */
static
int relay_recv_metadata(struct lttcomm_relayd_hdr *recv_hdr,
		struct relay_command *cmd)
{
	int ret = htobe32(LTTNG_OK);
	struct relay_session *session = cmd->session;
	struct lttcomm_relayd_metadata_payload *metadata_struct;
	struct relay_stream *metadata_stream;
	uint64_t data_size, payload_size;

	if (!session) {
		ERR("Metadata sent before version check");
		ret = -1;
		goto end;
	}

	data_size = payload_size = be64toh(recv_hdr->data_size);
	if (data_size < sizeof(struct lttcomm_relayd_metadata_payload)) {
		ERR("Incorrect data size");
		ret = -1;
		goto end;
	}
	payload_size -= sizeof(struct lttcomm_relayd_metadata_payload);

	if (data_buffer_size < data_size) {
		/* In case the realloc fails, we can free the memory */
		char *tmp_data_ptr;

		tmp_data_ptr = realloc(data_buffer, data_size);
		if (!tmp_data_ptr) {
			ERR("Allocating data buffer");
			free(data_buffer);
			ret = -1;
			goto end;
		}
		data_buffer = tmp_data_ptr;
		data_buffer_size = data_size;
	}
	memset(data_buffer, 0, data_size);
	DBG2("Relay receiving metadata, waiting for %" PRIu64 " bytes", data_size);
	ret = cmd->sock->ops->recvmsg(cmd->sock, data_buffer, data_size, 0);
	if (ret < 0 || ret != data_size) {
		if (ret == 0) {
			/* Orderly shutdown. Not necessary to print an error. */
			DBG("Socket %d did an orderly shutdown", cmd->sock->fd);
		} else {
			ERR("Relay didn't receive the whole metadata");
		}
		ret = -1;
		goto end;
	}
	metadata_struct = (struct lttcomm_relayd_metadata_payload *) data_buffer;

	rcu_read_lock();
	metadata_stream = relay_stream_find_by_id(
			be64toh(metadata_struct->stream_id));
	if (!metadata_stream) {
		ret = -1;
		goto end_unlock;
	}

	do {
		ret = write(metadata_stream->fd, metadata_struct->payload,
				payload_size);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0 || ret != payload_size) {
		ERR("Relay error writing metadata on file");
		ret = -1;
		goto end_unlock;
	}

	ret = write_padding_to_file(metadata_stream->fd,
			be32toh(metadata_struct->padding_size));
	if (ret < 0) {
		goto end_unlock;
	}
	metadata_stream->ctf_trace->metadata_received +=
		payload_size + be32toh(metadata_struct->padding_size);

	DBG2("Relay metadata written");

end_unlock:
	rcu_read_unlock();
end:
	return ret;
}

/*
 * relay_send_version: send relayd version number
 */
static
int relay_send_version(struct lttcomm_relayd_hdr *recv_hdr,
		struct relay_command *cmd, struct lttng_ht *sessions_ht)
{
	int ret;
	struct lttcomm_relayd_version reply, msg;

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

	reply.major = RELAYD_VERSION_COMM_MAJOR;
	reply.minor = RELAYD_VERSION_COMM_MINOR;

	/* Major versions must be the same */
	if (reply.major != be32toh(msg.major)) {
		DBG("Incompatible major versions (%u vs %u), deleting session",
				reply.major, be32toh(msg.major));
		relay_delete_session(cmd, sessions_ht);
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

	reply.major = htobe32(reply.major);
	reply.minor = htobe32(reply.minor);
	ret = cmd->sock->ops->sendmsg(cmd->sock, &reply,
			sizeof(struct lttcomm_relayd_version), 0);
	if (ret < 0) {
		ERR("Relay sending version");
	}

	DBG("Version check done using protocol %u.%u", cmd->major,
			cmd->minor);

end:
	return ret;
}

/*
 * Check for data pending for a given stream id from the session daemon.
 */
static
int relay_data_pending(struct lttcomm_relayd_hdr *recv_hdr,
		struct relay_command *cmd)
{
	struct relay_session *session = cmd->session;
	struct lttcomm_relayd_data_pending msg;
	struct lttcomm_relayd_generic_reply reply;
	struct relay_stream *stream;
	int ret;
	uint64_t last_net_seq_num, stream_id;

	DBG("Data pending command received");

	if (!session || cmd->version_check_done == 0) {
		ERR("Trying to check for data before version check");
		ret = -1;
		goto end_no_session;
	}

	ret = cmd->sock->ops->recvmsg(cmd->sock, &msg, sizeof(msg), 0);
	if (ret < sizeof(msg)) {
		if (ret == 0) {
			/* Orderly shutdown. Not necessary to print an error. */
			DBG("Socket %d did an orderly shutdown", cmd->sock->fd);
		} else {
			ERR("Relay didn't receive valid data_pending struct size : %d",
					ret);
		}
		ret = -1;
		goto end_no_session;
	}

	stream_id = be64toh(msg.stream_id);
	last_net_seq_num = be64toh(msg.last_net_seq_num);

	rcu_read_lock();
	stream = relay_stream_find_by_id(stream_id);
	if (stream == NULL) {
		ret = -1;
		goto end_unlock;
	}

	DBG("Data pending for stream id %" PRIu64 " prev_seq %" PRIu64
			" and last_seq %" PRIu64, stream_id, stream->prev_seq,
			last_net_seq_num);

	/* Avoid wrapping issue */
	if (((int64_t) (stream->prev_seq - last_net_seq_num)) >= 0) {
		/* Data has in fact been written and is NOT pending */
		ret = 0;
	} else {
		/* Data still being streamed thus pending */
		ret = 1;
	}

	/* Pending check is now done. */
	stream->data_pending_check_done = 1;

end_unlock:
	rcu_read_unlock();

	reply.ret_code = htobe32(ret);
	ret = cmd->sock->ops->sendmsg(cmd->sock, &reply, sizeof(reply), 0);
	if (ret < 0) {
		ERR("Relay data pending ret code failed");
	}

end_no_session:
	return ret;
}

/*
 * Wait for the control socket to reach a quiescent state.
 *
 * Note that for now, when receiving this command from the session daemon, this
 * means that every subsequent commands or data received on the control socket
 * has been handled. So, this is why we simply return OK here.
 */
static
int relay_quiescent_control(struct lttcomm_relayd_hdr *recv_hdr,
		struct relay_command *cmd)
{
	int ret;
	uint64_t stream_id;
	struct relay_stream *stream;
	struct lttng_ht_iter iter;
	struct lttcomm_relayd_quiescent_control msg;
	struct lttcomm_relayd_generic_reply reply;

	DBG("Checking quiescent state on control socket");

	if (!cmd->session || cmd->version_check_done == 0) {
		ERR("Trying to check for data before version check");
		ret = -1;
		goto end_no_session;
	}

	ret = cmd->sock->ops->recvmsg(cmd->sock, &msg, sizeof(msg), 0);
	if (ret < sizeof(msg)) {
		if (ret == 0) {
			/* Orderly shutdown. Not necessary to print an error. */
			DBG("Socket %d did an orderly shutdown", cmd->sock->fd);
		} else {
			ERR("Relay didn't receive valid begin data_pending struct size: %d",
					ret);
		}
		ret = -1;
		goto end_no_session;
	}

	stream_id = be64toh(msg.stream_id);

	rcu_read_lock();
	cds_lfht_for_each_entry(relay_streams_ht->ht, &iter.iter, stream,
			stream_n.node) {
		if (stream->stream_handle == stream_id) {
			stream->data_pending_check_done = 1;
			DBG("Relay quiescent control pending flag set to %" PRIu64,
					stream_id);
			break;
		}
	}
	rcu_read_unlock();

	reply.ret_code = htobe32(LTTNG_OK);
	ret = cmd->sock->ops->sendmsg(cmd->sock, &reply, sizeof(reply), 0);
	if (ret < 0) {
		ERR("Relay data quiescent control ret code failed");
	}

end_no_session:
	return ret;
}

/*
 * Initialize a data pending command. This means that a client is about to ask
 * for data pending for each stream he/she holds. Simply iterate over all
 * streams of a session and set the data_pending_check_done flag.
 *
 * This command returns to the client a LTTNG_OK code.
 */
static
int relay_begin_data_pending(struct lttcomm_relayd_hdr *recv_hdr,
		struct relay_command *cmd)
{
	int ret;
	struct lttng_ht_iter iter;
	struct lttcomm_relayd_begin_data_pending msg;
	struct lttcomm_relayd_generic_reply reply;
	struct relay_stream *stream;
	uint64_t session_id;

	assert(recv_hdr);
	assert(cmd);

	DBG("Init streams for data pending");

	if (!cmd->session || cmd->version_check_done == 0) {
		ERR("Trying to check for data before version check");
		ret = -1;
		goto end_no_session;
	}

	ret = cmd->sock->ops->recvmsg(cmd->sock, &msg, sizeof(msg), 0);
	if (ret < sizeof(msg)) {
		if (ret == 0) {
			/* Orderly shutdown. Not necessary to print an error. */
			DBG("Socket %d did an orderly shutdown", cmd->sock->fd);
		} else {
			ERR("Relay didn't receive valid begin data_pending struct size: %d",
					ret);
		}
		ret = -1;
		goto end_no_session;
	}

	session_id = be64toh(msg.session_id);

	/*
	 * Iterate over all streams to set the begin data pending flag. For now, the
	 * streams are indexed by stream handle so we have to iterate over all
	 * streams to find the one associated with the right session_id.
	 */
	rcu_read_lock();
	cds_lfht_for_each_entry(relay_streams_ht->ht, &iter.iter, stream,
			stream_n.node) {
		if (stream->session->id == session_id) {
			stream->data_pending_check_done = 0;
			DBG("Set begin data pending flag to stream %" PRIu64,
					stream->stream_handle);
		}
	}
	rcu_read_unlock();

	/* All good, send back reply. */
	reply.ret_code = htobe32(LTTNG_OK);

	ret = cmd->sock->ops->sendmsg(cmd->sock, &reply, sizeof(reply), 0);
	if (ret < 0) {
		ERR("Relay begin data pending send reply failed");
	}

end_no_session:
	return ret;
}

/*
 * End data pending command. This will check, for a given session id, if each
 * stream associated with it has its data_pending_check_done flag set. If not,
 * this means that the client lost track of the stream but the data is still
 * being streamed on our side. In this case, we inform the client that data is
 * inflight.
 *
 * Return to the client if there is data in flight or not with a ret_code.
 */
static
int relay_end_data_pending(struct lttcomm_relayd_hdr *recv_hdr,
		struct relay_command *cmd)
{
	int ret;
	struct lttng_ht_iter iter;
	struct lttcomm_relayd_end_data_pending msg;
	struct lttcomm_relayd_generic_reply reply;
	struct relay_stream *stream;
	uint64_t session_id;
	uint32_t is_data_inflight = 0;

	assert(recv_hdr);
	assert(cmd);

	DBG("End data pending command");

	if (!cmd->session || cmd->version_check_done == 0) {
		ERR("Trying to check for data before version check");
		ret = -1;
		goto end_no_session;
	}

	ret = cmd->sock->ops->recvmsg(cmd->sock, &msg, sizeof(msg), 0);
	if (ret < sizeof(msg)) {
		if (ret == 0) {
			/* Orderly shutdown. Not necessary to print an error. */
			DBG("Socket %d did an orderly shutdown", cmd->sock->fd);
		} else {
			ERR("Relay didn't receive valid end data_pending struct size: %d",
					ret);
		}
		ret = -1;
		goto end_no_session;
	}

	session_id = be64toh(msg.session_id);

	/* Iterate over all streams to see if the begin data pending flag is set. */
	rcu_read_lock();
	cds_lfht_for_each_entry(relay_streams_ht->ht, &iter.iter, stream,
			stream_n.node) {
		if (stream->session->id == session_id &&
				!stream->data_pending_check_done) {
			is_data_inflight = 1;
			DBG("Data is still in flight for stream %" PRIu64,
					stream->stream_handle);
			break;
		}
	}
	rcu_read_unlock();

	/* All good, send back reply. */
	reply.ret_code = htobe32(is_data_inflight);

	ret = cmd->sock->ops->sendmsg(cmd->sock, &reply, sizeof(reply), 0);
	if (ret < 0) {
		ERR("Relay end data pending send reply failed");
	}

end_no_session:
	return ret;
}

/*
 * Receive an index for a specific stream.
 *
 * Return 0 on success else a negative value.
 */
static
int relay_recv_index(struct lttcomm_relayd_hdr *recv_hdr,
		struct relay_command *cmd)
{
	int ret, send_ret, index_created = 0;
	struct relay_session *session = cmd->session;
	struct lttcomm_relayd_index index_info;
	struct relay_index *index, *wr_index = NULL;
	struct lttcomm_relayd_generic_reply reply;
	struct relay_stream *stream;
	uint64_t net_seq_num;

	assert(cmd);

	DBG("Relay receiving index");

	if (!session || cmd->version_check_done == 0) {
		ERR("Trying to close a stream before version check");
		ret = -1;
		goto end_no_session;
	}

	ret = cmd->sock->ops->recvmsg(cmd->sock, &index_info,
			sizeof(index_info), 0);
	if (ret < sizeof(index_info)) {
		if (ret == 0) {
			/* Orderly shutdown. Not necessary to print an error. */
			DBG("Socket %d did an orderly shutdown", cmd->sock->fd);
		} else {
			ERR("Relay didn't receive valid index struct size : %d", ret);
		}
		ret = -1;
		goto end_no_session;
	}

	net_seq_num = be64toh(index_info.net_seq_num);

	rcu_read_lock();
	stream = relay_stream_find_by_id(be64toh(index_info.relay_stream_id));
	if (!stream) {
		ret = -1;
		goto end_rcu_unlock;
	}

	/* Live beacon handling */
	if (index_info.packet_size == 0) {
		DBG("Received live beacon for stream %" PRIu64, stream->stream_handle);

		/*
		 * Only flag a stream inactive when it has already received data.
		 */
		if (stream->total_index_received > 0) {
			stream->beacon_ts_end = be64toh(index_info.timestamp_end);
		}
		ret = 0;
		goto end_rcu_unlock;
	} else {
		stream->beacon_ts_end = -1ULL;
	}

	index = relay_index_find(stream->stream_handle, net_seq_num);
	if (!index) {
		/* A successful creation will add the object to the HT. */
		index = relay_index_create(stream->stream_handle, net_seq_num);
		if (!index) {
			goto end_rcu_unlock;
		}
		index_created = 1;
	}

	copy_index_control_data(index, &index_info);

	if (index_created) {
		/*
		 * Try to add the relay index object to the hash table. If an object
		 * already exist, destroy back the index created, set the data in this
		 * object and write it on disk.
		 */
		relay_index_add(index, &wr_index);
		if (wr_index) {
			copy_index_control_data(wr_index, &index_info);
			free(index);
		}
	} else {
		/* The index already exists so write it on disk. */
		wr_index = index;
	}

	/* Do we have a writable ready index to write on disk. */
	if (wr_index) {
		/* Starting at 2.4, create the index file if none available. */
		if (cmd->minor >= 4 && stream->index_fd < 0) {
			ret = index_create_file(stream->path_name, stream->channel_name,
					relayd_uid, relayd_gid, stream->tracefile_size,
					stream->tracefile_count_current);
			if (ret < 0) {
				goto end_rcu_unlock;
			}
			stream->index_fd = ret;
		}

		ret = relay_index_write(wr_index->fd, wr_index);
		if (ret < 0) {
			goto end_rcu_unlock;
		}
		stream->total_index_received++;
	}

end_rcu_unlock:
	rcu_read_unlock();

	if (ret < 0) {
		reply.ret_code = htobe32(LTTNG_ERR_UNK);
	} else {
		reply.ret_code = htobe32(LTTNG_OK);
	}
	send_ret = cmd->sock->ops->sendmsg(cmd->sock, &reply, sizeof(reply), 0);
	if (send_ret < 0) {
		ERR("Relay sending close index id reply");
		ret = send_ret;
	}

end_no_session:
	return ret;
}

/*
 * Process the commands received on the control socket
 */
static
int relay_process_control(struct lttcomm_relayd_hdr *recv_hdr,
		struct relay_command *cmd, struct relay_local_data *ctx)
{
	int ret = 0;

	switch (be32toh(recv_hdr->cmd)) {
	case RELAYD_CREATE_SESSION:
		ret = relay_create_session(recv_hdr, cmd, ctx->sessions_ht);
		break;
	case RELAYD_ADD_STREAM:
		ret = relay_add_stream(recv_hdr, cmd, ctx->sessions_ht);
		break;
	case RELAYD_START_DATA:
		ret = relay_start(recv_hdr, cmd);
		break;
	case RELAYD_SEND_METADATA:
		ret = relay_recv_metadata(recv_hdr, cmd);
		break;
	case RELAYD_VERSION:
		ret = relay_send_version(recv_hdr, cmd, ctx->sessions_ht);
		break;
	case RELAYD_CLOSE_STREAM:
		ret = relay_close_stream(recv_hdr, cmd);
		break;
	case RELAYD_DATA_PENDING:
		ret = relay_data_pending(recv_hdr, cmd);
		break;
	case RELAYD_QUIESCENT_CONTROL:
		ret = relay_quiescent_control(recv_hdr, cmd);
		break;
	case RELAYD_BEGIN_DATA_PENDING:
		ret = relay_begin_data_pending(recv_hdr, cmd);
		break;
	case RELAYD_END_DATA_PENDING:
		ret = relay_end_data_pending(recv_hdr, cmd);
		break;
	case RELAYD_SEND_INDEX:
		ret = relay_recv_index(recv_hdr, cmd);
		break;
	case RELAYD_UPDATE_SYNC_INFO:
	default:
		ERR("Received unknown command (%u)", be32toh(recv_hdr->cmd));
		relay_unknown_command(cmd);
		ret = -1;
		goto end;
	}

end:
	return ret;
}

/*
 * relay_process_data: Process the data received on the data socket
 */
static
int relay_process_data(struct relay_command *cmd)
{
	int ret = 0, rotate_index = 0, index_created = 0;
	struct relay_stream *stream;
	struct relay_index *index, *wr_index = NULL;
	struct lttcomm_relayd_data_hdr data_hdr;
	uint64_t stream_id, data_offset;
	uint64_t net_seq_num;
	uint32_t data_size;

	ret = cmd->sock->ops->recvmsg(cmd->sock, &data_hdr,
			sizeof(struct lttcomm_relayd_data_hdr), 0);
	if (ret <= 0) {
		if (ret == 0) {
			/* Orderly shutdown. Not necessary to print an error. */
			DBG("Socket %d did an orderly shutdown", cmd->sock->fd);
		} else {
			ERR("Unable to receive data header on sock %d", cmd->sock->fd);
		}
		ret = -1;
		goto end;
	}

	stream_id = be64toh(data_hdr.stream_id);

	rcu_read_lock();
	stream = relay_stream_find_by_id(stream_id);
	if (!stream) {
		ret = -1;
		goto end_rcu_unlock;
	}

	data_size = be32toh(data_hdr.data_size);
	if (data_buffer_size < data_size) {
		char *tmp_data_ptr;

		tmp_data_ptr = realloc(data_buffer, data_size);
		if (!tmp_data_ptr) {
			ERR("Allocating data buffer");
			free(data_buffer);
			ret = -1;
			goto end_rcu_unlock;
		}
		data_buffer = tmp_data_ptr;
		data_buffer_size = data_size;
	}
	memset(data_buffer, 0, data_size);

	net_seq_num = be64toh(data_hdr.net_seq_num);

	DBG3("Receiving data of size %u for stream id %" PRIu64 " seqnum %" PRIu64,
		data_size, stream_id, net_seq_num);
	ret = cmd->sock->ops->recvmsg(cmd->sock, data_buffer, data_size, 0);
	if (ret <= 0) {
		if (ret == 0) {
			/* Orderly shutdown. Not necessary to print an error. */
			DBG("Socket %d did an orderly shutdown", cmd->sock->fd);
		}
		ret = -1;
		goto end_rcu_unlock;
	}

	/* Check if a rotation is needed. */
	if (stream->tracefile_size > 0 &&
			(stream->tracefile_size_current + data_size) >
			stream->tracefile_size) {
		ret = utils_rotate_stream_file(stream->path_name, stream->channel_name,
				stream->tracefile_size, stream->tracefile_count,
				relayd_uid, relayd_gid, stream->fd,
				&(stream->tracefile_count_current), &stream->fd);
		if (ret < 0) {
			ERR("Rotating stream output file");
			goto end_rcu_unlock;
		}
		/* Reset current size because we just perform a stream rotation. */
		stream->tracefile_size_current = 0;
		rotate_index = 1;
	}

	/* Get data offset because we are about to update the index. */
	data_offset = htobe64(stream->tracefile_size_current);

	/*
	 * Lookup for an existing index for that stream id/sequence number. If on
	 * exists, the control thread already received the data for it thus we need
	 * to write it on disk.
	 */
	index = relay_index_find(stream_id, net_seq_num);
	if (!index) {
		/* A successful creation will add the object to the HT. */
		index = relay_index_create(stream->stream_handle, net_seq_num);
		if (!index) {
			goto end_rcu_unlock;
		}
		index_created = 1;
	}

	if (rotate_index || stream->index_fd < 0) {
		index->to_close_fd = stream->index_fd;
		ret = index_create_file(stream->path_name, stream->channel_name,
				relayd_uid, relayd_gid, stream->tracefile_size,
				stream->tracefile_count_current);
		if (ret < 0) {
			/* This will close the stream's index fd if one. */
			relay_index_free_safe(index);
			goto end_rcu_unlock;
		}
		stream->index_fd = ret;
	}
	index->fd = stream->index_fd;
	index->index_data.offset = data_offset;

	if (index_created) {
		/*
		 * Try to add the relay index object to the hash table. If an object
		 * already exist, destroy back the index created and set the data.
		 */
		relay_index_add(index, &wr_index);
		if (wr_index) {
			/* Copy back data from the created index. */
			wr_index->fd = index->fd;
			wr_index->to_close_fd = index->to_close_fd;
			wr_index->index_data.offset = data_offset;
			free(index);
		}
	} else {
		/* The index already exists so write it on disk. */
		wr_index = index;
	}

	/* Do we have a writable ready index to write on disk. */
	if (wr_index) {
		/* Starting at 2.4, create the index file if none available. */
		if (cmd->minor >= 4 && stream->index_fd < 0) {
			ret = index_create_file(stream->path_name, stream->channel_name,
					relayd_uid, relayd_gid, stream->tracefile_size,
					stream->tracefile_count_current);
			if (ret < 0) {
				goto end_rcu_unlock;
			}
			stream->index_fd = ret;
		}

		ret = relay_index_write(wr_index->fd, wr_index);
		if (ret < 0) {
			goto end_rcu_unlock;
		}
		stream->total_index_received++;
	}

	do {
		ret = write(stream->fd, data_buffer, data_size);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0 || ret != data_size) {
		ERR("Relay error writing data to file");
		ret = -1;
		goto end_rcu_unlock;
	}

	DBG2("Relay wrote %d bytes to tracefile for stream id %" PRIu64,
			ret, stream->stream_handle);

	ret = write_padding_to_file(stream->fd, be32toh(data_hdr.padding_size));
	if (ret < 0) {
		goto end_rcu_unlock;
	}
	stream->tracefile_size_current += data_size + be32toh(data_hdr.padding_size);

	stream->prev_seq = net_seq_num;

	/* Check if we need to close the FD */
	if (close_stream_check(stream)) {
		destroy_stream(stream, cmd->ctf_traces_ht);
	}

end_rcu_unlock:
	rcu_read_unlock();
end:
	return ret;
}

static
void relay_cleanup_poll_connection(struct lttng_poll_event *events, int pollfd)
{
	int ret;

	lttng_poll_del(events, pollfd);

	ret = close(pollfd);
	if (ret < 0) {
		ERR("Closing pollfd %d", pollfd);
	}
}

static
int relay_add_connection(int fd, struct lttng_poll_event *events,
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

	relay_connection->ctf_traces_ht = lttng_ht_new(0, LTTNG_HT_TYPE_STRING);
	if (!relay_connection->ctf_traces_ht) {
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
void deferred_free_connection(struct rcu_head *head)
{
	struct relay_command *relay_connection =
		caa_container_of(head, struct relay_command, rcu_node);

	lttng_ht_destroy(relay_connection->ctf_traces_ht);
	lttcomm_destroy_sock(relay_connection->sock);
	free(relay_connection);
}

static
void relay_del_connection(struct lttng_ht *relay_connections_ht,
		struct lttng_ht_iter *iter, struct relay_command *relay_connection,
		struct lttng_ht *sessions_ht)
{
	int ret;

	ret = lttng_ht_del(relay_connections_ht, iter);
	assert(!ret);
	if (relay_connection->type == RELAY_CONTROL) {
		relay_delete_session(relay_connection, sessions_ht);
	}

	call_rcu(&relay_connection->rcu_node,
		deferred_free_connection);
}

/*
 * This thread does the actual work
 */
static
void *relay_thread_worker(void *data)
{
	int ret, err = -1, last_seen_data_fd = -1;
	uint32_t nb_fd;
	struct relay_command *relay_connection;
	struct lttng_poll_event events;
	struct lttng_ht *relay_connections_ht;
	struct lttng_ht_node_ulong *node;
	struct lttng_ht_iter iter;
	struct lttcomm_relayd_hdr recv_hdr;
	struct relay_local_data *relay_ctx = (struct relay_local_data *) data;
	struct lttng_ht *sessions_ht = relay_ctx->sessions_ht;

	DBG("[thread] Relay worker started");

	rcu_register_thread();

	/* table of connections indexed on socket */
	relay_connections_ht = lttng_ht_new(0, LTTNG_HT_TYPE_ULONG);
	if (!relay_connections_ht) {
		goto relay_connections_ht_error;
	}

	/* Tables of received indexes indexed by index handle and net_seq_num. */
	indexes_ht = lttng_ht_new(0, LTTNG_HT_TYPE_TWO_U64);
	if (!indexes_ht) {
		goto indexes_ht_error;
	}

	ret = create_thread_poll_set(&events, 2);
	if (ret < 0) {
		goto error_poll_create;
	}

	ret = lttng_poll_add(&events, relay_cmd_pipe[0], LPOLLIN | LPOLLRDHUP);
	if (ret < 0) {
		goto error;
	}

restart:
	while (1) {
		int idx = -1, i, seen_control = 0, last_notdel_data_fd = -1;

		/* Infinite blocking call, waiting for transmission */
		DBG3("Relayd worker thread polling...");
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
		 * starve it with high throughout put tracing data on the data
		 * connection.
		 */
		for (i = 0; i < nb_fd; i++) {
			/* Fetch once the poll data */
			uint32_t revents = LTTNG_POLL_GETEV(&events, i);
			int pollfd = LTTNG_POLL_GETFD(&events, i);

			/* Thread quit pipe has been closed. Killing thread. */
			ret = check_thread_quit_pipe(pollfd, revents);
			if (ret) {
				err = 0;
				goto exit;
			}

			/* Inspect the relay cmd pipe for new connection */
			if (pollfd == relay_cmd_pipe[0]) {
				if (revents & (LPOLLERR | LPOLLHUP | LPOLLRDHUP)) {
					ERR("Relay pipe error");
					goto error;
				} else if (revents & LPOLLIN) {
					DBG("Relay command received");
					ret = relay_add_connection(relay_cmd_pipe[0],
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
					DBG2("Relay sock %d not found", pollfd);
					rcu_read_unlock();
					goto error;
				}
				relay_connection = caa_container_of(node,
						struct relay_command, sock_n);

				if (revents & (LPOLLERR)) {
					ERR("POLL ERROR");
					relay_cleanup_poll_connection(&events, pollfd);
					relay_del_connection(relay_connections_ht,
							&iter, relay_connection, sessions_ht);
					if (last_seen_data_fd == pollfd) {
						last_seen_data_fd = last_notdel_data_fd;
					}
				} else if (revents & (LPOLLHUP | LPOLLRDHUP)) {
					DBG("Socket %d hung up", pollfd);
					relay_cleanup_poll_connection(&events, pollfd);
					relay_del_connection(relay_connections_ht,
							&iter, relay_connection, sessions_ht);
					if (last_seen_data_fd == pollfd) {
						last_seen_data_fd = last_notdel_data_fd;
					}
				} else if (revents & LPOLLIN) {
					/* control socket */
					if (relay_connection->type == RELAY_CONTROL) {
						ret = relay_connection->sock->ops->recvmsg(
								relay_connection->sock, &recv_hdr,
								sizeof(struct lttcomm_relayd_hdr), 0);
						/* connection closed */
						if (ret <= 0) {
							relay_cleanup_poll_connection(&events, pollfd);
							relay_del_connection(relay_connections_ht,
									&iter, relay_connection, sessions_ht);
							DBG("Control connection closed with %d", pollfd);
						} else {
							if (relay_connection->session) {
								DBG2("Relay worker receiving data for session : %" PRIu64,
										relay_connection->session->id);
							}
							ret = relay_process_control(&recv_hdr,
									relay_connection, relay_ctx);
							if (ret < 0) {
								/* Clear the session on error. */
								relay_cleanup_poll_connection(&events, pollfd);
								relay_del_connection(relay_connections_ht,
										&iter, relay_connection, sessions_ht);
								DBG("Connection closed with %d", pollfd);
							}
							seen_control = 1;
						}
					} else {
						/*
						 * Flag the last seen data fd not deleted. It will be
						 * used as the last seen fd if any fd gets deleted in
						 * this first loop.
						 */
						last_notdel_data_fd = pollfd;
					}
				}
				rcu_read_unlock();
			}
		}

		/*
		 * The last loop handled a control request, go back to poll to make
		 * sure we prioritise the control socket.
		 */
		if (seen_control) {
			continue;
		}

		if (last_seen_data_fd >= 0) {
			for (i = 0; i < nb_fd; i++) {
				int pollfd = LTTNG_POLL_GETFD(&events, i);
				if (last_seen_data_fd == pollfd) {
					idx = i;
					break;
				}
			}
		}

		/* Process data connection. */
		for (i = idx + 1; i < nb_fd; i++) {
			/* Fetch the poll data. */
			uint32_t revents = LTTNG_POLL_GETEV(&events, i);
			int pollfd = LTTNG_POLL_GETFD(&events, i);

			/* Skip the command pipe. It's handled in the first loop. */
			if (pollfd == relay_cmd_pipe[0]) {
				continue;
			}

			if (revents) {
				rcu_read_lock();
				lttng_ht_lookup(relay_connections_ht,
						(void *)((unsigned long) pollfd),
						&iter);
				node = lttng_ht_iter_get_node_ulong(&iter);
				if (node == NULL) {
					/* Skip it. Might be removed before. */
					rcu_read_unlock();
					continue;
				}
				relay_connection = caa_container_of(node,
						struct relay_command, sock_n);

				if (revents & LPOLLIN) {
					if (relay_connection->type != RELAY_DATA) {
						continue;
					}

					ret = relay_process_data(relay_connection);
					/* connection closed */
					if (ret < 0) {
						relay_cleanup_poll_connection(&events, pollfd);
						relay_del_connection(relay_connections_ht,
								&iter, relay_connection, sessions_ht);
						DBG("Data connection closed with %d", pollfd);
						/*
						 * Every goto restart call sets the last seen fd where
						 * here we don't really care since we gracefully
						 * continue the loop after the connection is deleted.
						 */
					} else {
						/* Keep last seen port. */
						last_seen_data_fd = pollfd;
						rcu_read_unlock();
						goto restart;
					}
				}
				rcu_read_unlock();
			}
		}
		last_seen_data_fd = -1;
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
			relay_del_connection(relay_connections_ht,
					&iter, relay_connection, sessions_ht);
		}
	}
error_poll_create:
	{
		struct relay_index *index;
		cds_lfht_for_each_entry(indexes_ht->ht, &iter.iter, index, index_n.node) {
			relay_index_delete(index);
		}
		lttng_ht_destroy(indexes_ht);
	}
	rcu_read_unlock();
indexes_ht_error:
	lttng_ht_destroy(relay_connections_ht);
relay_connections_ht_error:
	/* Close relay cmd pipes */
	utils_close_pipe(relay_cmd_pipe);
	if (err) {
		DBG("Thread exited with error");
	}
	DBG("Worker thread cleanup complete");
	free(data_buffer);
	stop_threads();
	rcu_unregister_thread();
	return NULL;
}

/*
 * Create the relay command pipe to wake thread_manage_apps.
 * Closed in cleanup().
 */
static int create_relay_cmd_pipe(void)
{
	int ret;

	ret = utils_create_pipe_cloexec(relay_cmd_pipe);

	return ret;
}

/*
 * main
 */
int main(int argc, char **argv)
{
	int ret = 0;
	void *status;
	struct relay_local_data *relay_ctx;

	/* Create thread quit pipe */
	if ((ret = init_thread_quit_pipe()) < 0) {
		goto error;
	}

	/* Parse arguments */
	progname = argv[0];
	if ((ret = parse_args(argc, argv)) < 0) {
		goto exit;
	}

	if ((ret = set_signal_handler()) < 0) {
		goto exit;
	}

	/* Try to create directory if -o, --output is specified. */
	if (opt_output_path) {
		if (*opt_output_path != '/') {
			ERR("Please specify an absolute path for -o, --output PATH");
			goto exit;
		}

		ret = utils_mkdir_recursive(opt_output_path, S_IRWXU | S_IRWXG);
		if (ret < 0) {
			ERR("Unable to create %s", opt_output_path);
			goto exit;
		}
	}

	/* Daemonize */
	if (opt_daemon) {
		ret = daemon(0, 0);
		if (ret < 0) {
			PERROR("daemon");
			goto exit;
		}
	}

	/* We need those values for the file/dir creation. */
	relayd_uid = getuid();
	relayd_gid = getgid();

	/* Check if daemon is UID = 0 */
	if (relayd_uid == 0) {
		if (control_uri->port < 1024 || data_uri->port < 1024) {
			ERR("Need to be root to use ports < 1024");
			ret = -1;
			goto exit;
		}
	}

	/* Setup the thread apps communication pipe. */
	if ((ret = create_relay_cmd_pipe()) < 0) {
		goto exit;
	}

	/* Init relay command queue. */
	cds_wfq_init(&relay_cmd_queue.queue);

	/* Set up max poll set size */
	lttng_poll_set_max_size();

	/* Initialize communication library */
	lttcomm_init();

	relay_ctx = zmalloc(sizeof(struct relay_local_data));
	if (!relay_ctx) {
		PERROR("relay_ctx");
		goto exit;
	}

	/* tables of sessions indexed by session ID */
	relay_ctx->sessions_ht = lttng_ht_new(0, LTTNG_HT_TYPE_ULONG);
	if (!relay_ctx->sessions_ht) {
		goto exit_relay_ctx_sessions;
	}

	/* tables of streams indexed by stream ID */
	relay_streams_ht = lttng_ht_new(0, LTTNG_HT_TYPE_ULONG);
	if (!relay_streams_ht) {
		goto exit_relay_ctx_streams;
	}

	/* tables of streams indexed by stream ID */
	viewer_streams_ht = lttng_ht_new(0, LTTNG_HT_TYPE_U64);
	if (!viewer_streams_ht) {
		goto exit_relay_ctx_viewer_streams;
	}

	/* Setup the dispatcher thread */
	ret = pthread_create(&dispatcher_thread, NULL,
			relay_thread_dispatcher, (void *) NULL);
	if (ret != 0) {
		PERROR("pthread_create dispatcher");
		goto exit_dispatcher;
	}

	/* Setup the worker thread */
	ret = pthread_create(&worker_thread, NULL,
			relay_thread_worker, (void *) relay_ctx);
	if (ret != 0) {
		PERROR("pthread_create worker");
		goto exit_worker;
	}

	/* Setup the listener thread */
	ret = pthread_create(&listener_thread, NULL,
			relay_thread_listener, (void *) NULL);
	if (ret != 0) {
		PERROR("pthread_create listener");
		goto exit_listener;
	}

	ret = live_start_threads(live_uri, relay_ctx);
	if (ret != 0) {
		ERR("Starting live viewer threads");
	}

exit_listener:
	ret = pthread_join(listener_thread, &status);
	if (ret != 0) {
		PERROR("pthread_join");
		goto error;	/* join error, exit without cleanup */
	}

exit_worker:
	ret = pthread_join(worker_thread, &status);
	if (ret != 0) {
		PERROR("pthread_join");
		goto error;	/* join error, exit without cleanup */
	}

exit_dispatcher:
	ret = pthread_join(dispatcher_thread, &status);
	if (ret != 0) {
		PERROR("pthread_join");
		goto error;	/* join error, exit without cleanup */
	}
	lttng_ht_destroy(viewer_streams_ht);

exit_relay_ctx_viewer_streams:
	lttng_ht_destroy(relay_streams_ht);

exit_relay_ctx_streams:
	lttng_ht_destroy(relay_ctx->sessions_ht);

exit_relay_ctx_sessions:
	free(relay_ctx);

exit:
	live_stop_threads();
	cleanup();
	if (!ret) {
		exit(EXIT_SUCCESS);
	}

error:
	exit(EXIT_FAILURE);
}
