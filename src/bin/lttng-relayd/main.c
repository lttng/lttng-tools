/*
 * Copyright (C) 2012 - Julien Desfossez <jdesfossez@efficios.com>
 *                      David Goulet <dgoulet@efficios.com>
 *               2013 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
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
#include <unistd.h>
#include <fcntl.h>

#include <lttng/lttng.h>
#include <common/common.h>
#include <common/compat/poll.h>
#include <common/compat/socket.h>
#include <common/compat/endian.h>
#include <common/compat/getenv.h>
#include <common/defaults.h>
#include <common/daemonize.h>
#include <common/futex.h>
#include <common/sessiond-comm/sessiond-comm.h>
#include <common/sessiond-comm/inet.h>
#include <common/sessiond-comm/relayd.h>
#include <common/uri.h>
#include <common/utils.h>
#include <common/config/session-config.h>
#include <urcu/rculist.h>

#include "cmd.h"
#include "ctf-trace.h"
#include "index.h"
#include "utils.h"
#include "lttng-relayd.h"
#include "live.h"
#include "health-relayd.h"
#include "testpoint.h"
#include "viewer-stream.h"
#include "session.h"
#include "stream.h"
#include "connection.h"
#include "tracefile-array.h"

static const char *help_msg =
#ifdef LTTNG_EMBED_HELP
#include <lttng-relayd.8.h>
#else
NULL
#endif
;

/* command line options */
char *opt_output_path;
static int opt_daemon, opt_background;

/*
 * We need to wait for listener and live listener threads, as well as
 * health check thread, before being ready to signal readiness.
 */
#define NR_LTTNG_RELAY_READY	3
static int lttng_relay_ready = NR_LTTNG_RELAY_READY;

/* Size of receive buffer. */
#define RECV_DATA_BUFFER_SIZE		65536

static int recv_child_signal;	/* Set to 1 when a SIGUSR1 signal is received. */
static pid_t child_ppid;	/* Internal parent PID use with daemonize. */

static struct lttng_uri *control_uri;
static struct lttng_uri *data_uri;
static struct lttng_uri *live_uri;

const char *progname;

const char *tracing_group_name = DEFAULT_TRACING_GROUP;
static int tracing_group_name_override;

const char * const config_section_name = "relayd";

/*
 * Quit pipe for all threads. This permits a single cancellation point
 * for all threads when receiving an event on the pipe.
 */
int thread_quit_pipe[2] = { -1, -1 };

/*
 * This pipe is used to inform the worker thread that a command is queued and
 * ready to be processed.
 */
static int relay_conn_pipe[2] = { -1, -1 };

/* Shared between threads */
static int dispatch_thread_exit;

static pthread_t listener_thread;
static pthread_t dispatcher_thread;
static pthread_t worker_thread;
static pthread_t health_thread;

/*
 * last_relay_stream_id_lock protects last_relay_stream_id increment
 * atomicity on 32-bit architectures.
 */
static pthread_mutex_t last_relay_stream_id_lock = PTHREAD_MUTEX_INITIALIZER;
static uint64_t last_relay_stream_id;

/*
 * Relay command queue.
 *
 * The relay_thread_listener and relay_thread_dispatcher communicate with this
 * queue.
 */
static struct relay_conn_queue relay_conn_queue;

/* buffer allocated at startup, used to store the trace data */
static char *data_buffer;
static unsigned int data_buffer_size;

/* Global relay stream hash table. */
struct lttng_ht *relay_streams_ht;

/* Global relay viewer stream hash table. */
struct lttng_ht *viewer_streams_ht;

/* Global relay sessions hash table. */
struct lttng_ht *sessions_ht;

/* Relayd health monitoring */
struct health_app *health_relayd;

static struct option long_options[] = {
	{ "control-port", 1, 0, 'C', },
	{ "data-port", 1, 0, 'D', },
	{ "live-port", 1, 0, 'L', },
	{ "daemonize", 0, 0, 'd', },
	{ "background", 0, 0, 'b', },
	{ "group", 1, 0, 'g', },
	{ "help", 0, 0, 'h', },
	{ "output", 1, 0, 'o', },
	{ "verbose", 0, 0, 'v', },
	{ "config", 1, 0, 'f' },
	{ "version", 0, 0, 'V' },
	{ NULL, 0, 0, 0, },
};

static const char *config_ignore_options[] = { "help", "config", "version" };

/*
 * Take an option from the getopt output and set it in the right variable to be
 * used later.
 *
 * Return 0 on success else a negative value.
 */
static int set_option(int opt, const char *arg, const char *optname)
{
	int ret;

	switch (opt) {
	case 0:
		fprintf(stderr, "option %s", optname);
		if (arg) {
			fprintf(stderr, " with arg %s\n", arg);
		}
		break;
	case 'C':
		if (lttng_is_setuid_setgid()) {
			WARN("Getting '%s' argument from setuid/setgid binary refused for security reasons.",
				"-C, --control-port");
		} else {
			ret = uri_parse(arg, &control_uri);
			if (ret < 0) {
				ERR("Invalid control URI specified");
				goto end;
			}
			if (control_uri->port == 0) {
				control_uri->port = DEFAULT_NETWORK_CONTROL_PORT;
			}
		}
		break;
	case 'D':
		if (lttng_is_setuid_setgid()) {
			WARN("Getting '%s' argument from setuid/setgid binary refused for security reasons.",
				"-D, -data-port");
		} else {
			ret = uri_parse(arg, &data_uri);
			if (ret < 0) {
				ERR("Invalid data URI specified");
				goto end;
			}
			if (data_uri->port == 0) {
				data_uri->port = DEFAULT_NETWORK_DATA_PORT;
			}
		}
		break;
	case 'L':
		if (lttng_is_setuid_setgid()) {
			WARN("Getting '%s' argument from setuid/setgid binary refused for security reasons.",
				"-L, -live-port");
		} else {
			ret = uri_parse(arg, &live_uri);
			if (ret < 0) {
				ERR("Invalid live URI specified");
				goto end;
			}
			if (live_uri->port == 0) {
				live_uri->port = DEFAULT_NETWORK_VIEWER_PORT;
			}
		}
		break;
	case 'd':
		opt_daemon = 1;
		break;
	case 'b':
		opt_background = 1;
		break;
	case 'g':
		if (lttng_is_setuid_setgid()) {
			WARN("Getting '%s' argument from setuid/setgid binary refused for security reasons.",
				"-g, --group");
		} else {
			tracing_group_name = strdup(arg);
			if (tracing_group_name == NULL) {
				ret = -errno;
				PERROR("strdup");
				goto end;
			}
			tracing_group_name_override = 1;
		}
		break;
	case 'h':
		ret = utils_show_help(8, "lttng-relayd", help_msg);
		if (ret) {
			ERR("Cannot show --help for `lttng-relayd`");
			perror("exec");
		}
		exit(EXIT_FAILURE);
	case 'V':
		fprintf(stdout, "%s\n", VERSION);
		exit(EXIT_SUCCESS);
	case 'o':
		if (lttng_is_setuid_setgid()) {
			WARN("Getting '%s' argument from setuid/setgid binary refused for security reasons.",
				"-o, --output");
		} else {
			ret = asprintf(&opt_output_path, "%s", arg);
			if (ret < 0) {
				ret = -errno;
				PERROR("asprintf opt_output_path");
				goto end;
			}
		}
		break;
	case 'v':
		/* Verbose level can increase using multiple -v */
		if (arg) {
			lttng_opt_verbose = config_parse_value(arg);
		} else {
			/* Only 3 level of verbosity (-vvv). */
			if (lttng_opt_verbose < 3) {
				lttng_opt_verbose += 1;
			}
		}
		break;
	default:
		/* Unknown option or other error.
		 * Error is printed by getopt, just return */
		ret = -1;
		goto end;
	}

	/* All good. */
	ret = 0;

end:
	return ret;
}

/*
 * config_entry_handler_cb used to handle options read from a config file.
 * See config_entry_handler_cb comment in common/config/session-config.h for the
 * return value conventions.
 */
static int config_entry_handler(const struct config_entry *entry, void *unused)
{
	int ret = 0, i;

	if (!entry || !entry->name || !entry->value) {
		ret = -EINVAL;
		goto end;
	}

	/* Check if the option is to be ignored */
	for (i = 0; i < sizeof(config_ignore_options) / sizeof(char *); i++) {
		if (!strcmp(entry->name, config_ignore_options[i])) {
			goto end;
		}
	}

	for (i = 0; i < (sizeof(long_options) / sizeof(struct option)) - 1; i++) {
		/* Ignore if entry name is not fully matched. */
		if (strcmp(entry->name, long_options[i].name)) {
			continue;
		}

		/*
		 * If the option takes no argument on the command line,
		 * we have to check if the value is "true". We support
		 * non-zero numeric values, true, on and yes.
		 */
		if (!long_options[i].has_arg) {
			ret = config_parse_value(entry->value);
			if (ret <= 0) {
				if (ret) {
					WARN("Invalid configuration value \"%s\" for option %s",
							entry->value, entry->name);
				}
				/* False, skip boolean config option. */
				goto end;
			}
		}

		ret = set_option(long_options[i].val, entry->value, entry->name);
		goto end;
	}

	WARN("Unrecognized option \"%s\" in daemon configuration file.",
			entry->name);

end:
	return ret;
}

static int set_options(int argc, char **argv)
{
	int c, ret = 0, option_index = 0, retval = 0;
	int orig_optopt = optopt, orig_optind = optind;
	char *default_address, *optstring;
	const char *config_path = NULL;

	optstring = utils_generate_optstring(long_options,
			sizeof(long_options) / sizeof(struct option));
	if (!optstring) {
		retval = -ENOMEM;
		goto exit;
	}

	/* Check for the --config option */

	while ((c = getopt_long(argc, argv, optstring, long_options,
					&option_index)) != -1) {
		if (c == '?') {
			retval = -EINVAL;
			goto exit;
		} else if (c != 'f') {
			continue;
		}

		if (lttng_is_setuid_setgid()) {
			WARN("Getting '%s' argument from setuid/setgid binary refused for security reasons.",
				"-f, --config");
		} else {
			config_path = utils_expand_path(optarg);
			if (!config_path) {
				ERR("Failed to resolve path: %s", optarg);
			}
		}
	}

	ret = config_get_section_entries(config_path, config_section_name,
			config_entry_handler, NULL);
	if (ret) {
		if (ret > 0) {
			ERR("Invalid configuration option at line %i", ret);
		}
		retval = -1;
		goto exit;
	}

	/* Reset getopt's global state */
	optopt = orig_optopt;
	optind = orig_optind;
	while (1) {
		c = getopt_long(argc, argv, optstring, long_options, &option_index);
		if (c == -1) {
			break;
		}

		ret = set_option(c, optarg, long_options[option_index].name);
		if (ret < 0) {
			retval = -1;
			goto exit;
		}
	}

	/* assign default values */
	if (control_uri == NULL) {
		ret = asprintf(&default_address,
			"tcp://" DEFAULT_NETWORK_CONTROL_BIND_ADDRESS ":%d",
			DEFAULT_NETWORK_CONTROL_PORT);
		if (ret < 0) {
			PERROR("asprintf default data address");
			retval = -1;
			goto exit;
		}

		ret = uri_parse(default_address, &control_uri);
		free(default_address);
		if (ret < 0) {
			ERR("Invalid control URI specified");
			retval = -1;
			goto exit;
		}
	}
	if (data_uri == NULL) {
		ret = asprintf(&default_address,
			"tcp://" DEFAULT_NETWORK_DATA_BIND_ADDRESS ":%d",
			DEFAULT_NETWORK_DATA_PORT);
		if (ret < 0) {
			PERROR("asprintf default data address");
			retval = -1;
			goto exit;
		}

		ret = uri_parse(default_address, &data_uri);
		free(default_address);
		if (ret < 0) {
			ERR("Invalid data URI specified");
			retval = -1;
			goto exit;
		}
	}
	if (live_uri == NULL) {
		ret = asprintf(&default_address,
			"tcp://" DEFAULT_NETWORK_VIEWER_BIND_ADDRESS ":%d",
			DEFAULT_NETWORK_VIEWER_PORT);
		if (ret < 0) {
			PERROR("asprintf default viewer control address");
			retval = -1;
			goto exit;
		}

		ret = uri_parse(default_address, &live_uri);
		free(default_address);
		if (ret < 0) {
			ERR("Invalid viewer control URI specified");
			retval = -1;
			goto exit;
		}
	}

exit:
	free(optstring);
	return retval;
}

static void print_global_objects(void)
{
	rcu_register_thread();

	print_viewer_streams();
	print_relay_streams();
	print_sessions();

	rcu_unregister_thread();
}

/*
 * Cleanup the daemon
 */
static void relayd_cleanup(void)
{
	print_global_objects();

	DBG("Cleaning up");

	if (viewer_streams_ht)
		lttng_ht_destroy(viewer_streams_ht);
	if (relay_streams_ht)
		lttng_ht_destroy(relay_streams_ht);
	if (sessions_ht)
		lttng_ht_destroy(sessions_ht);

	/* free the dynamically allocated opt_output_path */
	free(opt_output_path);

	/* Close thread quit pipes */
	utils_close_pipe(thread_quit_pipe);

	uri_free(control_uri);
	uri_free(data_uri);
	/* Live URI is freed in the live thread. */

	if (tracing_group_name_override) {
		free((void *) tracing_group_name);
	}
}

/*
 * Write to writable pipe used to notify a thread.
 */
static int notify_thread_pipe(int wpipe)
{
	ssize_t ret;

	ret = lttng_write(wpipe, "!", 1);
	if (ret < 1) {
		PERROR("write poll pipe");
		goto end;
	}
	ret = 0;
end:
	return ret;
}

static int notify_health_quit_pipe(int *pipe)
{
	ssize_t ret;

	ret = lttng_write(pipe[1], "4", 1);
	if (ret < 1) {
		PERROR("write relay health quit");
		goto end;
	}
	ret = 0;
end:
	return ret;
}

/*
 * Stop all relayd and relayd-live threads.
 */
int lttng_relay_stop_threads(void)
{
	int retval = 0;

	/* Stopping all threads */
	DBG("Terminating all threads");
	if (notify_thread_pipe(thread_quit_pipe[1])) {
		ERR("write error on thread quit pipe");
		retval = -1;
	}

	if (notify_health_quit_pipe(health_quit_pipe)) {
		ERR("write error on health quit pipe");
	}

	/* Dispatch thread */
	CMM_STORE_SHARED(dispatch_thread_exit, 1);
	futex_nto1_wake(&relay_conn_queue.futex);

	if (relayd_live_stop()) {
		ERR("Error stopping live threads");
		retval = -1;
	}
	return retval;
}

/*
 * Signal handler for the daemon
 *
 * Simply stop all worker threads, leaving main() return gracefully after
 * joining all threads and calling cleanup().
 */
static void sighandler(int sig)
{
	switch (sig) {
	case SIGINT:
		DBG("SIGINT caught");
		if (lttng_relay_stop_threads()) {
			ERR("Error stopping threads");
		}
		break;
	case SIGTERM:
		DBG("SIGTERM caught");
		if (lttng_relay_stop_threads()) {
			ERR("Error stopping threads");
		}
		break;
	case SIGUSR1:
		CMM_STORE_SHARED(recv_child_signal, 1);
		break;
	default:
		break;
	}
}

/*
 * Setup signal handler for :
 *		SIGINT, SIGTERM, SIGPIPE
 */
static int set_signal_handler(void)
{
	int ret = 0;
	struct sigaction sa;
	sigset_t sigset;

	if ((ret = sigemptyset(&sigset)) < 0) {
		PERROR("sigemptyset");
		return ret;
	}

	sa.sa_mask = sigset;
	sa.sa_flags = 0;

	sa.sa_handler = sighandler;
	if ((ret = sigaction(SIGTERM, &sa, NULL)) < 0) {
		PERROR("sigaction");
		return ret;
	}

	if ((ret = sigaction(SIGINT, &sa, NULL)) < 0) {
		PERROR("sigaction");
		return ret;
	}

	if ((ret = sigaction(SIGUSR1, &sa, NULL)) < 0) {
		PERROR("sigaction");
		return ret;
	}

	sa.sa_handler = SIG_IGN;
	if ((ret = sigaction(SIGPIPE, &sa, NULL)) < 0) {
		PERROR("sigaction");
		return ret;
	}

	DBG("Signal handler set for SIGTERM, SIGUSR1, SIGPIPE and SIGINT");

	return ret;
}

void lttng_relay_notify_ready(void)
{
	/* Notify the parent of the fork() process that we are ready. */
	if (opt_daemon || opt_background) {
		if (uatomic_sub_return(&lttng_relay_ready, 1) == 0) {
			kill(child_ppid, SIGUSR1);
		}
	}
}

/*
 * Init thread quit pipe.
 *
 * Return -1 on error or 0 if all pipes are created.
 */
static int init_thread_quit_pipe(void)
{
	int ret;

	ret = utils_create_pipe_cloexec(thread_quit_pipe);

	return ret;
}

/*
 * Create a poll set with O_CLOEXEC and add the thread quit pipe to the set.
 */
static int create_thread_poll_set(struct lttng_poll_event *events, int size)
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
static int check_thread_quit_pipe(int fd, uint32_t events)
{
	if (fd == thread_quit_pipe[0] && (events & LPOLLIN)) {
		return 1;
	}

	return 0;
}

/*
 * Create and init socket from uri.
 */
static struct lttcomm_sock *relay_socket_create(struct lttng_uri *uri)
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
 * This thread manages the listening for new connections on the network
 */
static void *relay_thread_listener(void *data)
{
	int i, ret, pollfd, err = -1;
	uint32_t revents, nb_fd;
	struct lttng_poll_event events;
	struct lttcomm_sock *control_sock, *data_sock;

	DBG("[thread] Relay listener started");

	health_register(health_relayd, HEALTH_RELAYD_TYPE_LISTENER);

	health_code_update();

	control_sock = relay_socket_create(control_uri);
	if (!control_sock) {
		goto error_sock_control;
	}

	data_sock = relay_socket_create(data_uri);
	if (!data_sock) {
		goto error_sock_relay;
	}

	/*
	 * Pass 3 as size here for the thread quit pipe, control and
	 * data socket.
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

	lttng_relay_notify_ready();

	if (testpoint(relayd_thread_listener)) {
		goto error_testpoint;
	}

	while (1) {
		health_code_update();

		DBG("Listener accepting connections");

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

		DBG("Relay new connection received");
		for (i = 0; i < nb_fd; i++) {
			health_code_update();

			/* Fetch once the poll data */
			revents = LTTNG_POLL_GETEV(&events, i);
			pollfd = LTTNG_POLL_GETFD(&events, i);

			if (!revents) {
				/*
				 * No activity for this FD (poll
				 * implementation).
				 */
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
				 * sessiond/consumerd connection is allocated in
				 * this thread, enqueued to a global queue and
				 * dequeued (and freed) in the worker thread.
				 */
				int val = 1;
				struct relay_connection *new_conn;
				struct lttcomm_sock *newsock;
				enum connection_type type;

				if (pollfd == data_sock->fd) {
					type = RELAY_DATA;
					newsock = data_sock->ops->accept(data_sock);
					DBG("Relay data connection accepted, socket %d",
							newsock->fd);
				} else {
					assert(pollfd == control_sock->fd);
					type = RELAY_CONTROL;
					newsock = control_sock->ops->accept(control_sock);
					DBG("Relay control connection accepted, socket %d",
							newsock->fd);
				}
				if (!newsock) {
					PERROR("accepting sock");
					goto error;
				}

				ret = setsockopt(newsock->fd, SOL_SOCKET, SO_REUSEADDR, &val,
						sizeof(val));
				if (ret < 0) {
					PERROR("setsockopt inet");
					lttcomm_destroy_sock(newsock);
					goto error;
				}
				new_conn = connection_create(newsock, type);
				if (!new_conn) {
					lttcomm_destroy_sock(newsock);
					goto error;
				}

				/* Enqueue request for the dispatcher thread. */
				cds_wfcq_enqueue(&relay_conn_queue.head, &relay_conn_queue.tail,
						 &new_conn->qnode);

				/*
				 * Wake the dispatch queue futex.
				 * Implicit memory barrier with the
				 * exchange in cds_wfcq_enqueue.
				 */
				futex_nto1_wake(&relay_conn_queue.futex);
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
		health_error();
		ERR("Health error occurred in %s", __func__);
	}
	health_unregister(health_relayd);
	DBG("Relay listener thread cleanup complete");
	lttng_relay_stop_threads();
	return NULL;
}

/*
 * This thread manages the dispatching of the requests to worker threads
 */
static void *relay_thread_dispatcher(void *data)
{
	int err = -1;
	ssize_t ret;
	struct cds_wfcq_node *node;
	struct relay_connection *new_conn = NULL;

	DBG("[thread] Relay dispatcher started");

	health_register(health_relayd, HEALTH_RELAYD_TYPE_DISPATCHER);

	if (testpoint(relayd_thread_dispatcher)) {
		goto error_testpoint;
	}

	health_code_update();

	for (;;) {
		health_code_update();

		/* Atomically prepare the queue futex */
		futex_nto1_prepare(&relay_conn_queue.futex);

		if (CMM_LOAD_SHARED(dispatch_thread_exit)) {
			break;
		}

		do {
			health_code_update();

			/* Dequeue commands */
			node = cds_wfcq_dequeue_blocking(&relay_conn_queue.head,
							 &relay_conn_queue.tail);
			if (node == NULL) {
				DBG("Woken up but nothing in the relay command queue");
				/* Continue thread execution */
				break;
			}
			new_conn = caa_container_of(node, struct relay_connection, qnode);

			DBG("Dispatching request waiting on sock %d", new_conn->sock->fd);

			/*
			 * Inform worker thread of the new request. This
			 * call is blocking so we can be assured that
			 * the data will be read at some point in time
			 * or wait to the end of the world :)
			 */
			ret = lttng_write(relay_conn_pipe[1], &new_conn, sizeof(new_conn));
			if (ret < 0) {
				PERROR("write connection pipe");
				connection_put(new_conn);
				goto error;
			}
		} while (node != NULL);

		/* Futex wait on queue. Blocking call on futex() */
		health_poll_entry();
		futex_nto1_wait(&relay_conn_queue.futex);
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
	DBG("Dispatch thread dying");
	lttng_relay_stop_threads();
	return NULL;
}

/*
 * Set index data from the control port to a given index object.
 */
static int set_index_control_data(struct relay_index *index,
		struct lttcomm_relayd_index *data,
		struct relay_connection *conn)
{
	struct ctf_packet_index index_data;

	/*
	 * The index on disk is encoded in big endian, so we don't need
	 * to convert the data received on the network. The data_offset
	 * value is NEVER modified here and is updated by the data
	 * thread.
	 */
	index_data.packet_size = data->packet_size;
	index_data.content_size = data->content_size;
	index_data.timestamp_begin = data->timestamp_begin;
	index_data.timestamp_end = data->timestamp_end;
	index_data.events_discarded = data->events_discarded;
	index_data.stream_id = data->stream_id;

	if (conn->minor >= 8) {
		index->index_data.stream_instance_id = data->stream_instance_id;
		index->index_data.packet_seq_num = data->packet_seq_num;
	}

	return relay_index_set_data(index, &index_data);
}

/*
 * Handle the RELAYD_CREATE_SESSION command.
 *
 * On success, send back the session id or else return a negative value.
 */
static int relay_create_session(struct lttcomm_relayd_hdr *recv_hdr,
		struct relay_connection *conn)
{
	int ret = 0, send_ret;
	struct relay_session *session;
	struct lttcomm_relayd_status_session reply;
	char session_name[LTTNG_NAME_MAX];
	char hostname[LTTNG_HOST_NAME_MAX];
	uint32_t live_timer = 0;
	bool snapshot = false;

	memset(session_name, 0, LTTNG_NAME_MAX);
	memset(hostname, 0, LTTNG_HOST_NAME_MAX);

	memset(&reply, 0, sizeof(reply));

	switch (conn->minor) {
	case 1:
	case 2:
	case 3:
		break;
	case 4: /* LTTng sessiond 2.4 */
	default:
		ret = cmd_create_session_2_4(conn, session_name,
			hostname, &live_timer, &snapshot);
	}
	if (ret < 0) {
		goto send_reply;
	}

	session = session_create(session_name, hostname, live_timer,
			snapshot, conn->major, conn->minor);
	if (!session) {
		ret = -1;
		goto send_reply;
	}
	assert(!conn->session);
	conn->session = session;
	DBG("Created session %" PRIu64, session->id);

	reply.session_id = htobe64(session->id);

send_reply:
	if (ret < 0) {
		reply.ret_code = htobe32(LTTNG_ERR_FATAL);
	} else {
		reply.ret_code = htobe32(LTTNG_OK);
	}

	send_ret = conn->sock->ops->sendmsg(conn->sock, &reply, sizeof(reply), 0);
	if (send_ret < 0) {
		ERR("Relayd sending session id");
		ret = send_ret;
	}

	return ret;
}

/*
 * When we have received all the streams and the metadata for a channel,
 * we make them visible to the viewer threads.
 */
static void publish_connection_local_streams(struct relay_connection *conn)
{
	struct relay_stream *stream;
	struct relay_session *session = conn->session;

	/*
	 * We publish all streams belonging to a session atomically wrt
	 * session lock.
	 */
	pthread_mutex_lock(&session->lock);
	rcu_read_lock();
	cds_list_for_each_entry_rcu(stream, &session->recv_list,
			recv_node) {
		stream_publish(stream);
	}
	rcu_read_unlock();

	/*
	 * Inform the viewer that there are new streams in the session.
	 */
	if (session->viewer_attached) {
		uatomic_set(&session->new_streams, 1);
	}
	pthread_mutex_unlock(&session->lock);
}

/*
 * relay_add_stream: allocate a new stream for a session
 */
static int relay_add_stream(struct lttcomm_relayd_hdr *recv_hdr,
		struct relay_connection *conn)
{
	int ret;
	ssize_t send_ret;
	struct relay_session *session = conn->session;
	struct relay_stream *stream = NULL;
	struct lttcomm_relayd_status_stream reply;
	struct ctf_trace *trace = NULL;
	uint64_t stream_handle = -1ULL;
	char *path_name = NULL, *channel_name = NULL;
	uint64_t tracefile_size = 0, tracefile_count = 0;

	if (!session || conn->version_check_done == 0) {
		ERR("Trying to add a stream before version check");
		ret = -1;
		goto end_no_session;
	}

	switch (session->minor) {
	case 1: /* LTTng sessiond 2.1. Allocates path_name and channel_name. */
		ret = cmd_recv_stream_2_1(conn, &path_name,
			&channel_name);
		break;
	case 2: /* LTTng sessiond 2.2. Allocates path_name and channel_name. */
	default:
		ret = cmd_recv_stream_2_2(conn, &path_name,
			&channel_name, &tracefile_size, &tracefile_count);
		break;
	}
	if (ret < 0) {
		goto send_reply;
	}

	trace = ctf_trace_get_by_path_or_create(session, path_name);
	if (!trace) {
		goto send_reply;
	}
	/* This stream here has one reference on the trace. */

	pthread_mutex_lock(&last_relay_stream_id_lock);
	stream_handle = ++last_relay_stream_id;
	pthread_mutex_unlock(&last_relay_stream_id_lock);

	/* We pass ownership of path_name and channel_name. */
	stream = stream_create(trace, stream_handle, path_name,
			channel_name, tracefile_size, tracefile_count);
	path_name = NULL;
	channel_name = NULL;

	/*
	 * Streams are the owners of their trace. Reference to trace is
	 * kept within stream_create().
	 */
	ctf_trace_put(trace);

send_reply:
	memset(&reply, 0, sizeof(reply));
	reply.handle = htobe64(stream_handle);
	if (!stream) {
		reply.ret_code = htobe32(LTTNG_ERR_UNK);
	} else {
		reply.ret_code = htobe32(LTTNG_OK);
	}

	send_ret = conn->sock->ops->sendmsg(conn->sock, &reply,
			sizeof(struct lttcomm_relayd_status_stream), 0);
	if (send_ret < 0) {
		ERR("Relay sending stream id");
		ret = (int) send_ret;
	}

end_no_session:
	free(path_name);
	free(channel_name);
	return ret;
}

/*
 * relay_close_stream: close a specific stream
 */
static int relay_close_stream(struct lttcomm_relayd_hdr *recv_hdr,
		struct relay_connection *conn)
{
	int ret, send_ret;
	struct relay_session *session = conn->session;
	struct lttcomm_relayd_close_stream stream_info;
	struct lttcomm_relayd_generic_reply reply;
	struct relay_stream *stream;

	DBG("Close stream received");

	if (!session || conn->version_check_done == 0) {
		ERR("Trying to close a stream before version check");
		ret = -1;
		goto end_no_session;
	}

	ret = conn->sock->ops->recvmsg(conn->sock, &stream_info,
			sizeof(struct lttcomm_relayd_close_stream), 0);
	if (ret < sizeof(struct lttcomm_relayd_close_stream)) {
		if (ret == 0) {
			/* Orderly shutdown. Not necessary to print an error. */
			DBG("Socket %d did an orderly shutdown", conn->sock->fd);
		} else {
			ERR("Relay didn't receive valid add_stream struct size : %d", ret);
		}
		ret = -1;
		goto end_no_session;
	}

	stream = stream_get_by_id(be64toh(stream_info.stream_id));
	if (!stream) {
		ret = -1;
		goto end;
	}

	/*
	 * Set last_net_seq_num before the close flag. Required by data
	 * pending check.
	 */
	pthread_mutex_lock(&stream->lock);
	stream->last_net_seq_num = be64toh(stream_info.last_net_seq_num);
	pthread_mutex_unlock(&stream->lock);

	/*
	 * This is one of the conditions which may trigger a stream close
	 * with the others being:
	 *     1) A close command is received for a stream
	 *     2) The control connection owning the stream is closed
	 *     3) We have received all of the stream's data _after_ a close
	 *        request.
	 */
	try_stream_close(stream);
	if (stream->is_metadata) {
		struct relay_viewer_stream *vstream;

		vstream = viewer_stream_get_by_id(stream->stream_handle);
		if (vstream) {
			if (vstream->metadata_sent == stream->metadata_received) {
				/*
				 * Since all the metadata has been sent to the
				 * viewer and that we have a request to close
				 * its stream, we can safely teardown the
				 * corresponding metadata viewer stream.
				 */
				viewer_stream_put(vstream);
			}
			/* Put local reference. */
			viewer_stream_put(vstream);
		}
	}
	stream_put(stream);

end:
	memset(&reply, 0, sizeof(reply));
	if (ret < 0) {
		reply.ret_code = htobe32(LTTNG_ERR_UNK);
	} else {
		reply.ret_code = htobe32(LTTNG_OK);
	}
	send_ret = conn->sock->ops->sendmsg(conn->sock, &reply,
			sizeof(struct lttcomm_relayd_generic_reply), 0);
	if (send_ret < 0) {
		ERR("Relay sending stream id");
		ret = send_ret;
	}

end_no_session:
	return ret;
}

/*
 * relay_reset_metadata: reset a metadata stream
 */
static
int relay_reset_metadata(struct lttcomm_relayd_hdr *recv_hdr,
		struct relay_connection *conn)
{
	int ret, send_ret;
	struct relay_session *session = conn->session;
	struct lttcomm_relayd_reset_metadata stream_info;
	struct lttcomm_relayd_generic_reply reply;
	struct relay_stream *stream;

	DBG("Reset metadata received");

	if (!session || conn->version_check_done == 0) {
		ERR("Trying to reset a metadata stream before version check");
		ret = -1;
		goto end_no_session;
	}

	ret = conn->sock->ops->recvmsg(conn->sock, &stream_info,
			sizeof(struct lttcomm_relayd_reset_metadata), 0);
	if (ret < sizeof(struct lttcomm_relayd_reset_metadata)) {
		if (ret == 0) {
			/* Orderly shutdown. Not necessary to print an error. */
			DBG("Socket %d did an orderly shutdown", conn->sock->fd);
		} else {
			ERR("Relay didn't receive valid reset_metadata struct "
					"size : %d", ret);
		}
		ret = -1;
		goto end_no_session;
	}
	DBG("Update metadata to version %" PRIu64, be64toh(stream_info.version));

	/* Unsupported for live sessions for now. */
	if (session->live_timer != 0) {
		ret = -1;
		goto end;
	}

	stream = stream_get_by_id(be64toh(stream_info.stream_id));
	if (!stream) {
		ret = -1;
		goto end;
	}
	pthread_mutex_lock(&stream->lock);
	if (!stream->is_metadata) {
		ret = -1;
		goto end_unlock;
	}

	ret = utils_rotate_stream_file(stream->path_name, stream->channel_name,
			0, 0, -1, -1, stream->stream_fd->fd, NULL,
			&stream->stream_fd->fd);
	if (ret < 0) {
		ERR("Failed to rotate metadata file %s of channel %s",
				stream->path_name, stream->channel_name);
		goto end_unlock;
	}

end_unlock:
	pthread_mutex_unlock(&stream->lock);
	stream_put(stream);

end:
	memset(&reply, 0, sizeof(reply));
	if (ret < 0) {
		reply.ret_code = htobe32(LTTNG_ERR_UNK);
	} else {
		reply.ret_code = htobe32(LTTNG_OK);
	}
	send_ret = conn->sock->ops->sendmsg(conn->sock, &reply,
			sizeof(struct lttcomm_relayd_generic_reply), 0);
	if (send_ret < 0) {
		ERR("Relay sending reset metadata reply");
		ret = send_ret;
	}

end_no_session:
	return ret;
}

/*
 * relay_unknown_command: send -1 if received unknown command
 */
static void relay_unknown_command(struct relay_connection *conn)
{
	struct lttcomm_relayd_generic_reply reply;
	int ret;

	memset(&reply, 0, sizeof(reply));
	reply.ret_code = htobe32(LTTNG_ERR_UNK);
	ret = conn->sock->ops->sendmsg(conn->sock, &reply,
			sizeof(struct lttcomm_relayd_generic_reply), 0);
	if (ret < 0) {
		ERR("Relay sending unknown command");
	}
}

/*
 * relay_start: send an acknowledgment to the client to tell if we are
 * ready to receive data. We are ready if a session is established.
 */
static int relay_start(struct lttcomm_relayd_hdr *recv_hdr,
		struct relay_connection *conn)
{
	int ret = htobe32(LTTNG_OK);
	struct lttcomm_relayd_generic_reply reply;
	struct relay_session *session = conn->session;

	if (!session) {
		DBG("Trying to start the streaming without a session established");
		ret = htobe32(LTTNG_ERR_UNK);
	}

	memset(&reply, 0, sizeof(reply));
	reply.ret_code = ret;
	ret = conn->sock->ops->sendmsg(conn->sock, &reply,
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
	ssize_t ret = 0;
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

	ret = lttng_write(fd, zeros, size);
	if (ret < size) {
		PERROR("write padding to file");
	}

	free(zeros);

end:
	return ret;
}

/*
 * relay_recv_metadata: receive the metadata for the session.
 */
static int relay_recv_metadata(struct lttcomm_relayd_hdr *recv_hdr,
		struct relay_connection *conn)
{
	int ret = 0;
	ssize_t size_ret;
	struct relay_session *session = conn->session;
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
	size_ret = conn->sock->ops->recvmsg(conn->sock, data_buffer, data_size, 0);
	if (size_ret < 0 || size_ret != data_size) {
		if (size_ret == 0) {
			/* Orderly shutdown. Not necessary to print an error. */
			DBG("Socket %d did an orderly shutdown", conn->sock->fd);
		} else {
			ERR("Relay didn't receive the whole metadata");
		}
		ret = -1;
		goto end;
	}
	metadata_struct = (struct lttcomm_relayd_metadata_payload *) data_buffer;

	metadata_stream = stream_get_by_id(be64toh(metadata_struct->stream_id));
	if (!metadata_stream) {
		ret = -1;
		goto end;
	}

	pthread_mutex_lock(&metadata_stream->lock);

	size_ret = lttng_write(metadata_stream->stream_fd->fd, metadata_struct->payload,
			payload_size);
	if (size_ret < payload_size) {
		ERR("Relay error writing metadata on file");
		ret = -1;
		goto end_put;
	}

	size_ret = write_padding_to_file(metadata_stream->stream_fd->fd,
			be32toh(metadata_struct->padding_size));
	if (size_ret < 0) {
		goto end_put;
	}

	metadata_stream->metadata_received +=
		payload_size + be32toh(metadata_struct->padding_size);
	DBG2("Relay metadata written. Updated metadata_received %" PRIu64,
		metadata_stream->metadata_received);

end_put:
	pthread_mutex_unlock(&metadata_stream->lock);
	stream_put(metadata_stream);
end:
	return ret;
}

/*
 * relay_send_version: send relayd version number
 */
static int relay_send_version(struct lttcomm_relayd_hdr *recv_hdr,
		struct relay_connection *conn)
{
	int ret;
	struct lttcomm_relayd_version reply, msg;

	conn->version_check_done = 1;

	/* Get version from the other side. */
	ret = conn->sock->ops->recvmsg(conn->sock, &msg, sizeof(msg), 0);
	if (ret < 0 || ret != sizeof(msg)) {
		if (ret == 0) {
			/* Orderly shutdown. Not necessary to print an error. */
			DBG("Socket %d did an orderly shutdown", conn->sock->fd);
		} else {
			ERR("Relay failed to receive the version values.");
		}
		ret = -1;
		goto end;
	}

	memset(&reply, 0, sizeof(reply));
	reply.major = RELAYD_VERSION_COMM_MAJOR;
	reply.minor = RELAYD_VERSION_COMM_MINOR;

	/* Major versions must be the same */
	if (reply.major != be32toh(msg.major)) {
		DBG("Incompatible major versions (%u vs %u), deleting session",
				reply.major, be32toh(msg.major));
		connection_put(conn);
		ret = 0;
		goto end;
	}

	conn->major = reply.major;
	/* We adapt to the lowest compatible version */
	if (reply.minor <= be32toh(msg.minor)) {
		conn->minor = reply.minor;
	} else {
		conn->minor = be32toh(msg.minor);
	}

	reply.major = htobe32(reply.major);
	reply.minor = htobe32(reply.minor);
	ret = conn->sock->ops->sendmsg(conn->sock, &reply,
			sizeof(struct lttcomm_relayd_version), 0);
	if (ret < 0) {
		ERR("Relay sending version");
	}

	DBG("Version check done using protocol %u.%u", conn->major,
			conn->minor);

end:
	return ret;
}

/*
 * Check for data pending for a given stream id from the session daemon.
 */
static int relay_data_pending(struct lttcomm_relayd_hdr *recv_hdr,
		struct relay_connection *conn)
{
	struct relay_session *session = conn->session;
	struct lttcomm_relayd_data_pending msg;
	struct lttcomm_relayd_generic_reply reply;
	struct relay_stream *stream;
	int ret;
	uint64_t last_net_seq_num, stream_id;

	DBG("Data pending command received");

	if (!session || conn->version_check_done == 0) {
		ERR("Trying to check for data before version check");
		ret = -1;
		goto end_no_session;
	}

	ret = conn->sock->ops->recvmsg(conn->sock, &msg, sizeof(msg), 0);
	if (ret < sizeof(msg)) {
		if (ret == 0) {
			/* Orderly shutdown. Not necessary to print an error. */
			DBG("Socket %d did an orderly shutdown", conn->sock->fd);
		} else {
			ERR("Relay didn't receive valid data_pending struct size : %d",
					ret);
		}
		ret = -1;
		goto end_no_session;
	}

	stream_id = be64toh(msg.stream_id);
	last_net_seq_num = be64toh(msg.last_net_seq_num);

	stream = stream_get_by_id(stream_id);
	if (stream == NULL) {
		ret = -1;
		goto end;
	}

	pthread_mutex_lock(&stream->lock);

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

	stream->data_pending_check_done = true;
	pthread_mutex_unlock(&stream->lock);

	stream_put(stream);
end:

	memset(&reply, 0, sizeof(reply));
	reply.ret_code = htobe32(ret);
	ret = conn->sock->ops->sendmsg(conn->sock, &reply, sizeof(reply), 0);
	if (ret < 0) {
		ERR("Relay data pending ret code failed");
	}

end_no_session:
	return ret;
}

/*
 * Wait for the control socket to reach a quiescent state.
 *
 * Note that for now, when receiving this command from the session
 * daemon, this means that every subsequent commands or data received on
 * the control socket has been handled. So, this is why we simply return
 * OK here.
 */
static int relay_quiescent_control(struct lttcomm_relayd_hdr *recv_hdr,
		struct relay_connection *conn)
{
	int ret;
	uint64_t stream_id;
	struct relay_stream *stream;
	struct lttcomm_relayd_quiescent_control msg;
	struct lttcomm_relayd_generic_reply reply;

	DBG("Checking quiescent state on control socket");

	if (!conn->session || conn->version_check_done == 0) {
		ERR("Trying to check for data before version check");
		ret = -1;
		goto end_no_session;
	}

	ret = conn->sock->ops->recvmsg(conn->sock, &msg, sizeof(msg), 0);
	if (ret < sizeof(msg)) {
		if (ret == 0) {
			/* Orderly shutdown. Not necessary to print an error. */
			DBG("Socket %d did an orderly shutdown", conn->sock->fd);
		} else {
			ERR("Relay didn't receive valid begin data_pending struct size: %d",
					ret);
		}
		ret = -1;
		goto end_no_session;
	}

	stream_id = be64toh(msg.stream_id);
	stream = stream_get_by_id(stream_id);
	if (!stream) {
		goto reply;
	}
	pthread_mutex_lock(&stream->lock);
	stream->data_pending_check_done = true;
	pthread_mutex_unlock(&stream->lock);
	DBG("Relay quiescent control pending flag set to %" PRIu64, stream_id);
	stream_put(stream);
reply:
	memset(&reply, 0, sizeof(reply));
	reply.ret_code = htobe32(LTTNG_OK);
	ret = conn->sock->ops->sendmsg(conn->sock, &reply, sizeof(reply), 0);
	if (ret < 0) {
		ERR("Relay data quiescent control ret code failed");
	}

end_no_session:
	return ret;
}

/*
 * Initialize a data pending command. This means that a consumer is about
 * to ask for data pending for each stream it holds. Simply iterate over
 * all streams of a session and set the data_pending_check_done flag.
 *
 * This command returns to the client a LTTNG_OK code.
 */
static int relay_begin_data_pending(struct lttcomm_relayd_hdr *recv_hdr,
		struct relay_connection *conn)
{
	int ret;
	struct lttng_ht_iter iter;
	struct lttcomm_relayd_begin_data_pending msg;
	struct lttcomm_relayd_generic_reply reply;
	struct relay_stream *stream;
	uint64_t session_id;

	assert(recv_hdr);
	assert(conn);

	DBG("Init streams for data pending");

	if (!conn->session || conn->version_check_done == 0) {
		ERR("Trying to check for data before version check");
		ret = -1;
		goto end_no_session;
	}

	ret = conn->sock->ops->recvmsg(conn->sock, &msg, sizeof(msg), 0);
	if (ret < sizeof(msg)) {
		if (ret == 0) {
			/* Orderly shutdown. Not necessary to print an error. */
			DBG("Socket %d did an orderly shutdown", conn->sock->fd);
		} else {
			ERR("Relay didn't receive valid begin data_pending struct size: %d",
					ret);
		}
		ret = -1;
		goto end_no_session;
	}

	session_id = be64toh(msg.session_id);

	/*
	 * Iterate over all streams to set the begin data pending flag.
	 * For now, the streams are indexed by stream handle so we have
	 * to iterate over all streams to find the one associated with
	 * the right session_id.
	 */
	rcu_read_lock();
	cds_lfht_for_each_entry(relay_streams_ht->ht, &iter.iter, stream,
			node.node) {
		if (!stream_get(stream)) {
			continue;
		}
		if (stream->trace->session->id == session_id) {
			pthread_mutex_lock(&stream->lock);
			stream->data_pending_check_done = false;
			pthread_mutex_unlock(&stream->lock);
			DBG("Set begin data pending flag to stream %" PRIu64,
					stream->stream_handle);
		}
		stream_put(stream);
	}
	rcu_read_unlock();

	memset(&reply, 0, sizeof(reply));
	/* All good, send back reply. */
	reply.ret_code = htobe32(LTTNG_OK);

	ret = conn->sock->ops->sendmsg(conn->sock, &reply, sizeof(reply), 0);
	if (ret < 0) {
		ERR("Relay begin data pending send reply failed");
	}

end_no_session:
	return ret;
}

/*
 * End data pending command. This will check, for a given session id, if
 * each stream associated with it has its data_pending_check_done flag
 * set. If not, this means that the client lost track of the stream but
 * the data is still being streamed on our side. In this case, we inform
 * the client that data is in flight.
 *
 * Return to the client if there is data in flight or not with a ret_code.
 */
static int relay_end_data_pending(struct lttcomm_relayd_hdr *recv_hdr,
		struct relay_connection *conn)
{
	int ret;
	struct lttng_ht_iter iter;
	struct lttcomm_relayd_end_data_pending msg;
	struct lttcomm_relayd_generic_reply reply;
	struct relay_stream *stream;
	uint64_t session_id;
	uint32_t is_data_inflight = 0;

	DBG("End data pending command");

	if (!conn->session || conn->version_check_done == 0) {
		ERR("Trying to check for data before version check");
		ret = -1;
		goto end_no_session;
	}

	ret = conn->sock->ops->recvmsg(conn->sock, &msg, sizeof(msg), 0);
	if (ret < sizeof(msg)) {
		if (ret == 0) {
			/* Orderly shutdown. Not necessary to print an error. */
			DBG("Socket %d did an orderly shutdown", conn->sock->fd);
		} else {
			ERR("Relay didn't receive valid end data_pending struct size: %d",
					ret);
		}
		ret = -1;
		goto end_no_session;
	}

	session_id = be64toh(msg.session_id);

	/*
	 * Iterate over all streams to see if the begin data pending
	 * flag is set.
	 */
	rcu_read_lock();
	cds_lfht_for_each_entry(relay_streams_ht->ht, &iter.iter, stream,
			node.node) {
		if (!stream_get(stream)) {
			continue;
		}
		if (stream->trace->session->id != session_id) {
			stream_put(stream);
			continue;
		}
		pthread_mutex_lock(&stream->lock);
		if (!stream->data_pending_check_done) {
			if (!stream->closed || !(((int64_t) (stream->prev_seq - stream->last_net_seq_num)) >= 0)) {
				is_data_inflight = 1;
				DBG("Data is still in flight for stream %" PRIu64,
						stream->stream_handle);
				pthread_mutex_unlock(&stream->lock);
				stream_put(stream);
				break;
			}
		}
		pthread_mutex_unlock(&stream->lock);
		stream_put(stream);
	}
	rcu_read_unlock();

	memset(&reply, 0, sizeof(reply));
	/* All good, send back reply. */
	reply.ret_code = htobe32(is_data_inflight);

	ret = conn->sock->ops->sendmsg(conn->sock, &reply, sizeof(reply), 0);
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
static int relay_recv_index(struct lttcomm_relayd_hdr *recv_hdr,
		struct relay_connection *conn)
{
	int ret, send_ret;
	struct relay_session *session = conn->session;
	struct lttcomm_relayd_index index_info;
	struct relay_index *index;
	struct lttcomm_relayd_generic_reply reply;
	struct relay_stream *stream;
	uint64_t net_seq_num;
	size_t msg_len;

	assert(conn);

	DBG("Relay receiving index");

	if (!session || conn->version_check_done == 0) {
		ERR("Trying to close a stream before version check");
		ret = -1;
		goto end_no_session;
	}

	msg_len = lttcomm_relayd_index_len(
			lttng_to_index_major(conn->major, conn->minor),
			lttng_to_index_minor(conn->major, conn->minor));
	ret = conn->sock->ops->recvmsg(conn->sock, &index_info,
			msg_len, 0);
	if (ret < msg_len) {
		if (ret == 0) {
			/* Orderly shutdown. Not necessary to print an error. */
			DBG("Socket %d did an orderly shutdown", conn->sock->fd);
		} else {
			ERR("Relay didn't receive valid index struct size : %d", ret);
		}
		ret = -1;
		goto end_no_session;
	}

	net_seq_num = be64toh(index_info.net_seq_num);

	stream = stream_get_by_id(be64toh(index_info.relay_stream_id));
	if (!stream) {
		ERR("stream_get_by_id not found");
		ret = -1;
		goto end;
	}
	pthread_mutex_lock(&stream->lock);

	/* Live beacon handling */
	if (index_info.packet_size == 0) {
		DBG("Received live beacon for stream %" PRIu64,
				stream->stream_handle);

		/*
		 * Only flag a stream inactive when it has already
		 * received data and no indexes are in flight.
		 */
		if (stream->index_received_seqcount > 0
				&& stream->indexes_in_flight == 0) {
			stream->beacon_ts_end =
				be64toh(index_info.timestamp_end);
		}
		ret = 0;
		goto end_stream_put;
	} else {
		stream->beacon_ts_end = -1ULL;
	}

	if (stream->ctf_stream_id == -1ULL) {
		stream->ctf_stream_id = be64toh(index_info.stream_id);
	}
	index = relay_index_get_by_id_or_create(stream, net_seq_num);
	if (!index) {
		ret = -1;
		ERR("relay_index_get_by_id_or_create index NULL");
		goto end_stream_put;
	}
	if (set_index_control_data(index, &index_info, conn)) {
		ERR("set_index_control_data error");
		relay_index_put(index);
		ret = -1;
		goto end_stream_put;
	}
	ret = relay_index_try_flush(index);
	if (ret == 0) {
		tracefile_array_commit_seq(stream->tfa);
		stream->index_received_seqcount++;
	} else if (ret > 0) {
		/* no flush. */
		ret = 0;
	} else {
		ERR("relay_index_try_flush error %d", ret);
		relay_index_put(index);
		ret = -1;
	}

end_stream_put:
	pthread_mutex_unlock(&stream->lock);
	stream_put(stream);

end:

	memset(&reply, 0, sizeof(reply));
	if (ret < 0) {
		reply.ret_code = htobe32(LTTNG_ERR_UNK);
	} else {
		reply.ret_code = htobe32(LTTNG_OK);
	}
	send_ret = conn->sock->ops->sendmsg(conn->sock, &reply, sizeof(reply), 0);
	if (send_ret < 0) {
		ERR("Relay sending close index id reply");
		ret = send_ret;
	}

end_no_session:
	return ret;
}

/*
 * Receive the streams_sent message.
 *
 * Return 0 on success else a negative value.
 */
static int relay_streams_sent(struct lttcomm_relayd_hdr *recv_hdr,
		struct relay_connection *conn)
{
	int ret, send_ret;
	struct lttcomm_relayd_generic_reply reply;

	assert(conn);

	DBG("Relay receiving streams_sent");

	if (!conn->session || conn->version_check_done == 0) {
		ERR("Trying to close a stream before version check");
		ret = -1;
		goto end_no_session;
	}

	/*
	 * Publish every pending stream in the connection recv list which are
	 * now ready to be used by the viewer.
	 */
	publish_connection_local_streams(conn);

	memset(&reply, 0, sizeof(reply));
	reply.ret_code = htobe32(LTTNG_OK);
	send_ret = conn->sock->ops->sendmsg(conn->sock, &reply, sizeof(reply), 0);
	if (send_ret < 0) {
		ERR("Relay sending sent_stream reply");
		ret = send_ret;
	} else {
		/* Success. */
		ret = 0;
	}

end_no_session:
	return ret;
}

/*
 * Process the commands received on the control socket
 */
static int relay_process_control(struct lttcomm_relayd_hdr *recv_hdr,
		struct relay_connection *conn)
{
	int ret = 0;

	switch (be32toh(recv_hdr->cmd)) {
	case RELAYD_CREATE_SESSION:
		ret = relay_create_session(recv_hdr, conn);
		break;
	case RELAYD_ADD_STREAM:
		ret = relay_add_stream(recv_hdr, conn);
		break;
	case RELAYD_START_DATA:
		ret = relay_start(recv_hdr, conn);
		break;
	case RELAYD_SEND_METADATA:
		ret = relay_recv_metadata(recv_hdr, conn);
		break;
	case RELAYD_VERSION:
		ret = relay_send_version(recv_hdr, conn);
		break;
	case RELAYD_CLOSE_STREAM:
		ret = relay_close_stream(recv_hdr, conn);
		break;
	case RELAYD_DATA_PENDING:
		ret = relay_data_pending(recv_hdr, conn);
		break;
	case RELAYD_QUIESCENT_CONTROL:
		ret = relay_quiescent_control(recv_hdr, conn);
		break;
	case RELAYD_BEGIN_DATA_PENDING:
		ret = relay_begin_data_pending(recv_hdr, conn);
		break;
	case RELAYD_END_DATA_PENDING:
		ret = relay_end_data_pending(recv_hdr, conn);
		break;
	case RELAYD_SEND_INDEX:
		ret = relay_recv_index(recv_hdr, conn);
		break;
	case RELAYD_STREAMS_SENT:
		ret = relay_streams_sent(recv_hdr, conn);
		break;
	case RELAYD_RESET_METADATA:
		ret = relay_reset_metadata(recv_hdr, conn);
		break;
	case RELAYD_UPDATE_SYNC_INFO:
	default:
		ERR("Received unknown command (%u)", be32toh(recv_hdr->cmd));
		relay_unknown_command(conn);
		ret = -1;
		goto end;
	}

end:
	return ret;
}

/*
 * Handle index for a data stream.
 *
 * Called with the stream lock held.
 *
 * Return 0 on success else a negative value.
 */
static int handle_index_data(struct relay_stream *stream, uint64_t net_seq_num,
		int rotate_index)
{
	int ret = 0;
	uint64_t data_offset;
	struct relay_index *index;

	/* Get data offset because we are about to update the index. */
	data_offset = htobe64(stream->tracefile_size_current);

	DBG("handle_index_data: stream %" PRIu64 " net_seq_num %" PRIu64 " data offset %" PRIu64,
			stream->stream_handle, net_seq_num, stream->tracefile_size_current);

	/*
	 * Lookup for an existing index for that stream id/sequence
	 * number. If it exists, the control thread has already received the
	 * data for it, thus we need to write it to disk.
	 */
	index = relay_index_get_by_id_or_create(stream, net_seq_num);
	if (!index) {
		ret = -1;
		goto end;
	}

	if (rotate_index || !stream->index_file) {
		uint32_t major, minor;

		/* Put ref on previous index_file. */
		if (stream->index_file) {
			lttng_index_file_put(stream->index_file);
			stream->index_file = NULL;
		}
		major = stream->trace->session->major;
		minor = stream->trace->session->minor;
		stream->index_file = lttng_index_file_create(stream->path_name,
				stream->channel_name,
			        -1, -1, stream->tracefile_size,
				tracefile_array_get_file_index_head(stream->tfa),
				lttng_to_index_major(major, minor),
				lttng_to_index_minor(major, minor));
		if (!stream->index_file) {
			ret = -1;
			/* Put self-ref for this index due to error. */
			relay_index_put(index);
			index = NULL;
			goto end;
		}
	}

	if (relay_index_set_file(index, stream->index_file, data_offset)) {
		ret = -1;
		/* Put self-ref for this index due to error. */
		relay_index_put(index);
		index = NULL;
		goto end;
	}

	ret = relay_index_try_flush(index);
	if (ret == 0) {
		tracefile_array_commit_seq(stream->tfa);
		stream->index_received_seqcount++;
	} else if (ret > 0) {
		/* No flush. */
		ret = 0;
	} else {
		/* Put self-ref for this index due to error. */
		relay_index_put(index);
		index = NULL;
		ret = -1;
	}
end:
	return ret;
}

/*
 * relay_process_data: Process the data received on the data socket
 */
static int relay_process_data(struct relay_connection *conn)
{
	int ret = 0, rotate_index = 0;
	ssize_t size_ret;
	struct relay_stream *stream;
	struct lttcomm_relayd_data_hdr data_hdr;
	uint64_t stream_id;
	uint64_t net_seq_num;
	uint32_t data_size;
	struct relay_session *session;
	bool new_stream = false, close_requested = false;
	size_t chunk_size = RECV_DATA_BUFFER_SIZE;
	size_t recv_off = 0;
	char data_buffer[chunk_size];

	ret = conn->sock->ops->recvmsg(conn->sock, &data_hdr,
			sizeof(struct lttcomm_relayd_data_hdr), 0);
	if (ret <= 0) {
		if (ret == 0) {
			/* Orderly shutdown. Not necessary to print an error. */
			DBG("Socket %d did an orderly shutdown", conn->sock->fd);
		} else {
			ERR("Unable to receive data header on sock %d", conn->sock->fd);
		}
		ret = -1;
		goto end;
	}

	stream_id = be64toh(data_hdr.stream_id);
	stream = stream_get_by_id(stream_id);
	if (!stream) {
		ERR("relay_process_data: Cannot find stream %" PRIu64, stream_id);
		ret = -1;
		goto end;
	}
	session = stream->trace->session;
	data_size = be32toh(data_hdr.data_size);

	net_seq_num = be64toh(data_hdr.net_seq_num);

	DBG3("Receiving data of size %u for stream id %" PRIu64 " seqnum %" PRIu64,
		data_size, stream_id, net_seq_num);

	pthread_mutex_lock(&stream->lock);

	/* Check if a rotation is needed. */
	if (stream->tracefile_size > 0 &&
			(stream->tracefile_size_current + data_size) >
			stream->tracefile_size) {
		uint64_t old_id, new_id;

		old_id = tracefile_array_get_file_index_head(stream->tfa);
		tracefile_array_file_rotate(stream->tfa);

		/* new_id is updated by utils_rotate_stream_file. */
		new_id = old_id;

		ret = utils_rotate_stream_file(stream->path_name,
				stream->channel_name, stream->tracefile_size,
				stream->tracefile_count, -1,
			        -1, stream->stream_fd->fd,
				&new_id, &stream->stream_fd->fd);
		if (ret < 0) {
			ERR("Rotating stream output file");
			goto end_stream_unlock;
		}
		/*
		 * Reset current size because we just performed a stream
		 * rotation.
		 */
		stream->tracefile_size_current = 0;
		rotate_index = 1;
	}

	/*
	 * Index are handled in protocol version 2.4 and above. Also,
	 * snapshot and index are NOT supported.
	 */
	if (session->minor >= 4 && !session->snapshot) {
		ret = handle_index_data(stream, net_seq_num, rotate_index);
		if (ret < 0) {
			ERR("handle_index_data: fail stream %" PRIu64 " net_seq_num %" PRIu64 " ret %d",
					stream->stream_handle, net_seq_num, ret);
			goto end_stream_unlock;
		}
	}

	for (recv_off = 0; recv_off < data_size; recv_off += chunk_size) {
		size_t recv_size = min(data_size - recv_off, chunk_size);

		ret = conn->sock->ops->recvmsg(conn->sock, data_buffer, recv_size, 0);
		if (ret <= 0) {
			if (ret == 0) {
				/* Orderly shutdown. Not necessary to print an error. */
				DBG("Socket %d did an orderly shutdown", conn->sock->fd);
			} else {
				ERR("Socket %d error %d", conn->sock->fd, ret);
			}
			ret = -1;
			goto end_stream_unlock;
		}

		/* Write data to stream output fd. */
		size_ret = lttng_write(stream->stream_fd->fd, data_buffer,
				recv_size);
		if (size_ret < recv_size) {
			ERR("Relay error writing data to file");
			ret = -1;
			goto end_stream_unlock;
		}

		DBG2("Relay wrote %zd bytes to tracefile for stream id %" PRIu64,
				size_ret, stream->stream_handle);
	}

	ret = write_padding_to_file(stream->stream_fd->fd,
			be32toh(data_hdr.padding_size));
	if (ret < 0) {
		ERR("write_padding_to_file: fail stream %" PRIu64 " net_seq_num %" PRIu64 " ret %d",
				stream->stream_handle, net_seq_num, ret);
		goto end_stream_unlock;
	}
	stream->tracefile_size_current +=
			data_size + be32toh(data_hdr.padding_size);
	if (stream->prev_seq == -1ULL) {
		new_stream = true;
	}

	stream->prev_seq = net_seq_num;

end_stream_unlock:
	close_requested = stream->close_requested;
	pthread_mutex_unlock(&stream->lock);
	if (close_requested) {
		try_stream_close(stream);
	}

	if (new_stream) {
		pthread_mutex_lock(&session->lock);
		uatomic_set(&session->new_streams, 1);
		pthread_mutex_unlock(&session->lock);
	}
	stream_put(stream);
end:
	return ret;
}

static void cleanup_connection_pollfd(struct lttng_poll_event *events, int pollfd)
{
	int ret;

	(void) lttng_poll_del(events, pollfd);

	ret = close(pollfd);
	if (ret < 0) {
		ERR("Closing pollfd %d", pollfd);
	}
}

static void relay_thread_close_connection(struct lttng_poll_event *events,
		int pollfd, struct relay_connection *conn)
{
	const char *type_str;

	switch (conn->type) {
	case RELAY_DATA:
		type_str = "Data";
		break;
	case RELAY_CONTROL:
		type_str = "Control";
		break;
	case RELAY_VIEWER_COMMAND:
		type_str = "Viewer Command";
		break;
	case RELAY_VIEWER_NOTIFICATION:
		type_str = "Viewer Notification";
		break;
	default:
		type_str = "Unknown";
	}
	cleanup_connection_pollfd(events, pollfd);
	connection_put(conn);
	DBG("%s connection closed with %d", type_str, pollfd);
}

/*
 * This thread does the actual work
 */
static void *relay_thread_worker(void *data)
{
	int ret, err = -1, last_seen_data_fd = -1;
	uint32_t nb_fd;
	struct lttng_poll_event events;
	struct lttng_ht *relay_connections_ht;
	struct lttng_ht_iter iter;
	struct lttcomm_relayd_hdr recv_hdr;
	struct relay_connection *destroy_conn = NULL;

	DBG("[thread] Relay worker started");

	rcu_register_thread();

	health_register(health_relayd, HEALTH_RELAYD_TYPE_WORKER);

	if (testpoint(relayd_thread_worker)) {
		goto error_testpoint;
	}

	health_code_update();

	/* table of connections indexed on socket */
	relay_connections_ht = lttng_ht_new(0, LTTNG_HT_TYPE_ULONG);
	if (!relay_connections_ht) {
		goto relay_connections_ht_error;
	}

	ret = create_thread_poll_set(&events, 2);
	if (ret < 0) {
		goto error_poll_create;
	}

	ret = lttng_poll_add(&events, relay_conn_pipe[0], LPOLLIN | LPOLLRDHUP);
	if (ret < 0) {
		goto error;
	}

restart:
	while (1) {
		int idx = -1, i, seen_control = 0, last_notdel_data_fd = -1;

		health_code_update();

		/* Infinite blocking call, waiting for transmission */
		DBG3("Relayd worker thread polling...");
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
		 * Process control. The control connection is
		 * prioritized so we don't starve it with high
		 * throughput tracing data on the data connection.
		 */
		for (i = 0; i < nb_fd; i++) {
			/* Fetch once the poll data */
			uint32_t revents = LTTNG_POLL_GETEV(&events, i);
			int pollfd = LTTNG_POLL_GETFD(&events, i);

			health_code_update();

			if (!revents) {
				/*
				 * No activity for this FD (poll
				 * implementation).
				 */
				continue;
			}

			/* Thread quit pipe has been closed. Killing thread. */
			ret = check_thread_quit_pipe(pollfd, revents);
			if (ret) {
				err = 0;
				goto exit;
			}

			/* Inspect the relay conn pipe for new connection */
			if (pollfd == relay_conn_pipe[0]) {
				if (revents & LPOLLIN) {
					struct relay_connection *conn;

					ret = lttng_read(relay_conn_pipe[0], &conn, sizeof(conn));
					if (ret < 0) {
						goto error;
					}
					lttng_poll_add(&events, conn->sock->fd,
							LPOLLIN | LPOLLRDHUP);
					connection_ht_add(relay_connections_ht, conn);
					DBG("Connection socket %d added", conn->sock->fd);
				} else if (revents & (LPOLLERR | LPOLLHUP | LPOLLRDHUP)) {
					ERR("Relay connection pipe error");
					goto error;
				} else {
					ERR("Unexpected poll events %u for sock %d", revents, pollfd);
					goto error;
				}
			} else {
				struct relay_connection *ctrl_conn;

				ctrl_conn = connection_get_by_sock(relay_connections_ht, pollfd);
				/* If not found, there is a synchronization issue. */
				assert(ctrl_conn);

				if (ctrl_conn->type == RELAY_DATA) {
					if (revents & LPOLLIN) {
						/*
						 * Flag the last seen data fd not deleted. It will be
						 * used as the last seen fd if any fd gets deleted in
						 * this first loop.
						 */
						last_notdel_data_fd = pollfd;
					}
					goto put_ctrl_connection;
				}
				assert(ctrl_conn->type == RELAY_CONTROL);

				if (revents & LPOLLIN) {
					ret = ctrl_conn->sock->ops->recvmsg(ctrl_conn->sock,
							&recv_hdr, sizeof(recv_hdr), 0);
					if (ret <= 0) {
						/* Connection closed */
						relay_thread_close_connection(&events, pollfd,
								ctrl_conn);
					} else {
						ret = relay_process_control(&recv_hdr, ctrl_conn);
						if (ret < 0) {
							/* Clear the session on error. */
							relay_thread_close_connection(&events,
									pollfd, ctrl_conn);
						}
						seen_control = 1;
					}
				} else if (revents & (LPOLLERR | LPOLLHUP | LPOLLRDHUP)) {
					relay_thread_close_connection(&events,
							pollfd, ctrl_conn);
					if (last_seen_data_fd == pollfd) {
						last_seen_data_fd = last_notdel_data_fd;
					}
				} else {
					ERR("Unexpected poll events %u for control sock %d",
							revents, pollfd);
					connection_put(ctrl_conn);
					goto error;
				}
			put_ctrl_connection:
				connection_put(ctrl_conn);
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

				health_code_update();

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
			struct relay_connection *data_conn;

			health_code_update();

			if (!revents) {
				/* No activity for this FD (poll implementation). */
				continue;
			}

			/* Skip the command pipe. It's handled in the first loop. */
			if (pollfd == relay_conn_pipe[0]) {
				continue;
			}

			data_conn = connection_get_by_sock(relay_connections_ht, pollfd);
			if (!data_conn) {
				/* Skip it. Might be removed before. */
				continue;
			}
			if (data_conn->type == RELAY_CONTROL) {
				goto put_data_connection;
			}
			assert(data_conn->type == RELAY_DATA);

			if (revents & LPOLLIN) {
				ret = relay_process_data(data_conn);
				/* Connection closed */
				if (ret < 0) {
					relay_thread_close_connection(&events, pollfd,
							data_conn);
					/*
					 * Every goto restart call sets the last seen fd where
					 * here we don't really care since we gracefully
					 * continue the loop after the connection is deleted.
					 */
				} else {
					/* Keep last seen port. */
					last_seen_data_fd = pollfd;
					connection_put(data_conn);
					goto restart;
				}
			} else if (revents & (LPOLLERR | LPOLLHUP | LPOLLRDHUP)) {
				relay_thread_close_connection(&events, pollfd,
						data_conn);
			} else {
				ERR("Unknown poll events %u for data sock %d",
						revents, pollfd);
			}
		put_data_connection:
			connection_put(data_conn);
		}
		last_seen_data_fd = -1;
	}

	/* Normal exit, no error */
	ret = 0;

exit:
error:
	/* Cleanup reamaining connection object. */
	rcu_read_lock();
	cds_lfht_for_each_entry(relay_connections_ht->ht, &iter.iter,
			destroy_conn,
			sock_n.node) {
		health_code_update();

		if (session_abort(destroy_conn->session)) {
			assert(0);
		}

		/*
		 * No need to grab another ref, because we own
		 * destroy_conn.
		 */
		relay_thread_close_connection(&events, destroy_conn->sock->fd,
				destroy_conn);
	}
	rcu_read_unlock();

	lttng_poll_clean(&events);
error_poll_create:
	lttng_ht_destroy(relay_connections_ht);
relay_connections_ht_error:
	/* Close relay conn pipes */
	utils_close_pipe(relay_conn_pipe);
	if (err) {
		DBG("Thread exited with error");
	}
	DBG("Worker thread cleanup complete");
error_testpoint:
	if (err) {
		health_error();
		ERR("Health error occurred in %s", __func__);
	}
	health_unregister(health_relayd);
	rcu_unregister_thread();
	lttng_relay_stop_threads();
	return NULL;
}

/*
 * Create the relay command pipe to wake thread_manage_apps.
 * Closed in cleanup().
 */
static int create_relay_conn_pipe(void)
{
	int ret;

	ret = utils_create_pipe_cloexec(relay_conn_pipe);

	return ret;
}

/*
 * main
 */
int main(int argc, char **argv)
{
	int ret = 0, retval = 0;
	void *status;

	/* Parse arguments */
	progname = argv[0];
	if (set_options(argc, argv)) {
		retval = -1;
		goto exit_options;
	}

	if (set_signal_handler()) {
		retval = -1;
		goto exit_options;
	}

	/* Try to create directory if -o, --output is specified. */
	if (opt_output_path) {
		if (*opt_output_path != '/') {
			ERR("Please specify an absolute path for -o, --output PATH");
			retval = -1;
			goto exit_options;
		}

		ret = utils_mkdir_recursive(opt_output_path, S_IRWXU | S_IRWXG,
				-1, -1);
		if (ret < 0) {
			ERR("Unable to create %s", opt_output_path);
			retval = -1;
			goto exit_options;
		}
	}

	/* Daemonize */
	if (opt_daemon || opt_background) {
		int i;

		ret = lttng_daemonize(&child_ppid, &recv_child_signal,
			!opt_background);
		if (ret < 0) {
			retval = -1;
			goto exit_options;
		}

		/*
		 * We are in the child. Make sure all other file
		 * descriptors are closed, in case we are called with
		 * more opened file descriptors than the standard ones.
		 */
		for (i = 3; i < sysconf(_SC_OPEN_MAX); i++) {
			(void) close(i);
		}
	}

	/* Initialize thread health monitoring */
	health_relayd = health_app_create(NR_HEALTH_RELAYD_TYPES);
	if (!health_relayd) {
		PERROR("health_app_create error");
		retval = -1;
		goto exit_health_app_create;
	}

	/* Create thread quit pipe */
	if (init_thread_quit_pipe()) {
		retval = -1;
		goto exit_init_data;
	}

	/* Setup the thread apps communication pipe. */
	if (create_relay_conn_pipe()) {
		retval = -1;
		goto exit_init_data;
	}

	/* Init relay command queue. */
	cds_wfcq_init(&relay_conn_queue.head, &relay_conn_queue.tail);

	/* Initialize communication library */
	lttcomm_init();
	lttcomm_inet_init();

	/* tables of sessions indexed by session ID */
	sessions_ht = lttng_ht_new(0, LTTNG_HT_TYPE_U64);
	if (!sessions_ht) {
		retval = -1;
		goto exit_init_data;
	}

	/* tables of streams indexed by stream ID */
	relay_streams_ht = lttng_ht_new(0, LTTNG_HT_TYPE_U64);
	if (!relay_streams_ht) {
		retval = -1;
		goto exit_init_data;
	}

	/* tables of streams indexed by stream ID */
	viewer_streams_ht = lttng_ht_new(0, LTTNG_HT_TYPE_U64);
	if (!viewer_streams_ht) {
		retval = -1;
		goto exit_init_data;
	}

	ret = utils_create_pipe(health_quit_pipe);
	if (ret) {
		retval = -1;
		goto exit_health_quit_pipe;
	}

	/* Create thread to manage the client socket */
	ret = pthread_create(&health_thread, default_pthread_attr(),
			thread_manage_health, (void *) NULL);
	if (ret) {
		errno = ret;
		PERROR("pthread_create health");
		retval = -1;
		goto exit_health_thread;
	}

	/* Setup the dispatcher thread */
	ret = pthread_create(&dispatcher_thread, default_pthread_attr(),
			relay_thread_dispatcher, (void *) NULL);
	if (ret) {
		errno = ret;
		PERROR("pthread_create dispatcher");
		retval = -1;
		goto exit_dispatcher_thread;
	}

	/* Setup the worker thread */
	ret = pthread_create(&worker_thread, default_pthread_attr(),
			relay_thread_worker, NULL);
	if (ret) {
		errno = ret;
		PERROR("pthread_create worker");
		retval = -1;
		goto exit_worker_thread;
	}

	/* Setup the listener thread */
	ret = pthread_create(&listener_thread, default_pthread_attr(),
			relay_thread_listener, (void *) NULL);
	if (ret) {
		errno = ret;
		PERROR("pthread_create listener");
		retval = -1;
		goto exit_listener_thread;
	}

	ret = relayd_live_create(live_uri);
	if (ret) {
		ERR("Starting live viewer threads");
		retval = -1;
		goto exit_live;
	}

	/*
	 * This is where we start awaiting program completion (e.g. through
	 * signal that asks threads to teardown).
	 */

	ret = relayd_live_join();
	if (ret) {
		retval = -1;
	}
exit_live:

	ret = pthread_join(listener_thread, &status);
	if (ret) {
		errno = ret;
		PERROR("pthread_join listener_thread");
		retval = -1;
	}

exit_listener_thread:
	ret = pthread_join(worker_thread, &status);
	if (ret) {
		errno = ret;
		PERROR("pthread_join worker_thread");
		retval = -1;
	}

exit_worker_thread:
	ret = pthread_join(dispatcher_thread, &status);
	if (ret) {
		errno = ret;
		PERROR("pthread_join dispatcher_thread");
		retval = -1;
	}
exit_dispatcher_thread:

	ret = pthread_join(health_thread, &status);
	if (ret) {
		errno = ret;
		PERROR("pthread_join health_thread");
		retval = -1;
	}
exit_health_thread:

	utils_close_pipe(health_quit_pipe);
exit_health_quit_pipe:

exit_init_data:
	health_app_destroy(health_relayd);
exit_health_app_create:
exit_options:
	/*
	 * Wait for all pending call_rcu work to complete before tearing
	 * down data structures. call_rcu worker may be trying to
	 * perform lookups in those structures.
	 */
	rcu_barrier();
	relayd_cleanup();

	/* Ensure all prior call_rcu are done. */
	rcu_barrier();

	if (!retval) {
		exit(EXIT_SUCCESS);
	} else {
		exit(EXIT_FAILURE);
	}
}
