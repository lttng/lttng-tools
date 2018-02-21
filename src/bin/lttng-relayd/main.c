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
#include <common/align.h>
#include <common/config/session-config.h>
#include <common/dynamic-buffer.h>
#include <common/buffer-view.h>
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
#include "tcp_keep_alive.h"

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
#define FILE_COPY_BUFFER_SIZE		65536

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
		PERROR("Failed to bind socket");
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

				ret = socket_apply_keep_alive_config(newsock->fd);
				if (ret < 0) {
					ERR("Failed to apply TCP keep-alive configuration on socket (%i)",
							newsock->fd);
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
	 * The index on disk is encoded in big endian.
	 */
	index_data.packet_size = htobe64(data->packet_size);
	index_data.content_size = htobe64(data->content_size);
	index_data.timestamp_begin = htobe64(data->timestamp_begin);
	index_data.timestamp_end = htobe64(data->timestamp_end);
	index_data.events_discarded = htobe64(data->events_discarded);
	index_data.stream_id = htobe64(data->stream_id);

	if (conn->minor >= 8) {
		index->index_data.stream_instance_id = htobe64(data->stream_instance_id);
		index->index_data.packet_seq_num = htobe64(data->packet_seq_num);
	}

	return relay_index_set_data(index, &index_data);
}

/*
 * Handle the RELAYD_CREATE_SESSION command.
 *
 * On success, send back the session id or else return a negative value.
 */
static int relay_create_session(const struct lttcomm_relayd_hdr *recv_hdr,
		struct relay_connection *conn,
		const struct lttng_buffer_view *payload)
{
	int ret = 0;
	ssize_t send_ret;
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
		ret = cmd_create_session_2_4(payload, session_name,
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
	if (send_ret < (ssize_t) sizeof(reply)) {
		ERR("Failed to send \"create session\" command reply (ret = %zd)",
				send_ret);
		ret = -1;
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
static int relay_add_stream(const struct lttcomm_relayd_hdr *recv_hdr,
		struct relay_connection *conn,
		const struct lttng_buffer_view *payload)
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

	if (!session || !conn->version_check_done) {
		ERR("Trying to add a stream before version check");
		ret = -1;
		goto end_no_session;
	}

	switch (session->minor) {
	case 1: /* LTTng sessiond 2.1. Allocates path_name and channel_name. */
		ret = cmd_recv_stream_2_1(payload, &path_name,
			&channel_name);
		break;
	case 2: /* LTTng sessiond 2.2. Allocates path_name and channel_name. */
	default:
		ret = cmd_recv_stream_2_2(payload, &path_name,
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
	if (send_ret < (ssize_t) sizeof(reply)) {
		ERR("Failed to send \"add stream\" command reply (ret = %zd)",
				send_ret);
		ret = -1;
	}

end_no_session:
	free(path_name);
	free(channel_name);
	return ret;
}

/*
 * relay_close_stream: close a specific stream
 */
static int relay_close_stream(const struct lttcomm_relayd_hdr *recv_hdr,
		struct relay_connection *conn,
		const struct lttng_buffer_view *payload)
{
	int ret;
	ssize_t send_ret;
	struct relay_session *session = conn->session;
	struct lttcomm_relayd_close_stream stream_info;
	struct lttcomm_relayd_generic_reply reply;
	struct relay_stream *stream;

	DBG("Close stream received");

	if (!session || !conn->version_check_done) {
		ERR("Trying to close a stream before version check");
		ret = -1;
		goto end_no_session;
	}

	if (payload->size < sizeof(stream_info)) {
		ERR("Unexpected payload size in \"relay_close_stream\": expected >= %zu bytes, got %zu bytes",
				sizeof(stream_info), payload->size);
		ret = -1;
		goto end_no_session;
	}
	memcpy(&stream_info, payload->data, sizeof(stream_info));
	stream_info.stream_id = be64toh(stream_info.stream_id);
	stream_info.last_net_seq_num = be64toh(stream_info.last_net_seq_num);

	stream = stream_get_by_id(stream_info.stream_id);
	if (!stream) {
		ret = -1;
		goto end;
	}

	/*
	 * Set last_net_seq_num before the close flag. Required by data
	 * pending check.
	 */
	pthread_mutex_lock(&stream->lock);
	stream->last_net_seq_num = stream_info.last_net_seq_num;
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
	ret = 0;

end:
	memset(&reply, 0, sizeof(reply));
	if (ret < 0) {
		reply.ret_code = htobe32(LTTNG_ERR_UNK);
	} else {
		reply.ret_code = htobe32(LTTNG_OK);
	}
	send_ret = conn->sock->ops->sendmsg(conn->sock, &reply,
			sizeof(struct lttcomm_relayd_generic_reply), 0);
	if (send_ret < (ssize_t) sizeof(reply)) {
		ERR("Failed to send \"close stream\" command reply (ret = %zd)",
				send_ret);
		ret = -1;
	}

end_no_session:
	return ret;
}

/*
 * relay_reset_metadata: reset a metadata stream
 */
static
int relay_reset_metadata(const struct lttcomm_relayd_hdr *recv_hdr,
		struct relay_connection *conn,
		const struct lttng_buffer_view *payload)
{
	int ret;
	ssize_t send_ret;
	struct relay_session *session = conn->session;
	struct lttcomm_relayd_reset_metadata stream_info;
	struct lttcomm_relayd_generic_reply reply;
	struct relay_stream *stream;

	DBG("Reset metadata received");

	if (!session || !conn->version_check_done) {
		ERR("Trying to reset a metadata stream before version check");
		ret = -1;
		goto end_no_session;
	}

	if (payload->size < sizeof(stream_info)) {
		ERR("Unexpected payload size in \"relay_reset_metadata\": expected >= %zu bytes, got %zu bytes",
				sizeof(stream_info), payload->size);
		ret = -1;
		goto end_no_session;
	}
	memcpy(&stream_info, payload->data, sizeof(stream_info));
	stream_info.stream_id = be64toh(stream_info.stream_id);
	stream_info.version = be64toh(stream_info.version);

	DBG("Update metadata to version %" PRIu64, stream_info.version);

	/* Unsupported for live sessions for now. */
	if (session->live_timer != 0) {
		ret = -1;
		goto end;
	}

	stream = stream_get_by_id(stream_info.stream_id);
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
	if (send_ret < (ssize_t) sizeof(reply)) {
		ERR("Failed to send \"reset metadata\" command reply (ret = %zd)",
				send_ret);
		ret = -1;
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
	ssize_t send_ret;

	memset(&reply, 0, sizeof(reply));
	reply.ret_code = htobe32(LTTNG_ERR_UNK);
	send_ret = conn->sock->ops->sendmsg(conn->sock, &reply, sizeof(reply), 0);
	if (send_ret < sizeof(reply)) {
		ERR("Failed to send \"unknown command\" command reply (ret = %zd)", send_ret);
	}
}

/*
 * relay_start: send an acknowledgment to the client to tell if we are
 * ready to receive data. We are ready if a session is established.
 */
static int relay_start(const struct lttcomm_relayd_hdr *recv_hdr,
		struct relay_connection *conn,
		const struct lttng_buffer_view *payload)
{
	int ret = 0;
	ssize_t send_ret;
	struct lttcomm_relayd_generic_reply reply;
	struct relay_session *session = conn->session;

	if (!session) {
		DBG("Trying to start the streaming without a session established");
		ret = htobe32(LTTNG_ERR_UNK);
	}

	memset(&reply, 0, sizeof(reply));
	reply.ret_code = htobe32(LTTNG_OK);
	send_ret = conn->sock->ops->sendmsg(conn->sock, &reply,
			sizeof(reply), 0);
	if (send_ret < (ssize_t) sizeof(reply)) {
		ERR("Failed to send \"relay_start\" command reply (ret = %zd)",
				send_ret);
		ret = -1;
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
 * Close the current index file if it is open, and create a new one.
 *
 * Return 0 on success, -1 on error.
 */
static
int create_rotate_index_file(struct relay_stream *stream)
{
	int ret;
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
		goto end;
	}

	ret = 0;

end:
	return ret;
}

static
int do_rotate_stream(struct relay_stream *stream)
{
	int ret;

	/* Perform the stream rotation. */
	ret = utils_rotate_stream_file(stream->path_name,
			stream->channel_name, stream->tracefile_size,
			stream->tracefile_count, -1,
			-1, stream->stream_fd->fd,
			NULL, &stream->stream_fd->fd);
	if (ret < 0) {
		ERR("Rotating stream output file");
		goto end;
	}
	stream->tracefile_size_current = 0;

	/* Rotate also the index if the stream is not a metadata stream. */
	if (!stream->is_metadata) {
		ret = create_rotate_index_file(stream);
		if (ret < 0) {
			ERR("Failed to rotate index file");
			goto end;
		}
	}

	stream->rotate_at_seq_num = -1ULL;
	stream->pos_after_last_complete_data_index = 0;

end:
	return ret;
}

/*
 * If too much data has been written in a tracefile before we received the
 * rotation command, we have to move the excess data to the new tracefile and
 * perform the rotation. This can happen because the control and data
 * connections are separate, the indexes as well as the commands arrive from
 * the control connection and we have no control over the order so we could be
 * in a situation where too much data has been received on the data connection
 * before the rotation command on the control connection arrives. We don't need
 * to update the index because its order is guaranteed with the rotation
 * command message.
 */
static
int rotate_truncate_stream(struct relay_stream *stream)
{
	int ret, new_fd;
	off_t lseek_ret;
	uint64_t diff, pos = 0;
	char buf[FILE_COPY_BUFFER_SIZE];

	assert(!stream->is_metadata);

	assert(stream->tracefile_size_current >
			stream->pos_after_last_complete_data_index);
	diff = stream->tracefile_size_current -
			stream->pos_after_last_complete_data_index;

	/* Create the new tracefile. */
	new_fd = utils_create_stream_file(stream->path_name,
			stream->channel_name,
			stream->tracefile_size, stream->tracefile_count,
			/* uid */ -1, /* gid */ -1, /* suffix */ NULL);
	if (new_fd < 0) {
		ERR("Failed to create new stream file at path %s for channel %s",
				stream->path_name, stream->channel_name);
		ret = -1;
		goto end;
	}

	/*
	 * Rewind the current tracefile to the position at which the rotation
	 * should have occured.
	 */
	lseek_ret = lseek(stream->stream_fd->fd,
			stream->pos_after_last_complete_data_index, SEEK_SET);
	if (lseek_ret < 0) {
		PERROR("seek truncate stream");
		ret = -1;
		goto end;
	}

	/* Move data from the old file to the new file. */
	while (pos < diff) {
		uint64_t count, bytes_left;
		ssize_t io_ret;

		bytes_left = diff - pos;
		count = bytes_left > sizeof(buf) ? sizeof(buf) : bytes_left;
		assert(count <= SIZE_MAX);

		io_ret = lttng_read(stream->stream_fd->fd, buf, count);
		if (io_ret < (ssize_t) count) {
			char error_string[256];

			snprintf(error_string, sizeof(error_string),
					"Failed to read %" PRIu64 " bytes from fd %i in rotate_truncate_stream(), returned %zi",
					count, stream->stream_fd->fd, io_ret);
			if (io_ret == -1) {
				PERROR("%s", error_string);
			} else {
				ERR("%s", error_string);
			}
			ret = -1;
			goto end;
		}

		io_ret = lttng_write(new_fd, buf, count);
		if (io_ret < (ssize_t) count) {
			char error_string[256];

			snprintf(error_string, sizeof(error_string),
					"Failed to write %" PRIu64 " bytes from fd %i in rotate_truncate_stream(), returned %zi",
					count, new_fd, io_ret);
			if (io_ret == -1) {
				PERROR("%s", error_string);
			} else {
				ERR("%s", error_string);
			}
			ret = -1;
			goto end;
		}

		pos += count;
	}

	/* Truncate the file to get rid of the excess data. */
	ret = ftruncate(stream->stream_fd->fd,
			stream->pos_after_last_complete_data_index);
	if (ret) {
		PERROR("ftruncate");
		goto end;
	}

	ret = close(stream->stream_fd->fd);
	if (ret < 0) {
		PERROR("Closing tracefile");
		goto end;
	}

	ret = create_rotate_index_file(stream);
	if (ret < 0) {
		ERR("Rotate stream index file");
		goto end;
	}

	/*
	 * Update the offset and FD of all the eventual indexes created by the
	 * data connection before the rotation command arrived.
	 */
	ret = relay_index_switch_all_files(stream);
	if (ret < 0) {
		ERR("Failed to rotate index file");
		goto end;
	}

	stream->stream_fd->fd = new_fd;
	stream->tracefile_size_current = diff;
	stream->pos_after_last_complete_data_index = 0;
	stream->rotate_at_seq_num = -1ULL;

	ret = 0;

end:
	return ret;
}

/*
 * Check if a stream should perform a rotation (for session rotation).
 * Must be called with the stream lock held.
 *
 * Return 0 on success, a negative value on error.
 */
static
int try_rotate_stream(struct relay_stream *stream)
{
	int ret = 0;

	/* No rotation expected. */
	if (stream->rotate_at_seq_num == -1ULL) {
		goto end;
	}

	if (stream->prev_seq < stream->rotate_at_seq_num ||
			stream->prev_seq == -1ULL) {
		DBG("Stream %" PRIu64 " no yet ready for rotation",
				stream->stream_handle);
		goto end;
	} else if (stream->prev_seq > stream->rotate_at_seq_num) {
		DBG("Rotation after too much data has been written in tracefile "
				"for stream %" PRIu64 ", need to truncate before "
				"rotating", stream->stream_handle);
		ret = rotate_truncate_stream(stream);
		if (ret) {
			ERR("Failed to truncate stream");
			goto end;
		}
	} else {
		/* stream->prev_seq == stream->rotate_at_seq_num */
		DBG("Stream %" PRIu64 " ready for rotation",
				stream->stream_handle);
		ret = do_rotate_stream(stream);
	}

end:
	return ret;
}

/*
 * relay_recv_metadata: receive the metadata for the session.
 */
static int relay_recv_metadata(const struct lttcomm_relayd_hdr *recv_hdr,
		struct relay_connection *conn,
		const struct lttng_buffer_view *payload)
{
	int ret = 0;
	ssize_t size_ret;
	struct relay_session *session = conn->session;
	struct lttcomm_relayd_metadata_payload metadata_payload_header;
	struct relay_stream *metadata_stream;
	uint64_t metadata_payload_size;

	if (!session) {
		ERR("Metadata sent before version check");
		ret = -1;
		goto end;
	}

	if (recv_hdr->data_size < sizeof(struct lttcomm_relayd_metadata_payload)) {
		ERR("Incorrect data size");
		ret = -1;
		goto end;
	}
	metadata_payload_size = recv_hdr->data_size -
			sizeof(struct lttcomm_relayd_metadata_payload);

	memcpy(&metadata_payload_header, payload->data,
			sizeof(metadata_payload_header));
	metadata_payload_header.stream_id = be64toh(
			metadata_payload_header.stream_id);
	metadata_payload_header.padding_size = be32toh(
			metadata_payload_header.padding_size);

	metadata_stream = stream_get_by_id(metadata_payload_header.stream_id);
	if (!metadata_stream) {
		ret = -1;
		goto end;
	}

	pthread_mutex_lock(&metadata_stream->lock);

	size_ret = lttng_write(metadata_stream->stream_fd->fd,
			payload->data + sizeof(metadata_payload_header),
			metadata_payload_size);
	if (size_ret < metadata_payload_size) {
		ERR("Relay error writing metadata on file");
		ret = -1;
		goto end_put;
	}

	size_ret = write_padding_to_file(metadata_stream->stream_fd->fd,
			metadata_payload_header.padding_size);
	if (size_ret < 0) {
		ret = -1;
		goto end_put;
	}

	metadata_stream->metadata_received +=
		metadata_payload_size + metadata_payload_header.padding_size;
	DBG2("Relay metadata written. Updated metadata_received %" PRIu64,
		metadata_stream->metadata_received);

	ret = try_rotate_stream(metadata_stream);
	if (ret < 0) {
		goto end_put;
	}

end_put:
	pthread_mutex_unlock(&metadata_stream->lock);
	stream_put(metadata_stream);
end:
	return ret;
}

/*
 * relay_send_version: send relayd version number
 */
static int relay_send_version(const struct lttcomm_relayd_hdr *recv_hdr,
		struct relay_connection *conn,
		const struct lttng_buffer_view *payload)
{
	int ret;
	ssize_t send_ret;
	struct lttcomm_relayd_version reply, msg;
	bool compatible = true;

	conn->version_check_done = true;

	/* Get version from the other side. */
	if (payload->size < sizeof(msg)) {
		ERR("Unexpected payload size in \"relay_send_version\": expected >= %zu bytes, got %zu bytes",
				sizeof(msg), payload->size);
		ret = -1;
		goto end;
	}

	memcpy(&msg, payload->data, sizeof(msg));
	msg.major = be32toh(msg.major);
	msg.minor = be32toh(msg.minor);

	memset(&reply, 0, sizeof(reply));
	reply.major = RELAYD_VERSION_COMM_MAJOR;
	reply.minor = RELAYD_VERSION_COMM_MINOR;

	/* Major versions must be the same */
	if (reply.major != msg.major) {
		DBG("Incompatible major versions (%u vs %u), deleting session",
				reply.major, msg.major);
		compatible = false;
	}

	conn->major = reply.major;
	/* We adapt to the lowest compatible version */
	if (reply.minor <= msg.minor) {
		conn->minor = reply.minor;
	} else {
		conn->minor = msg.minor;
	}

	reply.major = htobe32(reply.major);
	reply.minor = htobe32(reply.minor);
	send_ret = conn->sock->ops->sendmsg(conn->sock, &reply,
			sizeof(reply), 0);
	if (send_ret < (ssize_t) sizeof(reply)) {
		ERR("Failed to send \"send version\" command reply (ret = %zd)",
				send_ret);
		ret = -1;
		goto end;
	} else {
		ret = 0;
	}

	if (!compatible) {
		ret = -1;
		goto end;
	}

	DBG("Version check done using protocol %u.%u", conn->major,
			conn->minor);

end:
	return ret;
}

/*
 * Check for data pending for a given stream id from the session daemon.
 */
static int relay_data_pending(const struct lttcomm_relayd_hdr *recv_hdr,
		struct relay_connection *conn,
		const struct lttng_buffer_view *payload)
{
	struct relay_session *session = conn->session;
	struct lttcomm_relayd_data_pending msg;
	struct lttcomm_relayd_generic_reply reply;
	struct relay_stream *stream;
	ssize_t send_ret;
	int ret;

	DBG("Data pending command received");

	if (!session || !conn->version_check_done) {
		ERR("Trying to check for data before version check");
		ret = -1;
		goto end_no_session;
	}

	if (payload->size < sizeof(msg)) {
		ERR("Unexpected payload size in \"relay_data_pending\": expected >= %zu bytes, got %zu bytes",
				sizeof(msg), payload->size);
		ret = -1;
		goto end_no_session;
	}
	memcpy(&msg, payload->data, sizeof(msg));
	msg.stream_id = be64toh(msg.stream_id);
	msg.last_net_seq_num = be64toh(msg.last_net_seq_num);

	stream = stream_get_by_id(msg.stream_id);
	if (stream == NULL) {
		ret = -1;
		goto end;
	}

	pthread_mutex_lock(&stream->lock);

	DBG("Data pending for stream id %" PRIu64 " prev_seq %" PRIu64
			" and last_seq %" PRIu64, msg.stream_id,
			stream->prev_seq, msg.last_net_seq_num);

	/* Avoid wrapping issue */
	if (((int64_t) (stream->prev_seq - msg.last_net_seq_num)) >= 0) {
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
	send_ret = conn->sock->ops->sendmsg(conn->sock, &reply, sizeof(reply), 0);
	if (send_ret < (ssize_t) sizeof(reply)) {
		ERR("Failed to send \"data pending\" command reply (ret = %zd)",
				send_ret);
		ret = -1;
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
static int relay_quiescent_control(const struct lttcomm_relayd_hdr *recv_hdr,
		struct relay_connection *conn,
		const struct lttng_buffer_view *payload)
{
	int ret;
	ssize_t send_ret;
	struct relay_stream *stream;
	struct lttcomm_relayd_quiescent_control msg;
	struct lttcomm_relayd_generic_reply reply;

	DBG("Checking quiescent state on control socket");

	if (!conn->session || !conn->version_check_done) {
		ERR("Trying to check for data before version check");
		ret = -1;
		goto end_no_session;
	}

	if (payload->size < sizeof(msg)) {
		ERR("Unexpected payload size in \"relay_quiescent_control\": expected >= %zu bytes, got %zu bytes",
				sizeof(msg), payload->size);
		ret = -1;
		goto end_no_session;
	}
	memcpy(&msg, payload->data, sizeof(msg));
	msg.stream_id = be64toh(msg.stream_id);

	stream = stream_get_by_id(msg.stream_id);
	if (!stream) {
		goto reply;
	}
	pthread_mutex_lock(&stream->lock);
	stream->data_pending_check_done = true;
	pthread_mutex_unlock(&stream->lock);

	DBG("Relay quiescent control pending flag set to %" PRIu64, msg.stream_id);
	stream_put(stream);
reply:
	memset(&reply, 0, sizeof(reply));
	reply.ret_code = htobe32(LTTNG_OK);
	send_ret = conn->sock->ops->sendmsg(conn->sock, &reply, sizeof(reply), 0);
	if (send_ret < (ssize_t) sizeof(reply)) {
		ERR("Failed to send \"quiescent control\" command reply (ret = %zd)",
				send_ret);
		ret = -1;
	} else {
		ret = 0;
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
static int relay_begin_data_pending(const struct lttcomm_relayd_hdr *recv_hdr,
		struct relay_connection *conn,
		const struct lttng_buffer_view *payload)
{
	int ret;
	ssize_t send_ret;
	struct lttng_ht_iter iter;
	struct lttcomm_relayd_begin_data_pending msg;
	struct lttcomm_relayd_generic_reply reply;
	struct relay_stream *stream;

	assert(recv_hdr);
	assert(conn);

	DBG("Init streams for data pending");

	if (!conn->session || !conn->version_check_done) {
		ERR("Trying to check for data before version check");
		ret = -1;
		goto end_no_session;
	}

	if (payload->size < sizeof(msg)) {
		ERR("Unexpected payload size in \"relay_begin_data_pending\": expected >= %zu bytes, got %zu bytes",
				sizeof(msg), payload->size);
		ret = -1;
		goto end_no_session;
	}
	memcpy(&msg, payload->data, sizeof(msg));
	msg.session_id = be64toh(msg.session_id);

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
		if (stream->trace->session->id == msg.session_id) {
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

	send_ret = conn->sock->ops->sendmsg(conn->sock, &reply, sizeof(reply), 0);
	if (send_ret < (ssize_t) sizeof(reply)) {
		ERR("Failed to send \"begin data pending\" command reply (ret = %zd)",
			send_ret);
		ret = -1;
	} else {
		ret = 0;
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
static int relay_end_data_pending(const struct lttcomm_relayd_hdr *recv_hdr,
		struct relay_connection *conn,
		const struct lttng_buffer_view *payload)
{
	int ret;
	ssize_t send_ret;
	struct lttng_ht_iter iter;
	struct lttcomm_relayd_end_data_pending msg;
	struct lttcomm_relayd_generic_reply reply;
	struct relay_stream *stream;
	uint32_t is_data_inflight = 0;

	DBG("End data pending command");

	if (!conn->session || !conn->version_check_done) {
		ERR("Trying to check for data before version check");
		ret = -1;
		goto end_no_session;
	}

	if (payload->size < sizeof(msg)) {
		ERR("Unexpected payload size in \"relay_end_data_pending\": expected >= %zu bytes, got %zu bytes",
				sizeof(msg), payload->size);
		ret = -1;
		goto end_no_session;
	}
	memcpy(&msg, payload->data, sizeof(msg));
	msg.session_id = be64toh(msg.session_id);

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
		if (stream->trace->session->id != msg.session_id) {
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

	send_ret = conn->sock->ops->sendmsg(conn->sock, &reply, sizeof(reply), 0);
	if (send_ret < (ssize_t) sizeof(reply)) {
		ERR("Failed to send \"end data pending\" command reply (ret = %zd)",
			send_ret);
		ret = -1;
	} else {
		ret = 0;
	}

end_no_session:
	return ret;
}

/*
 * Receive an index for a specific stream.
 *
 * Return 0 on success else a negative value.
 */
static int relay_recv_index(const struct lttcomm_relayd_hdr *recv_hdr,
		struct relay_connection *conn,
		const struct lttng_buffer_view *payload)
{
	int ret;
	ssize_t send_ret;
	struct relay_session *session = conn->session;
	struct lttcomm_relayd_index index_info;
	struct relay_index *index;
	struct lttcomm_relayd_generic_reply reply;
	struct relay_stream *stream;
	size_t msg_len;

	assert(conn);

	DBG("Relay receiving index");

	if (!session || !conn->version_check_done) {
		ERR("Trying to close a stream before version check");
		ret = -1;
		goto end_no_session;
	}

	msg_len = lttcomm_relayd_index_len(
			lttng_to_index_major(conn->major, conn->minor),
			lttng_to_index_minor(conn->major, conn->minor));
	if (payload->size < msg_len) {
		ERR("Unexpected payload size in \"relay_recv_index\": expected >= %zu bytes, got %zu bytes",
				msg_len, payload->size);
		ret = -1;
		goto end_no_session;
	}
	memcpy(&index_info, payload->data, msg_len);
	index_info.relay_stream_id = be64toh(index_info.relay_stream_id);
	index_info.net_seq_num = be64toh(index_info.net_seq_num);
	index_info.packet_size = be64toh(index_info.packet_size);
	index_info.content_size = be64toh(index_info.content_size);
	index_info.timestamp_begin = be64toh(index_info.timestamp_begin);
	index_info.timestamp_end = be64toh(index_info.timestamp_end);
	index_info.events_discarded = be64toh(index_info.events_discarded);
	index_info.stream_id = be64toh(index_info.stream_id);
	index_info.stream_instance_id = be64toh(index_info.stream_instance_id);
	index_info.packet_seq_num = be64toh(index_info.packet_seq_num);

	stream = stream_get_by_id(index_info.relay_stream_id);
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
			stream->beacon_ts_end = index_info.timestamp_end;
		}
		ret = 0;
		goto end_stream_put;
	} else {
		stream->beacon_ts_end = -1ULL;
	}

	if (stream->ctf_stream_id == -1ULL) {
		stream->ctf_stream_id = index_info.stream_id;
	}
	index = relay_index_get_by_id_or_create(stream, index_info.net_seq_num);
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
		stream->pos_after_last_complete_data_index += index->total_size;
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
	if (send_ret < (ssize_t) sizeof(reply)) {
		ERR("Failed to send \"recv index\" command reply (ret = %zd)", send_ret);
		ret = -1;
	}

end_no_session:
	return ret;
}

/*
 * Receive the streams_sent message.
 *
 * Return 0 on success else a negative value.
 */
static int relay_streams_sent(const struct lttcomm_relayd_hdr *recv_hdr,
		struct relay_connection *conn,
		const struct lttng_buffer_view *payload)
{
	int ret;
	ssize_t send_ret;
	struct lttcomm_relayd_generic_reply reply;

	assert(conn);

	DBG("Relay receiving streams_sent");

	if (!conn->session || !conn->version_check_done) {
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
	if (send_ret < (ssize_t) sizeof(reply)) {
		ERR("Failed to send \"streams sent\" command reply (ret = %zd)",
			send_ret);
		ret = -1;
	} else {
		/* Success. */
		ret = 0;
	}

end_no_session:
	return ret;
}

/*
 * relay_rotate_session_stream: rotate a stream to a new tracefile for the session
 * rotation feature (not the tracefile rotation feature).
 */
static int relay_rotate_session_stream(const struct lttcomm_relayd_hdr *recv_hdr,
		struct relay_connection *conn,
		const struct lttng_buffer_view *payload)
{
	int ret;
	ssize_t send_ret;
	struct relay_session *session = conn->session;
	struct lttcomm_relayd_rotate_stream stream_info;
	struct lttcomm_relayd_generic_reply reply;
	struct relay_stream *stream;
	size_t header_len;
	size_t path_len;
	struct lttng_buffer_view new_path_view;

	DBG("Rotate stream received");

	if (!session || !conn->version_check_done) {
		ERR("Trying to rotate a stream before version check");
		ret = -1;
		goto end_no_reply;
	}

	if (session->major == 2 && session->minor < 11) {
		ERR("Unsupported feature before 2.11");
		ret = -1;
		goto end_no_reply;
	}

	header_len = sizeof(struct lttcomm_relayd_rotate_stream);

	if (payload->size < header_len) {
		ERR("Unexpected payload size in \"relay_rotate_session_stream\": expected >= %zu bytes, got %zu bytes",
				header_len, payload->size);
		ret = -1;
		goto end_no_reply;
	}

	memcpy(&stream_info, payload->data, header_len);

	/* Convert to host */
	stream_info.pathname_length = be32toh(stream_info.pathname_length);
	stream_info.stream_id = be64toh(stream_info.stream_id);
	stream_info.new_chunk_id = be64toh(stream_info.new_chunk_id);
	stream_info.rotate_at_seq_num = be64toh(stream_info.rotate_at_seq_num);

	path_len = stream_info.pathname_length;
	if (payload->size < header_len + path_len) {
		ERR("Unexpected payload size in \"relay_rotate_session_stream\" including path: expected >= %zu bytes, got %zu bytes",
				header_len + path_len, payload->size);
		ret = -1;
		goto end_no_reply;
	}	
	
	/* Ensure it fits in local filename length. */
	if (path_len >= LTTNG_PATH_MAX) {
		ret = -ENAMETOOLONG;
		ERR("Length of relay_rotate_session_stream command's path name (%zu bytes) exceeds the maximal allowed length of %i bytes",
				path_len, LTTNG_PATH_MAX);
		goto end;
	}

	new_path_view = lttng_buffer_view_from_view(payload, header_len,
			stream_info.pathname_length);

	stream = stream_get_by_id(stream_info.stream_id);
	if (!stream) {
		ret = -1;
		goto end;
	}

	pthread_mutex_lock(&stream->lock);

	/*
	 * Update the trace path (just the folder, the stream name does not
	 * change).
	 */
	free(stream->path_name);
	stream->path_name = create_output_path(new_path_view.data);
	if (!stream->path_name) {
		ERR("Failed to create a new output path");
		ret = -1;
		goto end_stream_unlock;
	}
	ret = utils_mkdir_recursive(stream->path_name, S_IRWXU | S_IRWXG,
			-1, -1);
	if (ret < 0) {
		ERR("relay creating output directory");
		ret = -1;
		goto end_stream_unlock;
	}

	stream->chunk_id = stream_info.new_chunk_id;

	if (stream->is_metadata) {
		/*
		 * The metadata stream is sent only over the control connection
		 * so we know we have all the data to perform the stream
		 * rotation.
		 */
		ret = do_rotate_stream(stream);
	} else {
		stream->rotate_at_seq_num = stream_info.rotate_at_seq_num;
		ret = try_rotate_stream(stream);
	}
	if (ret < 0) {
		goto end_stream_unlock;
	}

end_stream_unlock:
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
	if (send_ret < (ssize_t) sizeof(reply)) {
		ERR("Failed to send \"rotate session stream\" command reply (ret = %zd)",
				send_ret);
		ret = -1;
	}

end_no_reply:
	return ret;
}

/*
 * relay_mkdir: Create a folder on the disk.
 */
static int relay_mkdir(const struct lttcomm_relayd_hdr *recv_hdr,
		struct relay_connection *conn,
		const struct lttng_buffer_view *payload)
{
	int ret;
	struct relay_session *session = conn->session;
	struct lttcomm_relayd_mkdir path_info_header;
	struct lttcomm_relayd_generic_reply reply;
	char *path = NULL;
	size_t header_len;
	ssize_t send_ret;
	struct lttng_buffer_view path_view;

	if (!session || !conn->version_check_done) {
		ERR("Trying to create a directory before version check");
		ret = -1;
		goto end_no_session;
	}

	if (session->major == 2 && session->minor < 11) {
		/*
		 * This client is not supposed to use this command since
		 * it predates its introduction.
		 */
		ERR("relay_mkdir command is unsupported before LTTng 2.11");
		ret = -1;
		goto end_no_session;
	}

	header_len = sizeof(path_info_header);
	if (payload->size < header_len) {
		ERR("Unexpected payload size in \"relay_mkdir\": expected >= %zu bytes, got %zu bytes",
				header_len, payload->size);
		ret = -1;
		goto end_no_session;
	}

	memcpy(&path_info_header, payload->data, header_len);

	path_info_header.length = be32toh(path_info_header.length);

	if (payload->size < header_len + path_info_header.length) {
		ERR("Unexpected payload size in \"relay_mkdir\" including path: expected >= %zu bytes, got %zu bytes",
				header_len + path_info_header.length, payload->size);
		ret = -1;
		goto end_no_session;
	}

	/* Ensure that it fits in local path length. */
	if (path_info_header.length >= LTTNG_PATH_MAX) {
		ret = -ENAMETOOLONG;
		ERR("Path name argument of mkdir command (%" PRIu32 " bytes) exceeds the maximal length allowed (%d bytes)",
				path_info_header.length, LTTNG_PATH_MAX);
		goto end;
	}

	path_view = lttng_buffer_view_from_view(payload, header_len,
			path_info_header.length);

	path = create_output_path(path_view.data);
	if (!path) {
		ERR("Failed to create output path");
		ret = -1;
		goto end;
	}

	ret = utils_mkdir_recursive(path, S_IRWXU | S_IRWXG, -1, -1);
	if (ret < 0) {
		ERR("relay creating output directory");
		goto end;
	}

	ret = 0;

end:
	memset(&reply, 0, sizeof(reply));
	if (ret < 0) {
		reply.ret_code = htobe32(LTTNG_ERR_UNK);
	} else {
		reply.ret_code = htobe32(LTTNG_OK);
	}
	send_ret = conn->sock->ops->sendmsg(conn->sock, &reply, sizeof(reply), 0);
	if (send_ret < (ssize_t) sizeof(reply)) {
		ERR("Failed to send \"mkdir\" command reply (ret = %zd)", send_ret);
		ret = -1;
	}

end_no_session:
	free(path);
	return ret;
}

static int validate_rotate_rename_path_length(const char *path_type,
		uint32_t path_length)
{
	int ret = 0;

	if (path_length > LTTNG_PATH_MAX) {
		ret = -ENAMETOOLONG;
		ERR("rotate rename \"%s\" path name length (%" PRIu32 " bytes) exceeds the allowed size of %i bytes",
				path_type, path_length, LTTNG_PATH_MAX);
	} else if (path_length == 0) {
		ret = -EINVAL;
		ERR("rotate rename \"%s\" path name has an illegal length of 0", path_type);
	}
	return ret;
}

/*
 * relay_rotate_rename: rename the trace folder after a rotation is
 * completed. We are not closing any fd here, just moving the folder, so it
 * works even if data is still in-flight.
 */
static int relay_rotate_rename(const struct lttcomm_relayd_hdr *recv_hdr,
		struct relay_connection *conn,
		const struct lttng_buffer_view *payload)
{
	int ret;
	ssize_t send_ret;
	struct relay_session *session = conn->session;
	struct lttcomm_relayd_generic_reply reply;
	struct lttcomm_relayd_rotate_rename header;
	size_t header_len;
	size_t received_paths_size;
	char *complete_old_path = NULL, *complete_new_path = NULL;
	struct lttng_buffer_view old_path_view;
	struct lttng_buffer_view new_path_view;

	if (!session || !conn->version_check_done) {
		ERR("Trying to rename a trace folder before version check");
		ret = -1;
		goto end_no_reply;
	}

	if (session->major == 2 && session->minor < 11) {
		ERR("relay_rotate_rename command is unsupported before LTTng 2.11");
		ret = -1;
		goto end_no_reply;
	}

	header_len = sizeof(header);
	if (payload->size < header_len) {
		ERR("Unexpected payload size in \"relay_rotate_rename\": expected >= %zu bytes, got %zu bytes",
				header_len, payload->size);
		ret = -1;
		goto end_no_reply;
	}

	memcpy(&header, payload->data, header_len);

	header.old_path_length = be32toh(header.old_path_length);
	header.new_path_length = be32toh(header.new_path_length);
	received_paths_size = header.old_path_length + header.new_path_length;

	if (payload->size < header_len + received_paths_size) {
		ERR("Unexpected payload size in \"relay_rotate_rename\" including paths: expected >= %zu bytes, got %zu bytes",
				header_len, payload->size);
		ret = -1;
		goto end_no_reply;
	}

	/* Ensure the paths don't exceed their allowed size. */
	ret = validate_rotate_rename_path_length("old", header.old_path_length);
	if (ret) {
		goto end;
	}
	ret = validate_rotate_rename_path_length("new", header.new_path_length);
	if (ret) {
		goto end;
	}

	old_path_view = lttng_buffer_view_from_view(payload, header_len,
			header.old_path_length);
	new_path_view = lttng_buffer_view_from_view(payload,
		        header_len + header.old_path_length,
		        header.new_path_length);

	/* Validate that both paths received are NULL terminated. */
	if (old_path_view.data[old_path_view.size - 1] != '\0') {
		ERR("relay_rotate_rename command's \"old\" path is invalid (not NULL terminated)");
		ret = -1;
		goto end;
	}
	if (new_path_view.data[new_path_view.size - 1] != '\0') {
		ERR("relay_rotate_rename command's \"new\" path is invalid (not NULL terminated)");
		ret = -1;
		goto end;
	}

	complete_old_path = create_output_path(old_path_view.data);
	if (!complete_old_path) {
		ERR("Failed to build old output path in rotate_rename command");
		ret = -1;
		goto end;
	}

	complete_new_path = create_output_path(new_path_view.data);
	if (!complete_new_path) {
		ERR("Failed to build new output path in rotate_rename command");
		ret = -1;
		goto end;
	}

	ret = utils_mkdir_recursive(complete_new_path, S_IRWXU | S_IRWXG,
			-1, -1);
	if (ret < 0) {
		ERR("Failed to mkdir() rotate_rename's \"new\" output directory at \"%s\"",
				complete_new_path);
		goto end;
	}

	/*
	 * If a domain has not yet created its channel, the domain-specific
	 * folder might not exist, but this is not an error.
	 */
	ret = rename(complete_old_path, complete_new_path);
	if (ret < 0 && errno != ENOENT) {
		PERROR("Renaming chunk in rotate_rename command from \"%s\" to \"%s\"",
				complete_old_path, complete_new_path);
		goto end;
	}
	ret = 0;

end:
	memset(&reply, 0, sizeof(reply));
	if (ret < 0) {
		reply.ret_code = htobe32(LTTNG_ERR_UNK);
	} else {
		reply.ret_code = htobe32(LTTNG_OK);
	}
	send_ret = conn->sock->ops->sendmsg(conn->sock, &reply,
			sizeof(reply), 0);
	if (send_ret < sizeof(reply)) {
		ERR("Failed to send \"rotate rename\" command reply (ret = %zd)",
				send_ret);
		ret = -1;
	}

end_no_reply:
	free(complete_old_path);
	free(complete_new_path);
	return ret;
}

/*
 * Check if all the streams in the session have completed the last rotation.
 * The chunk_id value is used to distinguish the cases where a stream was
 * closed on the consumerd before the rotation started but it still active on
 * the relayd, and the case where a stream appeared on the consumerd/relayd
 * after the last rotation started (in that case, it is already writing in the
 * new chunk folder).
 */
static
int relay_rotate_pending(const struct lttcomm_relayd_hdr *recv_hdr,
		struct relay_connection *conn,
		const struct lttng_buffer_view *payload)
{
	struct relay_session *session = conn->session;
	struct lttcomm_relayd_rotate_pending msg;
	struct lttcomm_relayd_rotate_pending_reply reply;
	struct lttng_ht_iter iter;
	struct relay_stream *stream;
	int ret = 0;
	ssize_t send_ret;
	uint64_t chunk_id;
        bool rotate_pending = false;

	DBG("Rotate pending command received");

	if (!session || !conn->version_check_done) {
		ERR("Trying to check for data before version check");
		ret = -1;
		goto end_no_reply;
	}

	if (session->major == 2 && session->minor < 11) {
		ERR("Unsupported feature before 2.11");
		ret = -1;
		goto end_no_reply;
	}

	if (payload->size < sizeof(msg)) {
		ERR("Unexpected payload size in \"relay_rotate_pending\": expected >= %zu bytes, got %zu bytes",
				sizeof(msg), payload->size);
		ret = -1;
		goto end_no_reply;
	}

	memcpy(&msg, payload->data, sizeof(msg));

	chunk_id = be64toh(msg.chunk_id);

	DBG("Evaluating rotate pending for chunk id %" PRIu64, chunk_id);

	/*
	 * Iterate over all the streams in the session and check if they are
	 * still waiting for data to perform their rotation.
	 */
	rcu_read_lock();
	cds_lfht_for_each_entry(relay_streams_ht->ht, &iter.iter, stream,
			node.node) {
		if (!stream_get(stream)) {
			continue;
		}
		if (stream->trace->session != session) {
			stream_put(stream);
			continue;
		}
		pthread_mutex_lock(&stream->lock);
		if (stream->rotate_at_seq_num != -1ULL) {
			/* We have not yet performed the rotation. */
			rotate_pending = true;
			DBG("Stream %" PRIu64 " is still rotating",
					stream->stream_handle);
		} else if (stream->chunk_id < chunk_id) {
			/*
			 * Stream closed on the consumer but still active on the
			 * relay.
			 */
			rotate_pending = true;
			DBG("Stream %" PRIu64 " did not exist on the consumer "
					"when the last rotation started, but is"
					"still waiting for data before getting"
					"closed",
					stream->stream_handle);
		}
		pthread_mutex_unlock(&stream->lock);
		stream_put(stream);
		if (rotate_pending) {
			goto send_reply;
		}
	}

send_reply:
	rcu_read_unlock();
	memset(&reply, 0, sizeof(reply));
	reply.generic.ret_code = htobe32((uint32_t) LTTNG_OK);
	reply.is_pending = (uint8_t) !!rotate_pending;
	send_ret = conn->sock->ops->sendmsg(conn->sock, &reply,
			sizeof(reply), 0);
	if (send_ret < (ssize_t) sizeof(reply)) {
		ERR("Failed to send \"rotate pending\" command reply (ret = %zd)",
				send_ret);
		ret = -1;
	}

end_no_reply:
	return ret;
}

#define DBG_CMD(cmd_name, conn) \
		DBG3("Processing \"%s\" command for socket %i", cmd_name, conn->sock->fd);

static int relay_process_control_command(struct relay_connection *conn,
		const struct lttcomm_relayd_hdr *header,
		const struct lttng_buffer_view *payload)
{
	int ret = 0;

	switch (header->cmd) {
	case RELAYD_CREATE_SESSION:
		DBG_CMD("RELAYD_CREATE_SESSION", conn);
		ret = relay_create_session(header, conn, payload);
		break;
	case RELAYD_ADD_STREAM:
		DBG_CMD("RELAYD_ADD_STREAM", conn);
		ret = relay_add_stream(header, conn, payload);
		break;
	case RELAYD_START_DATA:
		DBG_CMD("RELAYD_START_DATA", conn);
		ret = relay_start(header, conn, payload);
		break;
	case RELAYD_SEND_METADATA:
		DBG_CMD("RELAYD_SEND_METADATA", conn);
		ret = relay_recv_metadata(header, conn, payload);
		break;
	case RELAYD_VERSION:
		DBG_CMD("RELAYD_VERSION", conn);
		ret = relay_send_version(header, conn, payload);
		break;
	case RELAYD_CLOSE_STREAM:
		DBG_CMD("RELAYD_CLOSE_STREAM", conn);
		ret = relay_close_stream(header, conn, payload);
		break;
	case RELAYD_DATA_PENDING:
		DBG_CMD("RELAYD_DATA_PENDING", conn);
		ret = relay_data_pending(header, conn, payload);
		break;
	case RELAYD_QUIESCENT_CONTROL:
		DBG_CMD("RELAYD_QUIESCENT_CONTROL", conn);
		ret = relay_quiescent_control(header, conn, payload);
		break;
	case RELAYD_BEGIN_DATA_PENDING:
		DBG_CMD("RELAYD_BEGIN_DATA_PENDING", conn);
		ret = relay_begin_data_pending(header, conn, payload);
		break;
	case RELAYD_END_DATA_PENDING:
		DBG_CMD("RELAYD_END_DATA_PENDING", conn);
		ret = relay_end_data_pending(header, conn, payload);
		break;
	case RELAYD_SEND_INDEX:
		DBG_CMD("RELAYD_SEND_INDEX", conn);
		ret = relay_recv_index(header, conn, payload);
		break;
	case RELAYD_STREAMS_SENT:
		DBG_CMD("RELAYD_STREAMS_SENT", conn);
		ret = relay_streams_sent(header, conn, payload);
		break;
	case RELAYD_RESET_METADATA:
		DBG_CMD("RELAYD_RESET_METADATA", conn);
		ret = relay_reset_metadata(header, conn, payload);
		break;
	case RELAYD_ROTATE_STREAM:
		DBG_CMD("RELAYD_ROTATE_STREAM", conn);
		ret = relay_rotate_session_stream(header, conn, payload);
		break;
	case RELAYD_ROTATE_RENAME:
		DBG_CMD("RELAYD_ROTATE_RENAME", conn);
		ret = relay_rotate_rename(header, conn, payload);
		break;
	case RELAYD_ROTATE_PENDING:
		DBG_CMD("RELAYD_ROTATE_PENDING", conn);
		ret = relay_rotate_pending(header, conn, payload);
		break;
	case RELAYD_MKDIR:
		DBG_CMD("RELAYD_MKDIR", conn);
		ret = relay_mkdir(header, conn, payload);
		break;
	case RELAYD_UPDATE_SYNC_INFO:
	default:
		ERR("Received unknown command (%u)", header->cmd);
		relay_unknown_command(conn);
		ret = -1;
		goto end;
	}

end:
	return ret;
}

static int relay_process_control_receive_payload(struct relay_connection *conn)
{
	int ret = 0;
	struct lttng_dynamic_buffer *reception_buffer =
			&conn->protocol.ctrl.reception_buffer;
	struct ctrl_connection_state_receive_payload *state =
			&conn->protocol.ctrl.state.receive_payload;
	struct lttng_buffer_view payload_view;

	if (state->left_to_receive == 0) {
		/* Short-circuit for payload-less commands. */
		goto reception_complete;
	}

	ret = conn->sock->ops->recvmsg(conn->sock,
			reception_buffer->data + state->received,
			state->left_to_receive, MSG_DONTWAIT);
	if (ret < 0) {
		ERR("Unable to receive command payload on sock %d", conn->sock->fd);
		goto end;
	} else if (ret == 0) {
		DBG("Socket %d performed an orderly shutdown (received EOF)", conn->sock->fd);
		ret = -1;
		goto end;
	}

	assert(ret > 0);
	assert(ret <= state->left_to_receive);

	state->left_to_receive -= ret;
	state->received += ret;

	if (state->left_to_receive > 0) {
		/*
		 * Can't transition to the protocol's next state, wait to
		 * receive the rest of the header.
		 */
		DBG3("Partial reception of control connection protocol payload (received %" PRIu64 " bytes, %" PRIu64 " bytes left to receive, fd = %i)",
				state->received, state->left_to_receive,
				conn->sock->fd);
		ret = 0;
		goto end;
	}

reception_complete:
	DBG("Done receiving control command payload: fd = %i, payload size = %" PRIu64 " bytes",
			conn->sock->fd, state->received);
	/*
	 * The payload required to process the command has been received.
	 * A view to the reception buffer is forwarded to the various
	 * commands and the state of the control is reset on success.
	 *
	 * Commands are responsible for sending their reply to the peer.
	 */
	payload_view = lttng_buffer_view_from_dynamic_buffer(reception_buffer,
			0, -1);
	ret = relay_process_control_command(conn,
			&state->header, &payload_view);
	if (ret < 0) {
		goto end;
	}

	ret = connection_reset_protocol_state(conn);
end:
	return ret;
}

static int relay_process_control_receive_header(struct relay_connection *conn)
{
	int ret = 0;
	struct lttcomm_relayd_hdr header;
	struct lttng_dynamic_buffer *reception_buffer =
			&conn->protocol.ctrl.reception_buffer;
	struct ctrl_connection_state_receive_header *state =
			&conn->protocol.ctrl.state.receive_header;

	assert(state->left_to_receive != 0);

	ret = conn->sock->ops->recvmsg(conn->sock,
			reception_buffer->data + state->received,
			state->left_to_receive, MSG_DONTWAIT);
	if (ret < 0) {
		ERR("Unable to receive control command header on sock %d", conn->sock->fd);
		goto end;
	} else if (ret == 0) {
		DBG("Socket %d performed an orderly shutdown (received EOF)", conn->sock->fd);
		ret = -1;
		goto end;
	}

	assert(ret > 0);
	assert(ret <= state->left_to_receive);

	state->left_to_receive -= ret;
	state->received += ret;

	if (state->left_to_receive > 0) {
		/*
		 * Can't transition to the protocol's next state, wait to
		 * receive the rest of the header.
		 */
		DBG3("Partial reception of control connection protocol header (received %" PRIu64 " bytes, %" PRIu64 " bytes left to receive, fd = %i)",
				state->received, state->left_to_receive,
				conn->sock->fd);
		ret = 0;
		goto end;
	}

	/* Transition to next state: receiving the command's payload. */
	conn->protocol.ctrl.state_id =
			CTRL_CONNECTION_STATE_RECEIVE_PAYLOAD;
	memcpy(&header, reception_buffer->data, sizeof(header));
	header.circuit_id = be64toh(header.circuit_id);
	header.data_size = be64toh(header.data_size);
	header.cmd = be32toh(header.cmd);
	header.cmd_version = be32toh(header.cmd_version);
	memcpy(&conn->protocol.ctrl.state.receive_payload.header,
			&header, sizeof(header));

	DBG("Done receiving control command header: fd = %i, cmd = %" PRIu32 ", cmd_version = %" PRIu32 ", payload size = %" PRIu64 " bytes",
			conn->sock->fd, header.cmd, header.cmd_version,
			header.data_size);

	/* FIXME temporary arbitrary limit on data size. */
	if (header.data_size > (128 * 1024 * 1024)) {
		ERR("Command header indicates a payload (%" PRIu64 " bytes) that exceeds the maximal payload size allowed on a control connection.",
				header.data_size);
		ret = -1;
		goto end;
	}

	conn->protocol.ctrl.state.receive_payload.left_to_receive =
			header.data_size;
	conn->protocol.ctrl.state.receive_payload.received = 0;
	ret = lttng_dynamic_buffer_set_size(reception_buffer,
			header.data_size);
	if (ret) {
		goto end;
	}

	if (header.data_size == 0) {
		/*
		 * Manually invoke the next state as the poll loop
		 * will not wake-up to allow us to proceed further.
		 */
		ret = relay_process_control_receive_payload(conn);
	}
end:
	return ret;
}

/*
 * Process the commands received on the control socket
 */
static int relay_process_control(struct relay_connection *conn)
{
	int ret = 0;

	switch (conn->protocol.ctrl.state_id) {
	case CTRL_CONNECTION_STATE_RECEIVE_HEADER:
		ret = relay_process_control_receive_header(conn);
		break;
	case CTRL_CONNECTION_STATE_RECEIVE_PAYLOAD:
		ret = relay_process_control_receive_payload(conn);
		break;
	default:
		ERR("Unknown control connection protocol state encountered.");
		abort();
	}

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
		bool rotate_index, bool *flushed, uint64_t total_size)
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
		ret = create_rotate_index_file(stream);
		if (ret < 0) {
			ERR("Failed to rotate index");
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
		*flushed = true;
	} else if (ret > 0) {
		index->total_size = total_size;
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

static int relay_process_data_receive_header(struct relay_connection *conn)
{
	int ret;
	struct data_connection_state_receive_header *state =
			&conn->protocol.data.state.receive_header;
	struct lttcomm_relayd_data_hdr header;
	struct relay_stream *stream;

	assert(state->left_to_receive != 0);

	ret = conn->sock->ops->recvmsg(conn->sock,
			state->header_reception_buffer + state->received,
			state->left_to_receive, MSG_DONTWAIT);
	if (ret < 0) {
		ERR("Unable to receive data header on sock %d", conn->sock->fd);
		goto end;
	} else if (ret == 0) {
		/* Orderly shutdown. Not necessary to print an error. */
		DBG("Socket %d performed an orderly shutdown (received EOF)", conn->sock->fd);
		ret = -1;
		goto end;
	}

	assert(ret > 0);
	assert(ret <= state->left_to_receive);

	state->left_to_receive -= ret;
	state->received += ret;

	if (state->left_to_receive > 0) {
		/*
		 * Can't transition to the protocol's next state, wait to
		 * receive the rest of the header.
		 */
		DBG3("Partial reception of data connection header (received %" PRIu64 " bytes, %" PRIu64 " bytes left to receive, fd = %i)",
				state->received, state->left_to_receive,
				conn->sock->fd);
		ret = 0;
		goto end;
	}

	/* Transition to next state: receiving the payload. */
	conn->protocol.data.state_id = DATA_CONNECTION_STATE_RECEIVE_PAYLOAD;

	memcpy(&header, state->header_reception_buffer, sizeof(header));
	header.circuit_id = be64toh(header.circuit_id);
	header.stream_id = be64toh(header.stream_id);
	header.data_size = be32toh(header.data_size);
	header.net_seq_num = be64toh(header.net_seq_num);
	header.padding_size = be32toh(header.padding_size);
	memcpy(&conn->protocol.data.state.receive_payload.header, &header, sizeof(header));

	conn->protocol.data.state.receive_payload.left_to_receive =
			header.data_size;
	conn->protocol.data.state.receive_payload.received = 0;
	conn->protocol.data.state.receive_payload.rotate_index = false;

	DBG("Received data connection header on fd %i: circuit_id = %" PRIu64 ", stream_id = %" PRIu64 ", data_size = %" PRIu32 ", net_seq_num = %" PRIu64 ", padding_size = %" PRIu32,
			conn->sock->fd, header.circuit_id,
			header.stream_id, header.data_size,
			header.net_seq_num, header.padding_size);

	stream = stream_get_by_id(header.stream_id);
	if (!stream) {
		DBG("relay_process_data_receive_payload: Cannot find stream %" PRIu64,
				header.stream_id);
		ret = 0;
		goto end;
	}

	pthread_mutex_lock(&stream->lock);

	/* Check if a rotation is needed. */
	if (stream->tracefile_size > 0 &&
			(stream->tracefile_size_current + header.data_size) >
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
			ERR("Failed to rotate stream output file");
			goto end_stream_unlock;
		}

		/*
		 * Reset current size because we just performed a stream
		 * rotation.
		 */
		stream->tracefile_size_current = 0;
		conn->protocol.data.state.receive_payload.rotate_index = true;
	}

	ret = 0;
end_stream_unlock:
	pthread_mutex_unlock(&stream->lock);
	stream_put(stream);
end:
	return ret;
}

static int relay_process_data_receive_payload(struct relay_connection *conn)
{
	int ret;
	struct relay_stream *stream;
	struct data_connection_state_receive_payload *state =
			&conn->protocol.data.state.receive_payload;
	const size_t chunk_size = RECV_DATA_BUFFER_SIZE;
	char data_buffer[chunk_size];
	bool partial_recv = false;
	bool new_stream = false, close_requested = false, index_flushed = false;
	uint64_t left_to_receive = state->left_to_receive;
	struct relay_session *session;

	stream = stream_get_by_id(state->header.stream_id);
	if (!stream) {
		DBG("relay_process_data_receive_payload: Cannot find stream %" PRIu64,
				state->header.stream_id);
		ret = 0;
		goto end;
	}

	pthread_mutex_lock(&stream->lock);
	session = stream->trace->session;

	DBG3("Receiving data for stream id %" PRIu64 " seqnum %" PRIu64 ", %" PRIu64" bytes received, %" PRIu64 " bytes left to receive",
			state->header.stream_id, state->header.net_seq_num,
			state->received, left_to_receive);

	/*
	 * The size of the "chunk" received on any iteration is bounded by:
	 *   - the data left to receive,
	 *   - the data immediately available on the socket,
	 *   - the on-stack data buffer
	 */
	while (left_to_receive > 0 && !partial_recv) {
		ssize_t write_ret;
		size_t recv_size = min(left_to_receive, chunk_size);

		ret = conn->sock->ops->recvmsg(conn->sock, data_buffer,
				recv_size, MSG_DONTWAIT);
		if (ret < 0) {
			ERR("Socket %d error %d", conn->sock->fd, ret);
			ret = -1;
			goto end_stream_unlock;
		} else if (ret == 0) {
			/* No more data ready to be consumed on socket. */
			DBG3("No more data ready for consumption on data socket of stream id %" PRIu64,
					state->header.stream_id);
			break;
		} else if (ret < (int) recv_size) {
			/*
			 * All the data available on the socket has been
			 * consumed.
			 */
			partial_recv = true;
		}

		recv_size = ret;

		/* Write data to stream output fd. */
		write_ret = lttng_write(stream->stream_fd->fd, data_buffer,
				recv_size);
		if (write_ret < (ssize_t) recv_size) {
			ERR("Relay error writing data to file");
			ret = -1;
			goto end_stream_unlock;
		}

		left_to_receive -= recv_size;
		state->received += recv_size;
		state->left_to_receive = left_to_receive;

		DBG2("Relay wrote %zd bytes to tracefile for stream id %" PRIu64,
				write_ret, stream->stream_handle);
	}

	if (state->left_to_receive > 0) {
		/*
		 * Did not receive all the data expected, wait for more data to
		 * become available on the socket.
		 */
		DBG3("Partial receive on data connection of stream id %" PRIu64 ", %" PRIu64 " bytes received, %" PRIu64 " bytes left to receive",
				state->header.stream_id, state->received,
				state->left_to_receive);
		ret = 0;
		goto end_stream_unlock;
	}

	ret = write_padding_to_file(stream->stream_fd->fd,
			state->header.padding_size);
	if (ret < 0) {
		ERR("write_padding_to_file: fail stream %" PRIu64 " net_seq_num %" PRIu64 " ret %d",
				stream->stream_handle,
				state->header.net_seq_num, ret);
		goto end_stream_unlock;
	}


	if (session->minor >= 4 && !session->snapshot) {
		ret = handle_index_data(stream, state->header.net_seq_num,
				state->rotate_index, &index_flushed, state->header.data_size + state->header.padding_size);
		if (ret < 0) {
			ERR("handle_index_data: fail stream %" PRIu64 " net_seq_num %" PRIu64 " ret %d",
					stream->stream_handle,
					state->header.net_seq_num, ret);
			goto end_stream_unlock;
		}
	}

	stream->tracefile_size_current += state->header.data_size +
			state->header.padding_size;

	if (stream->prev_seq == -1ULL) {
		new_stream = true;
	}
	if (index_flushed) {
		stream->pos_after_last_complete_data_index =
				stream->tracefile_size_current;
	}

	stream->prev_seq = state->header.net_seq_num;

	/*
	 * Resetting the protocol state (to RECEIVE_HEADER) will trash the
	 * contents of *state which are aliased (union) to the same location as
	 * the new state. Don't use it beyond this point.
	 */
	connection_reset_protocol_state(conn);
	state = NULL;

	ret = try_rotate_stream(stream);
	if (ret < 0) {
		goto end_stream_unlock;
	}

end_stream_unlock:
	close_requested = stream->close_requested;
	pthread_mutex_unlock(&stream->lock);
	if (close_requested && left_to_receive == 0) {
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

/*
 * relay_process_data: Process the data received on the data socket
 */
static int relay_process_data(struct relay_connection *conn)
{
	int ret;

	switch (conn->protocol.data.state_id) {
	case DATA_CONNECTION_STATE_RECEIVE_HEADER:
		ret = relay_process_data_receive_header(conn);
		break;
	case DATA_CONNECTION_STATE_RECEIVE_PAYLOAD:
		ret = relay_process_data_receive_payload(conn);
		break;
	default:
		ERR("Unexpected data connection communication state.");
		abort();
	}

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
					ret = relay_process_control(ctrl_conn);
					if (ret < 0) {
						/* Clear the connection on error. */
						relay_thread_close_connection(&events,
								pollfd,
								ctrl_conn);
					}
					seen_control = 1;
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
