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
#include <sys/resource.h>
#include <inttypes.h>
#include <urcu/futex.h>
#include <urcu/uatomic.h>
#include <urcu/rculist.h>
#include <unistd.h>
#include <fcntl.h>
#include <strings.h>
#include <ctype.h>

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
#include <common/string-utils/format.h>
#include <common/fd-tracker/fd-tracker.h>
#include <common/fd-tracker/utils.h>

#include "backward-compatibility-group-by.h"
#include "cmd.h"
#include "connection.h"
#include "ctf-trace.h"
#include "health-relayd.h"
#include "index.h"
#include "live.h"
#include "lttng-relayd.h"
#include "session.h"
#include "sessiond-trace-chunks.h"
#include "stream.h"
#include "tcp_keep_alive.h"
#include "testpoint.h"
#include "tracefile-array.h"
#include "utils.h"
#include "version.h"
#include "viewer-stream.h"

static const char *help_msg =
#ifdef LTTNG_EMBED_HELP
#include <lttng-relayd.8.h>
#else
NULL
#endif
;

enum relay_connection_status {
	RELAY_CONNECTION_STATUS_OK,
	/* An error occurred while processing an event on the connection. */
	RELAY_CONNECTION_STATUS_ERROR,
	/* Connection closed/shutdown cleanly. */
	RELAY_CONNECTION_STATUS_CLOSED,
};

/* command line options */
char *opt_output_path, *opt_working_directory;
static int opt_daemon, opt_background, opt_print_version, opt_allow_clear = 1;
enum relay_group_output_by opt_group_output_by = RELAYD_GROUP_OUTPUT_BY_UNKNOWN;

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

/* Cap of file desriptors to be in simultaneous use by the relay daemon. */
static unsigned int lttng_opt_fd_cap;

/* Global relay stream hash table. */
struct lttng_ht *relay_streams_ht;

/* Global relay viewer stream hash table. */
struct lttng_ht *viewer_streams_ht;

/* Global relay sessions hash table. */
struct lttng_ht *sessions_ht;

/* Relayd health monitoring */
struct health_app *health_relayd;

struct sessiond_trace_chunk_registry *sessiond_trace_chunk_registry;

/* Global fd tracker. */
struct fd_tracker *the_fd_tracker;

static struct option long_options[] = {
	{ "control-port", 1, 0, 'C', },
	{ "data-port", 1, 0, 'D', },
	{ "live-port", 1, 0, 'L', },
	{ "daemonize", 0, 0, 'd', },
	{ "background", 0, 0, 'b', },
	{ "group", 1, 0, 'g', },
	{ "fd-cap", 1, 0, '\0', },
	{ "help", 0, 0, 'h', },
	{ "output", 1, 0, 'o', },
	{ "verbose", 0, 0, 'v', },
	{ "config", 1, 0, 'f' },
	{ "version", 0, 0, 'V' },
	{ "working-directory", 1, 0, 'w', },
	{ "group-output-by-session", 0, 0, 's', },
	{ "group-output-by-host", 0, 0, 'p', },
	{ "disallow-clear", 0, 0, 'x' },
	{ NULL, 0, 0, 0, },
};

static const char *config_ignore_options[] = { "help", "config", "version" };

static void print_version(void) {
	fprintf(stdout, "%s\n", VERSION);
}

static void relayd_config_log(void)
{
	DBG("LTTng-relayd " VERSION " - " VERSION_NAME "%s%s",
			GIT_VERSION[0] == '\0' ? "" : " - " GIT_VERSION,
			EXTRA_VERSION_NAME[0] == '\0' ? "" : " - " EXTRA_VERSION_NAME);
	if (EXTRA_VERSION_DESCRIPTION[0] != '\0') {
		DBG("LTTng-relayd extra version description:\n\t" EXTRA_VERSION_DESCRIPTION "\n");
	}
	if (EXTRA_VERSION_PATCHES[0] != '\0') {
		DBG("LTTng-relayd extra patches:\n\t" EXTRA_VERSION_PATCHES "\n");
	}
}

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
		if (!strcmp(optname, "fd-cap")) {
			unsigned long v;

			errno = 0;
			v = strtoul(arg, NULL, 0);
			if (errno != 0 || !isdigit(arg[0])) {
				ERR("Wrong value in --fd-cap parameter: %s",
						arg);
				ret = -1;
				goto end;
			}
			if (v < DEFAULT_RELAYD_MINIMAL_FD_CAP) {
				ERR("File descriptor cap must be set to at least %d",
						DEFAULT_RELAYD_MINIMAL_FD_CAP);
			}
			if (v >= UINT_MAX) {
				ERR("File descriptor cap overflow in --fd-cap parameter: %s",
						arg);
				ret = -1;
				goto end;
			}
			lttng_opt_fd_cap = (unsigned int) v;
			DBG3("File descriptor cap set to %u", lttng_opt_fd_cap);
		} else {
			fprintf(stderr, "unknown option %s", optname);
			if (arg) {
				fprintf(stderr, " with arg %s\n", arg);
			}
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
		opt_print_version = 1;
		break;
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
	case 'w':
		if (lttng_is_setuid_setgid()) {
			WARN("Getting '%s' argument from setuid/setgid binary refused for security reasons.",
				"-w, --working-directory");
		} else {
			ret = asprintf(&opt_working_directory, "%s", arg);
			if (ret < 0) {
				ret = -errno;
				PERROR("asprintf opt_working_directory");
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
	case 's':
		if (opt_group_output_by != RELAYD_GROUP_OUTPUT_BY_UNKNOWN) {
			ERR("Cannot set --group-output-by-session, another --group-output-by argument is present");
			exit(EXIT_FAILURE);
		}
		opt_group_output_by = RELAYD_GROUP_OUTPUT_BY_SESSION;
		break;
	case 'p':
		if (opt_group_output_by != RELAYD_GROUP_OUTPUT_BY_UNKNOWN) {
			ERR("Cannot set --group-output-by-host, another --group-output-by argument is present");
			exit(EXIT_FAILURE);
		}
		opt_group_output_by = RELAYD_GROUP_OUTPUT_BY_HOST;
		break;
	case 'x':
		/* Disallow clear */
		opt_allow_clear = 0;
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

static int parse_env_options(void)
{
	int ret = 0;
	char *value = NULL;

	value = lttng_secure_getenv(DEFAULT_LTTNG_RELAYD_WORKING_DIRECTORY_ENV);
	if (value) {
		opt_working_directory = strdup(value);
		if (!opt_working_directory) {
			ERR("Failed to allocate working directory string (\"%s\")",
					value);
			ret = -1;
		}
	}
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
	if (lttng_opt_fd_cap == 0) {
		int ret;
		struct rlimit rlimit;

		ret = getrlimit(RLIMIT_NOFILE, &rlimit);
		if (ret) {
			PERROR("Failed to get file descriptor limit");
			retval = -1;
		}

		lttng_opt_fd_cap = rlimit.rlim_cur;
	}

	if (opt_group_output_by == RELAYD_GROUP_OUTPUT_BY_UNKNOWN) {
		opt_group_output_by = RELAYD_GROUP_OUTPUT_BY_HOST;
	}
	if (opt_allow_clear) {
		/* Check if env variable exists. */
		const char *value = lttng_secure_getenv(DEFAULT_LTTNG_RELAYD_DISALLOW_CLEAR_ENV);
		if (value) {
			ret = config_parse_value(value);
			if (ret < 0) {
				ERR("Invalid value for %s specified", DEFAULT_LTTNG_RELAYD_DISALLOW_CLEAR_ENV);
				retval = -1;
				goto exit;
			}
			opt_allow_clear = !ret;
		}
	}

exit:
	free(optstring);
	return retval;
}

static void print_global_objects(void)
{
	print_viewer_streams();
	print_relay_streams();
	print_sessions();
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

	free(opt_output_path);
	free(opt_working_directory);

	if (health_relayd) {
		health_app_destroy(health_relayd);
	}
	/* Close thread quit pipes */
	if (health_quit_pipe[0] != -1) {
		(void) fd_tracker_util_pipe_close(
				the_fd_tracker, health_quit_pipe);
	}
	if (thread_quit_pipe[0] != -1) {
		(void) fd_tracker_util_pipe_close(
				the_fd_tracker, thread_quit_pipe);
	}
	if (sessiond_trace_chunk_registry) {
		sessiond_trace_chunk_registry_destroy(
				sessiond_trace_chunk_registry);
	}
	if (the_fd_tracker) {
		fd_tracker_destroy(the_fd_tracker);
	}

	uri_free(control_uri);
	uri_free(data_uri);
	/* Live URI is freed in the live thread. */

	if (tracing_group_name_override) {
		free((void *) tracing_group_name);
	}
	fd_tracker_log(the_fd_tracker);
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
	return fd_tracker_util_pipe_open_cloexec(
			the_fd_tracker, "Quit pipe", thread_quit_pipe);
}

/*
 * Init health quit pipe.
 *
 * Return -1 on error or 0 if all pipes are created.
 */
static int init_health_quit_pipe(void)
{
	return fd_tracker_util_pipe_open_cloexec(the_fd_tracker,
			"Health quit pipe", health_quit_pipe);
}

/*
 * Create a poll set with O_CLOEXEC and add the thread quit pipe to the set.
 */
static int create_named_thread_poll_set(struct lttng_poll_event *events,
		int size, const char *name)
{
	int ret;

	if (events == NULL || size == 0) {
		ret = -1;
		goto error;
	}

	ret = fd_tracker_util_poll_create(the_fd_tracker,
		        name, events, 1, LTTNG_CLOEXEC);

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
	ret = create_named_thread_poll_set(&events, 3, "Listener thread epoll");
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
	(void) fd_tracker_util_poll_clean(the_fd_tracker, &events);
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

static bool session_streams_have_index(const struct relay_session *session)
{
	return session->minor >= 4 && !session->snapshot;
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
	struct relay_session *session = NULL;
	struct lttcomm_relayd_create_session_reply_2_11 reply = {};
	char session_name[LTTNG_NAME_MAX] = {};
	char hostname[LTTNG_HOST_NAME_MAX] = {};
	uint32_t live_timer = 0;
	bool snapshot = false;
	bool session_name_contains_creation_timestamp = false;
	/* Left nil for peers < 2.11. */
	char base_path[LTTNG_PATH_MAX] = {};
	lttng_uuid sessiond_uuid = {};
	LTTNG_OPTIONAL(uint64_t) id_sessiond = {};
	LTTNG_OPTIONAL(uint64_t) current_chunk_id = {};
	LTTNG_OPTIONAL(time_t) creation_time = {};
	struct lttng_dynamic_buffer reply_payload;

	lttng_dynamic_buffer_init(&reply_payload);

	if (conn->minor < 4) {
		/* From 2.1 to 2.3 */
		ret = 0;
	} else if (conn->minor >= 4 && conn->minor < 11) {
		/* From 2.4 to 2.10 */
		ret = cmd_create_session_2_4(payload, session_name,
			hostname, &live_timer, &snapshot);
	} else {
		bool has_current_chunk;
		uint64_t current_chunk_id_value;
		time_t creation_time_value;
		uint64_t id_sessiond_value;

		/* From 2.11 to ... */
		ret = cmd_create_session_2_11(payload, session_name, hostname,
				base_path, &live_timer, &snapshot, &id_sessiond_value,
				sessiond_uuid, &has_current_chunk,
				&current_chunk_id_value, &creation_time_value,
				&session_name_contains_creation_timestamp);
		if (lttng_uuid_is_nil(sessiond_uuid)) {
			/* The nil UUID is reserved for pre-2.11 clients. */
			ERR("Illegal nil UUID announced by peer in create session command");
			ret = -1;
			goto send_reply;
		}
		LTTNG_OPTIONAL_SET(&id_sessiond, id_sessiond_value);
		LTTNG_OPTIONAL_SET(&creation_time, creation_time_value);
		if (has_current_chunk) {
			LTTNG_OPTIONAL_SET(&current_chunk_id,
					current_chunk_id_value);
		}
	}

	if (ret < 0) {
		goto send_reply;
	}

	session = session_create(session_name, hostname, base_path, live_timer,
			snapshot, sessiond_uuid,
			id_sessiond.is_set ? &id_sessiond.value : NULL,
			current_chunk_id.is_set ? &current_chunk_id.value : NULL,
			creation_time.is_set ? &creation_time.value : NULL,
			conn->major, conn->minor,
			session_name_contains_creation_timestamp);
	if (!session) {
		ret = -1;
		goto send_reply;
	}
	assert(!conn->session);
	conn->session = session;
	DBG("Created session %" PRIu64, session->id);

	reply.generic.session_id = htobe64(session->id);

send_reply:
	if (ret < 0) {
		reply.generic.ret_code = htobe32(LTTNG_ERR_FATAL);
	} else {
		reply.generic.ret_code = htobe32(LTTNG_OK);
	}

	if (conn->minor < 11) {
		/* From 2.1 to 2.10 */
		ret = lttng_dynamic_buffer_append(&reply_payload,
				&reply.generic, sizeof(reply.generic));
		if (ret) {
			ERR("Failed to append \"create session\" command reply header to payload buffer");
			ret = -1;
			goto end;
		}
	} else {
		const uint32_t output_path_length =
				session ? strlen(session->output_path) + 1 : 0;

		reply.output_path_length = htobe32(output_path_length);
		ret = lttng_dynamic_buffer_append(
				&reply_payload, &reply, sizeof(reply));
		if (ret) {
			ERR("Failed to append \"create session\" command reply header to payload buffer");
			goto end;
		}

		if (output_path_length) {
			ret = lttng_dynamic_buffer_append(&reply_payload,
					session->output_path,
					output_path_length);
			if (ret) {
				ERR("Failed to append \"create session\" command reply path to payload buffer");
				goto end;
			}
		}
	}

	send_ret = conn->sock->ops->sendmsg(conn->sock, reply_payload.data,
			reply_payload.size, 0);
	if (send_ret < (ssize_t) reply_payload.size) {
		ERR("Failed to send \"create session\" command reply of %zu bytes (ret = %zd)",
				reply_payload.size, send_ret);
		ret = -1;
	}
end:
	if (ret < 0 && session) {
		session_put(session);
	}
	lttng_dynamic_buffer_reset(&reply_payload);
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

static int conform_channel_path(char *channel_path)
{
	int ret = 0;

	if (strstr("../", channel_path)) {
		ERR("Refusing channel path as it walks up the path hierarchy: \"%s\"",
				channel_path);
		ret = -1;
		goto end;
	}

	if (*channel_path == '/') {
		const size_t len = strlen(channel_path);

		/*
		 * Channel paths from peers prior to 2.11 are expressed as an
		 * absolute path that is, in reality, relative to the relay
		 * daemon's output directory. Remove the leading slash so it
		 * is correctly interpreted as a relative path later on.
		 *
		 * len (and not len - 1) is used to copy the trailing NULL.
		 */
		bcopy(channel_path + 1, channel_path, len);
	}
end:
	return ret;
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
	LTTNG_OPTIONAL(uint64_t) stream_chunk_id = {};

	if (!session || !conn->version_check_done) {
		ERR("Trying to add a stream before version check");
		ret = -1;
		goto end_no_session;
	}

	if (session->minor == 1) {
		/* For 2.1 */
		ret = cmd_recv_stream_2_1(payload, &path_name,
			&channel_name);
	} else if (session->minor > 1 && session->minor < 11) {
		/* From 2.2 to 2.10 */
		ret = cmd_recv_stream_2_2(payload, &path_name,
			&channel_name, &tracefile_size, &tracefile_count);
	} else {
		/* From 2.11 to ... */
		ret = cmd_recv_stream_2_11(payload, &path_name,
			&channel_name, &tracefile_size, &tracefile_count,
			&stream_chunk_id.value);
		stream_chunk_id.is_set = true;
	}

	if (ret < 0) {
		goto send_reply;
	}

	if (conform_channel_path(path_name)) {
		goto send_reply;
	}

	/*
	 * Backward compatibility for --group-output-by-session.
	 * Prior to lttng 2.11, the complete path is passed by the stream.
	 * Starting at 2.11, lttng-relayd uses chunk. When dealing with producer
	 * >=2.11 the chunk is responsible for the output path. When dealing
	 * with producer < 2.11 the chunk output_path is the root output path
	 * and the stream carries the complete path (path_name).
	 * To support --group-output-by-session with older producer (<2.11), we
	 * need to craft the path based on the stream path.
	 */
	if (opt_group_output_by == RELAYD_GROUP_OUTPUT_BY_SESSION) {
		if (conn->minor < 4) {
			/*
			 * From 2.1 to 2.3, the session_name is not passed on
			 * the RELAYD_CREATE_SESSION command. The session name
			 * is necessary to detect the presence of a base_path
			 * inside the stream path. Without it we cannot perform
			 * a valid group-output-by-session transformation.
			 */
			WARN("Unable to perform a --group-by-session transformation for session %" PRIu64
			     " for stream with path \"%s\" as it is produced by a peer using a protocol older than v2.4",
					session->id, path_name);
		} else if (conn->minor >= 4 && conn->minor < 11) {
			char *group_by_session_path_name;

			assert(session->session_name[0] != '\0');

			group_by_session_path_name =
					backward_compat_group_by_session(
							path_name,
							session->session_name);
			if (!group_by_session_path_name) {
				ERR("Failed to apply group by session to stream of session %" PRIu64,
						session->id);
				goto send_reply;
			}

			DBG("Transformed session path from \"%s\" to \"%s\" to honor per-session name grouping",
					path_name, group_by_session_path_name);

			free(path_name);
			path_name = group_by_session_path_name;
		}
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
			if (stream->no_new_metadata_notified) {
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

	ret = stream_reset_file(stream);
	if (ret < 0) {
		ERR("Failed to reset metadata stream %" PRIu64
				": stream_path = %s, channel = %s",
				stream->stream_handle, stream->path_name,
				stream->channel_name);
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
 * relay_recv_metadata: receive the metadata for the session.
 */
static int relay_recv_metadata(const struct lttcomm_relayd_hdr *recv_hdr,
		struct relay_connection *conn,
		const struct lttng_buffer_view *payload)
{
	int ret = 0;
	struct relay_session *session = conn->session;
	struct lttcomm_relayd_metadata_payload metadata_payload_header;
	struct relay_stream *metadata_stream;
	uint64_t metadata_payload_size;
	struct lttng_buffer_view packet_view;

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

	packet_view = lttng_buffer_view_from_view(payload,
			sizeof(metadata_payload_header), metadata_payload_size);
	if (!packet_view.data) {
		ERR("Invalid metadata packet length announced by header");
		ret = -1;
		goto end_put;
	}

	pthread_mutex_lock(&metadata_stream->lock);
	ret = stream_write(metadata_stream, &packet_view,
			metadata_payload_header.padding_size);
	pthread_mutex_unlock(&metadata_stream->lock);
	if (ret){
		ret = -1;
		goto end_put;
	}
end_put:
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
	uint64_t stream_seq;

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

	if (session_streams_have_index(session)) {
		/*
		 * Ensure that both the index and stream data have been
		 * flushed up to the requested point.
		 */
		stream_seq = min(stream->prev_data_seq, stream->prev_index_seq);
	} else {
		stream_seq = stream->prev_data_seq;
	}
	DBG("Data pending for stream id %" PRIu64 ": prev_data_seq %" PRIu64
			", prev_index_seq %" PRIu64
			", and last_seq %" PRIu64, msg.stream_id,
			stream->prev_data_seq, stream->prev_index_seq,
			msg.last_net_seq_num);

	/* Avoid wrapping issue */
	if (((int64_t) (stream_seq - msg.last_net_seq_num)) >= 0) {
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
			uint64_t stream_seq;

			if (session_streams_have_index(conn->session)) {
				/*
				 * Ensure that both the index and stream data have been
				 * flushed up to the requested point.
				 */
				stream_seq = min(stream->prev_data_seq, stream->prev_index_seq);
			} else {
				stream_seq = stream->prev_data_seq;
			}
			if (!stream->closed || !(((int64_t) (stream_seq - stream->last_net_seq_num)) >= 0)) {
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

	if (conn->minor >= 8) {
		index_info.stream_instance_id =
				be64toh(index_info.stream_instance_id);
		index_info.packet_seq_num = be64toh(index_info.packet_seq_num);
	} else {
		index_info.stream_instance_id = -1ULL;
		index_info.packet_seq_num = -1ULL;
	}

	stream = stream_get_by_id(index_info.relay_stream_id);
	if (!stream) {
		ERR("stream_get_by_id not found");
		ret = -1;
		goto end;
	}

	pthread_mutex_lock(&stream->lock);
	ret = stream_add_index(stream, &index_info);
	pthread_mutex_unlock(&stream->lock);
	if (ret) {
		goto end_stream_put;
	}

end_stream_put:
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
 * relay_rotate_session_stream: rotate a stream to a new tracefile for the
 * session rotation feature (not the tracefile rotation feature).
 */
static int relay_rotate_session_streams(
		const struct lttcomm_relayd_hdr *recv_hdr,
		struct relay_connection *conn,
		const struct lttng_buffer_view *payload)
{
	int ret = 0;
	uint32_t i;
	ssize_t send_ret;
	enum lttng_error_code reply_code = LTTNG_ERR_UNK;
	struct relay_session *session = conn->session;
	struct lttcomm_relayd_rotate_streams rotate_streams;
	struct lttcomm_relayd_generic_reply reply = {};
	struct relay_stream *stream = NULL;
	const size_t header_len = sizeof(struct lttcomm_relayd_rotate_streams);
	struct lttng_trace_chunk *next_trace_chunk = NULL;
	struct lttng_buffer_view stream_positions;
	char chunk_id_buf[MAX_INT_DEC_LEN(uint64_t)];
	const char *chunk_id_str = "none";

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

	if (payload->size < header_len) {
		ERR("Unexpected payload size in \"relay_rotate_session_stream\": expected >= %zu bytes, got %zu bytes",
				header_len, payload->size);
		ret = -1;
		goto end_no_reply;
	}

	memcpy(&rotate_streams, payload->data, header_len);

	/* Convert header to host endianness. */
	rotate_streams = (typeof(rotate_streams)) {
		.stream_count = be32toh(rotate_streams.stream_count),
		.new_chunk_id = (typeof(rotate_streams.new_chunk_id)) {
			.is_set = !!rotate_streams.new_chunk_id.is_set,
			.value = be64toh(rotate_streams.new_chunk_id.value),
		}
	};

	if (rotate_streams.new_chunk_id.is_set) {
		/*
		 * Retrieve the trace chunk the stream must transition to. As
		 * per the protocol, this chunk should have been created
		 * before this command is received.
		 */
		next_trace_chunk = sessiond_trace_chunk_registry_get_chunk(
				sessiond_trace_chunk_registry,
				session->sessiond_uuid, session->id,
				rotate_streams.new_chunk_id.value);
		if (!next_trace_chunk) {
			char uuid_str[LTTNG_UUID_STR_LEN];

			lttng_uuid_to_str(session->sessiond_uuid, uuid_str);
			ERR("Unknown next trace chunk in ROTATE_STREAMS command: sessiond_uuid = {%s}, session_id = %" PRIu64
					", trace_chunk_id = %" PRIu64,
					uuid_str, session->id,
					rotate_streams.new_chunk_id.value);
			reply_code = LTTNG_ERR_INVALID_PROTOCOL;
			ret = -1;
			goto end;
		}

		ret = snprintf(chunk_id_buf, sizeof(chunk_id_buf), "%" PRIu64,
				rotate_streams.new_chunk_id.value);
		if (ret < 0 || ret >= sizeof(chunk_id_buf)) {
			chunk_id_str = "formatting error";
		} else {
			chunk_id_str = chunk_id_buf;
		}
	}

	DBG("Rotate %" PRIu32 " streams of session \"%s\" to chunk \"%s\"",
			rotate_streams.stream_count, session->session_name,
			chunk_id_str);

	stream_positions = lttng_buffer_view_from_view(payload,
			sizeof(rotate_streams), -1);
	if (!stream_positions.data ||
			stream_positions.size <
					(rotate_streams.stream_count *
							sizeof(struct lttcomm_relayd_stream_rotation_position))) {
		reply_code = LTTNG_ERR_INVALID_PROTOCOL;
		ret = -1;
		goto end;
	}

	for (i = 0; i < rotate_streams.stream_count; i++) {
		struct lttcomm_relayd_stream_rotation_position *position_comm =
				&((typeof(position_comm)) stream_positions.data)[i];
		const struct lttcomm_relayd_stream_rotation_position pos = {
			.stream_id = be64toh(position_comm->stream_id),
			.rotate_at_seq_num = be64toh(
					position_comm->rotate_at_seq_num),
		};

		stream = stream_get_by_id(pos.stream_id);
		if (!stream) {
			reply_code = LTTNG_ERR_INVALID;
			ret = -1;
			goto end;
		}

		pthread_mutex_lock(&stream->lock);
		ret = stream_set_pending_rotation(stream, next_trace_chunk,
				pos.rotate_at_seq_num);
		pthread_mutex_unlock(&stream->lock);
		if (ret) {
			reply_code = LTTNG_ERR_FILE_CREATION_ERROR;
			goto end;
		}

		stream_put(stream);
		stream = NULL;
	}

	reply_code = LTTNG_OK;
	ret = 0;
end:
	if (stream) {
		stream_put(stream);
	}

	reply.ret_code = htobe32((uint32_t) reply_code);
	send_ret = conn->sock->ops->sendmsg(conn->sock, &reply,
			sizeof(struct lttcomm_relayd_generic_reply), 0);
	if (send_ret < (ssize_t) sizeof(reply)) {
		ERR("Failed to send \"rotate session stream\" command reply (ret = %zd)",
				send_ret);
		ret = -1;
	}
end_no_reply:
	lttng_trace_chunk_put(next_trace_chunk);
	return ret;
}



/*
 * relay_create_trace_chunk: create a new trace chunk
 */
static int relay_create_trace_chunk(const struct lttcomm_relayd_hdr *recv_hdr,
		struct relay_connection *conn,
		const struct lttng_buffer_view *payload)
{
	int ret = 0;
	ssize_t send_ret;
	struct relay_session *session = conn->session;
	struct lttcomm_relayd_create_trace_chunk *msg;
	struct lttcomm_relayd_generic_reply reply = {};
	struct lttng_buffer_view header_view;
	struct lttng_buffer_view chunk_name_view;
	struct lttng_trace_chunk *chunk = NULL, *published_chunk = NULL;
	enum lttng_error_code reply_code = LTTNG_OK;
	enum lttng_trace_chunk_status chunk_status;
	struct lttng_directory_handle *session_output = NULL;
	const char *new_path;

	if (!session || !conn->version_check_done) {
		ERR("Trying to create a trace chunk before version check");
		ret = -1;
		goto end_no_reply;
	}

	if (session->major == 2 && session->minor < 11) {
		ERR("Chunk creation command is unsupported before 2.11");
		ret = -1;
		goto end_no_reply;
	}

	header_view = lttng_buffer_view_from_view(payload, 0, sizeof(*msg));
	if (!header_view.data) {
		ERR("Failed to receive payload of chunk creation command");
		ret = -1;
		goto end_no_reply;
	}

	/* Convert to host endianness. */
	msg = (typeof(msg)) header_view.data;
	msg->chunk_id = be64toh(msg->chunk_id);
	msg->creation_timestamp = be64toh(msg->creation_timestamp);
	msg->override_name_length = be32toh(msg->override_name_length);

	if (session->current_trace_chunk &&
			!lttng_trace_chunk_get_name_overridden(session->current_trace_chunk)) {
		chunk_status = lttng_trace_chunk_rename_path(session->current_trace_chunk,
					DEFAULT_CHUNK_TMP_OLD_DIRECTORY);
		if (chunk_status != LTTNG_TRACE_CHUNK_STATUS_OK) {
			ERR("Failed to rename old chunk");
			ret = -1;
			reply_code = LTTNG_ERR_UNK;
			goto end;
		}
	}
	session->ongoing_rotation = true;
	if (!session->current_trace_chunk) {
		if (!session->has_rotated) {
			new_path = "";
		} else {
			new_path = NULL;
		}
	} else {
		new_path = DEFAULT_CHUNK_TMP_NEW_DIRECTORY;
	}
	chunk = lttng_trace_chunk_create(
			msg->chunk_id, msg->creation_timestamp, new_path);
	if (!chunk) {
		ERR("Failed to create trace chunk in trace chunk creation command");
		ret = -1;
		reply_code = LTTNG_ERR_NOMEM;
		goto end;
	}

	if (msg->override_name_length) {
		const char *name;

		chunk_name_view = lttng_buffer_view_from_view(payload,
				sizeof(*msg),
				msg->override_name_length);
		name = chunk_name_view.data;
		if (!name || name[msg->override_name_length - 1]) {
			ERR("Failed to receive payload of chunk creation command");
			ret = -1;
			reply_code = LTTNG_ERR_INVALID;
			goto end;
		}

		chunk_status = lttng_trace_chunk_override_name(
				chunk, chunk_name_view.data);
		switch (chunk_status) {
		case LTTNG_TRACE_CHUNK_STATUS_OK:
			break;
		case LTTNG_TRACE_CHUNK_STATUS_INVALID_ARGUMENT:
			ERR("Failed to set the name of new trace chunk in trace chunk creation command (invalid name)");
			reply_code = LTTNG_ERR_INVALID;
			ret = -1;
			goto end;
		default:
			ERR("Failed to set the name of new trace chunk in trace chunk creation command (unknown error)");
			reply_code = LTTNG_ERR_UNK;
			ret = -1;
			goto end;
		}
	}

	chunk_status = lttng_trace_chunk_set_credentials_current_user(chunk);
	if (chunk_status != LTTNG_TRACE_CHUNK_STATUS_OK) {
		reply_code = LTTNG_ERR_UNK;
		ret = -1;
		goto end;
	}

	session_output = session_create_output_directory_handle(
			conn->session);
	if (!session_output) {
		reply_code = LTTNG_ERR_CREATE_DIR_FAIL;
		goto end;
	}
	chunk_status = lttng_trace_chunk_set_as_owner(chunk, session_output);
	lttng_directory_handle_put(session_output);
	session_output = NULL;
	if (chunk_status != LTTNG_TRACE_CHUNK_STATUS_OK) {
		reply_code = LTTNG_ERR_UNK;
		ret = -1;
		goto end;
	}

	published_chunk = sessiond_trace_chunk_registry_publish_chunk(
			sessiond_trace_chunk_registry,
			conn->session->sessiond_uuid,
			conn->session->id,
			chunk);
	if (!published_chunk) {
		char uuid_str[LTTNG_UUID_STR_LEN];

		lttng_uuid_to_str(conn->session->sessiond_uuid, uuid_str);
		ERR("Failed to publish chunk: sessiond_uuid = %s, session_id = %" PRIu64 ", chunk_id = %" PRIu64,
				uuid_str,
				conn->session->id,
				msg->chunk_id);
		ret = -1;
		reply_code = LTTNG_ERR_NOMEM;
		goto end;
	}

	pthread_mutex_lock(&conn->session->lock);
	if (conn->session->pending_closure_trace_chunk) {
		/*
		 * Invalid; this means a second create_trace_chunk command was
		 * received before a close_trace_chunk.
		 */
		ERR("Invalid trace chunk close command received; a trace chunk is already waiting for a trace chunk close command");
		reply_code = LTTNG_ERR_INVALID_PROTOCOL;
		ret = -1;
		goto end_unlock_session;
	}
	conn->session->pending_closure_trace_chunk =
			conn->session->current_trace_chunk;
	conn->session->current_trace_chunk = published_chunk;
	published_chunk = NULL;
	if (!conn->session->pending_closure_trace_chunk) {
		session->ongoing_rotation = false;
	}
end_unlock_session:
	pthread_mutex_unlock(&conn->session->lock);
end:
	reply.ret_code = htobe32((uint32_t) reply_code);
	send_ret = conn->sock->ops->sendmsg(conn->sock,
			&reply,
			sizeof(struct lttcomm_relayd_generic_reply),
			0);
	if (send_ret < (ssize_t) sizeof(reply)) {
		ERR("Failed to send \"create trace chunk\" command reply (ret = %zd)",
				send_ret);
		ret = -1;
	}
end_no_reply:
	lttng_trace_chunk_put(chunk);
	lttng_trace_chunk_put(published_chunk);
	lttng_directory_handle_put(session_output);
	return ret;
}

/*
 * relay_close_trace_chunk: close a trace chunk
 */
static int relay_close_trace_chunk(const struct lttcomm_relayd_hdr *recv_hdr,
		struct relay_connection *conn,
		const struct lttng_buffer_view *payload)
{
	int ret = 0, buf_ret;
	ssize_t send_ret;
	struct relay_session *session = conn->session;
	struct lttcomm_relayd_close_trace_chunk *msg;
	struct lttcomm_relayd_close_trace_chunk_reply reply = {};
	struct lttng_buffer_view header_view;
	struct lttng_trace_chunk *chunk = NULL;
	enum lttng_error_code reply_code = LTTNG_OK;
	enum lttng_trace_chunk_status chunk_status;
	uint64_t chunk_id;
	LTTNG_OPTIONAL(enum lttng_trace_chunk_command_type) close_command = {};
	time_t close_timestamp;
	char closed_trace_chunk_path[LTTNG_PATH_MAX];
	size_t path_length = 0;
	const char *chunk_name = NULL;
	struct lttng_dynamic_buffer reply_payload;
	const char *new_path;

	lttng_dynamic_buffer_init(&reply_payload);

	if (!session || !conn->version_check_done) {
		ERR("Trying to close a trace chunk before version check");
		ret = -1;
		goto end_no_reply;
	}

	if (session->major == 2 && session->minor < 11) {
		ERR("Chunk close command is unsupported before 2.11");
		ret = -1;
		goto end_no_reply;
	}

	header_view = lttng_buffer_view_from_view(payload, 0, sizeof(*msg));
	if (!header_view.data) {
		ERR("Failed to receive payload of chunk close command");
		ret = -1;
		goto end_no_reply;
	}

	/* Convert to host endianness. */
	msg = (typeof(msg)) header_view.data;
	chunk_id = be64toh(msg->chunk_id);
	close_timestamp = (time_t) be64toh(msg->close_timestamp);
	close_command = (typeof(close_command)){
		.value = be32toh(msg->close_command.value),
		.is_set = msg->close_command.is_set,
	};

	chunk = sessiond_trace_chunk_registry_get_chunk(
			sessiond_trace_chunk_registry,
			conn->session->sessiond_uuid,
			conn->session->id,
			chunk_id);
	if (!chunk) {
		char uuid_str[LTTNG_UUID_STR_LEN];

		lttng_uuid_to_str(conn->session->sessiond_uuid, uuid_str);
		ERR("Failed to find chunk to close: sessiond_uuid = %s, session_id = %" PRIu64 ", chunk_id = %" PRIu64,
				uuid_str,
				conn->session->id,
				msg->chunk_id);
		ret = -1;
		reply_code = LTTNG_ERR_NOMEM;
		goto end;
	}

	pthread_mutex_lock(&session->lock);
	if (close_command.is_set &&
			close_command.value == LTTNG_TRACE_CHUNK_COMMAND_TYPE_DELETE) {
		/*
		 * Clear command. It is a protocol error to ask for a
		 * clear on a relay which does not allow it. Querying
		 * the configuration allows figuring out whether
		 * clearing is allowed before doing the clear.
		 */
		if (!opt_allow_clear) {
			ret = -1;
			reply_code = LTTNG_ERR_INVALID_PROTOCOL;
			goto end_unlock_session;
		}
	}
	if (session->pending_closure_trace_chunk &&
			session->pending_closure_trace_chunk != chunk) {
		ERR("Trace chunk close command for session \"%s\" does not target the trace chunk pending closure",
				session->session_name);
		reply_code = LTTNG_ERR_INVALID_PROTOCOL;
		ret = -1;
		goto end_unlock_session;
	}

	if (session->current_trace_chunk && session->current_trace_chunk != chunk &&
			!lttng_trace_chunk_get_name_overridden(session->current_trace_chunk)) {
		if (close_command.is_set &&
				close_command.value == LTTNG_TRACE_CHUNK_COMMAND_TYPE_DELETE &&
				!session->has_rotated) {
			/* New chunk stays in session output directory. */
			new_path = "";
		} else {
			/* Use chunk name for new chunk. */
			new_path = NULL;
		}
		/* Rename new chunk path. */
		chunk_status = lttng_trace_chunk_rename_path(session->current_trace_chunk,
				new_path);
		if (chunk_status != LTTNG_TRACE_CHUNK_STATUS_OK) {
			ret = -1;
			goto end;
		}
		session->ongoing_rotation = false;
	}
	if ((!close_command.is_set ||
			close_command.value == LTTNG_TRACE_CHUNK_COMMAND_TYPE_NO_OPERATION) &&
			!lttng_trace_chunk_get_name_overridden(chunk)) {
		const char *old_path;

		if (!session->has_rotated) {
			old_path = "";
		} else {
			old_path = NULL;
		}
		/* We need to move back the .tmp_old_chunk to its rightful place. */
		chunk_status = lttng_trace_chunk_rename_path(chunk, old_path);
		if (chunk_status != LTTNG_TRACE_CHUNK_STATUS_OK) {
			ret = -1;
			goto end;
		}
	}
	chunk_status = lttng_trace_chunk_set_close_timestamp(
			chunk, close_timestamp);
	if (chunk_status != LTTNG_TRACE_CHUNK_STATUS_OK) {
		ERR("Failed to set trace chunk close timestamp");
		ret = -1;
		reply_code = LTTNG_ERR_UNK;
		goto end_unlock_session;
	}

	if (close_command.is_set) {
		chunk_status = lttng_trace_chunk_set_close_command(
				chunk, close_command.value);
		if (chunk_status != LTTNG_TRACE_CHUNK_STATUS_OK) {
			ret = -1;
			reply_code = LTTNG_ERR_INVALID;
			goto end_unlock_session;
		}
	}
	chunk_status = lttng_trace_chunk_get_name(chunk, &chunk_name, NULL);
	if (chunk_status != LTTNG_TRACE_CHUNK_STATUS_OK) {
		ERR("Failed to get chunk name");
		ret = -1;
		reply_code = LTTNG_ERR_UNK;
		goto end_unlock_session;
	}
	if (!session->has_rotated && !session->snapshot) {
		ret = lttng_strncpy(closed_trace_chunk_path,
				session->output_path,
				sizeof(closed_trace_chunk_path));
		if (ret) {
			ERR("Failed to send trace chunk path: path length of %zu bytes exceeds the maximal allowed length of %zu bytes",
					strlen(session->output_path),
					sizeof(closed_trace_chunk_path));
			reply_code = LTTNG_ERR_NOMEM;
			ret = -1;
			goto end_unlock_session;
		}
	} else {
		if (session->snapshot) {
			ret = snprintf(closed_trace_chunk_path,
					sizeof(closed_trace_chunk_path),
					"%s/%s", session->output_path,
					chunk_name);
		} else {
			ret = snprintf(closed_trace_chunk_path,
					sizeof(closed_trace_chunk_path),
					"%s/" DEFAULT_ARCHIVED_TRACE_CHUNKS_DIRECTORY
					"/%s",
					session->output_path, chunk_name);
		}
		if (ret < 0 || ret == sizeof(closed_trace_chunk_path)) {
			ERR("Failed to format closed trace chunk resulting path");
			reply_code = ret < 0 ? LTTNG_ERR_UNK : LTTNG_ERR_NOMEM;
			ret = -1;
			goto end_unlock_session;
		}
	}
	if (close_command.is_set &&
			close_command.value == LTTNG_TRACE_CHUNK_COMMAND_TYPE_MOVE_TO_COMPLETED) {
		session->has_rotated = true;
	}
	DBG("Reply chunk path on close: %s", closed_trace_chunk_path);
	path_length = strlen(closed_trace_chunk_path) + 1;
	if (path_length > UINT32_MAX) {
		ERR("Closed trace chunk path exceeds the maximal length allowed by the protocol");
		ret = -1;
		reply_code = LTTNG_ERR_INVALID_PROTOCOL;
		goto end_unlock_session;
	}

	if (session->current_trace_chunk == chunk) {
		/*
		 * After a trace chunk close command, no new streams
		 * referencing the chunk may be created. Hence, on the
		 * event that no new trace chunk have been created for
		 * the session, the reference to the current trace chunk
		 * is released in order to allow it to be reclaimed when
		 * the last stream releases its reference to it.
		 */
		lttng_trace_chunk_put(session->current_trace_chunk);
		session->current_trace_chunk = NULL;
	}
	lttng_trace_chunk_put(session->pending_closure_trace_chunk);
	session->pending_closure_trace_chunk = NULL;
end_unlock_session:
	pthread_mutex_unlock(&session->lock);

end:
	reply.generic.ret_code = htobe32((uint32_t) reply_code);
	reply.path_length = htobe32((uint32_t) path_length);
	buf_ret = lttng_dynamic_buffer_append(
			&reply_payload, &reply, sizeof(reply));
	if (buf_ret) {
		ERR("Failed to append \"close trace chunk\" command reply header to payload buffer");
		goto end_no_reply;
	}

	if (reply_code == LTTNG_OK) {
		buf_ret = lttng_dynamic_buffer_append(&reply_payload,
				closed_trace_chunk_path, path_length);
		if (buf_ret) {
			ERR("Failed to append \"close trace chunk\" command reply path to payload buffer");
			goto end_no_reply;
		}
	}

	send_ret = conn->sock->ops->sendmsg(conn->sock,
			reply_payload.data,
			reply_payload.size,
			0);
	if (send_ret < reply_payload.size) {
		ERR("Failed to send \"close trace chunk\" command reply of %zu bytes (ret = %zd)",
				reply_payload.size, send_ret);
		ret = -1;
		goto end_no_reply;
	}
end_no_reply:
	lttng_trace_chunk_put(chunk);
	lttng_dynamic_buffer_reset(&reply_payload);
	return ret;
}

/*
 * relay_trace_chunk_exists: check if a trace chunk exists
 */
static int relay_trace_chunk_exists(const struct lttcomm_relayd_hdr *recv_hdr,
		struct relay_connection *conn,
		const struct lttng_buffer_view *payload)
{
	int ret = 0;
	ssize_t send_ret;
	struct relay_session *session = conn->session;
	struct lttcomm_relayd_trace_chunk_exists *msg;
	struct lttcomm_relayd_trace_chunk_exists_reply reply = {};
	struct lttng_buffer_view header_view;
	uint64_t chunk_id;
	bool chunk_exists;

	if (!session || !conn->version_check_done) {
		ERR("Trying to close a trace chunk before version check");
		ret = -1;
		goto end_no_reply;
	}

	if (session->major == 2 && session->minor < 11) {
		ERR("Chunk close command is unsupported before 2.11");
		ret = -1;
		goto end_no_reply;
	}

	header_view = lttng_buffer_view_from_view(payload, 0, sizeof(*msg));
	if (!header_view.data) {
		ERR("Failed to receive payload of chunk close command");
		ret = -1;
		goto end_no_reply;
	}

	/* Convert to host endianness. */
	msg = (typeof(msg)) header_view.data;
	chunk_id = be64toh(msg->chunk_id);

	ret = sessiond_trace_chunk_registry_chunk_exists(
			sessiond_trace_chunk_registry,
			conn->session->sessiond_uuid,
			conn->session->id,
			chunk_id, &chunk_exists);
	/*
	 * If ret is not 0, send the reply and report the error to the caller.
	 * It is a protocol (or internal) error and the session/connection
	 * should be torn down.
	 */
	reply = (typeof(reply)){
		.generic.ret_code = htobe32((uint32_t)
			(ret == 0 ? LTTNG_OK : LTTNG_ERR_INVALID_PROTOCOL)),
		.trace_chunk_exists = ret == 0 ? chunk_exists : 0,
	};
	send_ret = conn->sock->ops->sendmsg(
			conn->sock, &reply, sizeof(reply), 0);
	if (send_ret < (ssize_t) sizeof(reply)) {
		ERR("Failed to send \"create trace chunk\" command reply (ret = %zd)",
				send_ret);
		ret = -1;
	}
end_no_reply:
	return ret;
}

/*
 * relay_get_configuration: query whether feature is available
 */
static int relay_get_configuration(const struct lttcomm_relayd_hdr *recv_hdr,
		struct relay_connection *conn,
		const struct lttng_buffer_view *payload)
{
	int ret = 0;
	ssize_t send_ret;
	struct lttcomm_relayd_get_configuration *msg;
	struct lttcomm_relayd_get_configuration_reply reply = {};
	struct lttng_buffer_view header_view;
	uint64_t query_flags = 0;
	uint64_t result_flags = 0;

	header_view = lttng_buffer_view_from_view(payload, 0, sizeof(*msg));
	if (!header_view.data) {
		ERR("Failed to receive payload of chunk close command");
		ret = -1;
		goto end_no_reply;
	}

	/* Convert to host endianness. */
	msg = (typeof(msg)) header_view.data;
	query_flags = be64toh(msg->query_flags);

	if (query_flags) {
		ret = LTTNG_ERR_INVALID_PROTOCOL;
		goto reply;
	}
	if (opt_allow_clear) {
		result_flags |= LTTCOMM_RELAYD_CONFIGURATION_FLAG_CLEAR_ALLOWED;
	}
	ret = 0;
reply:
	reply = (typeof(reply)){
		.generic.ret_code = htobe32((uint32_t)
			(ret == 0 ? LTTNG_OK : LTTNG_ERR_INVALID_PROTOCOL)),
		.relayd_configuration_flags = htobe64(result_flags),
	};
	send_ret = conn->sock->ops->sendmsg(
			conn->sock, &reply, sizeof(reply), 0);
	if (send_ret < (ssize_t) sizeof(reply)) {
		ERR("Failed to send \"get configuration\" command reply (ret = %zd)",
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
	case RELAYD_ROTATE_STREAMS:
		DBG_CMD("RELAYD_ROTATE_STREAMS", conn);
		ret = relay_rotate_session_streams(header, conn, payload);
		break;
	case RELAYD_CREATE_TRACE_CHUNK:
		DBG_CMD("RELAYD_CREATE_TRACE_CHUNK", conn);
		ret = relay_create_trace_chunk(header, conn, payload);
		break;
	case RELAYD_CLOSE_TRACE_CHUNK:
		DBG_CMD("RELAYD_CLOSE_TRACE_CHUNK", conn);
		ret = relay_close_trace_chunk(header, conn, payload);
		break;
	case RELAYD_TRACE_CHUNK_EXISTS:
		DBG_CMD("RELAYD_TRACE_CHUNK_EXISTS", conn);
		ret = relay_trace_chunk_exists(header, conn, payload);
		break;
	case RELAYD_GET_CONFIGURATION:
		DBG_CMD("RELAYD_GET_CONFIGURATION", conn);
		ret = relay_get_configuration(header, conn, payload);
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

static enum relay_connection_status relay_process_control_receive_payload(
		struct relay_connection *conn)
{
	int ret = 0;
	enum relay_connection_status status = RELAY_CONNECTION_STATUS_OK;
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
		if (errno != EAGAIN && errno != EWOULDBLOCK) {
			PERROR("Unable to receive command payload on sock %d",
					conn->sock->fd);
			status = RELAY_CONNECTION_STATUS_ERROR;
		}
		goto end;
	} else if (ret == 0) {
		DBG("Socket %d performed an orderly shutdown (received EOF)", conn->sock->fd);
		status = RELAY_CONNECTION_STATUS_CLOSED;
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
		status = RELAY_CONNECTION_STATUS_ERROR;
		goto end;
	}

	ret = connection_reset_protocol_state(conn);
	if (ret) {
		status = RELAY_CONNECTION_STATUS_ERROR;
	}
end:
	return status;
}

static enum relay_connection_status relay_process_control_receive_header(
		struct relay_connection *conn)
{
	int ret = 0;
	enum relay_connection_status status = RELAY_CONNECTION_STATUS_OK;
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
		if (errno != EAGAIN && errno != EWOULDBLOCK) {
			PERROR("Unable to receive control command header on sock %d",
					conn->sock->fd);
			status = RELAY_CONNECTION_STATUS_ERROR;
		}
		goto end;
	} else if (ret == 0) {
		DBG("Socket %d performed an orderly shutdown (received EOF)", conn->sock->fd);
		status = RELAY_CONNECTION_STATUS_CLOSED;
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

	if (header.data_size > DEFAULT_NETWORK_RELAYD_CTRL_MAX_PAYLOAD_SIZE) {
		ERR("Command header indicates a payload (%" PRIu64 " bytes) that exceeds the maximal payload size allowed on a control connection.",
				header.data_size);
		status = RELAY_CONNECTION_STATUS_ERROR;
		goto end;
	}

	conn->protocol.ctrl.state.receive_payload.left_to_receive =
			header.data_size;
	conn->protocol.ctrl.state.receive_payload.received = 0;
	ret = lttng_dynamic_buffer_set_size(reception_buffer,
			header.data_size);
	if (ret) {
		status = RELAY_CONNECTION_STATUS_ERROR;
		goto end;
	}

	if (header.data_size == 0) {
		/*
		 * Manually invoke the next state as the poll loop
		 * will not wake-up to allow us to proceed further.
		 */
		status = relay_process_control_receive_payload(conn);
	}
end:
	return status;
}

/*
 * Process the commands received on the control socket
 */
static enum relay_connection_status relay_process_control(
		struct relay_connection *conn)
{
	enum relay_connection_status status;

	switch (conn->protocol.ctrl.state_id) {
	case CTRL_CONNECTION_STATE_RECEIVE_HEADER:
		status = relay_process_control_receive_header(conn);
		break;
	case CTRL_CONNECTION_STATE_RECEIVE_PAYLOAD:
		status = relay_process_control_receive_payload(conn);
		break;
	default:
		ERR("Unknown control connection protocol state encountered.");
		abort();
	}

	return status;
}

static enum relay_connection_status relay_process_data_receive_header(
		struct relay_connection *conn)
{
	int ret;
	enum relay_connection_status status = RELAY_CONNECTION_STATUS_OK;
	struct data_connection_state_receive_header *state =
			&conn->protocol.data.state.receive_header;
	struct lttcomm_relayd_data_hdr header;
	struct relay_stream *stream;

	assert(state->left_to_receive != 0);

	ret = conn->sock->ops->recvmsg(conn->sock,
			state->header_reception_buffer + state->received,
			state->left_to_receive, MSG_DONTWAIT);
	if (ret < 0) {
		if (errno != EAGAIN && errno != EWOULDBLOCK) {
			PERROR("Unable to receive data header on sock %d", conn->sock->fd);
			status = RELAY_CONNECTION_STATUS_ERROR;
		}
		goto end;
	} else if (ret == 0) {
		/* Orderly shutdown. Not necessary to print an error. */
		DBG("Socket %d performed an orderly shutdown (received EOF)", conn->sock->fd);
		status = RELAY_CONNECTION_STATUS_CLOSED;
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
		/* Protocol error. */
		status = RELAY_CONNECTION_STATUS_ERROR;
		goto end;
	}

	pthread_mutex_lock(&stream->lock);
	/* Prepare stream for the reception of a new packet. */
	ret = stream_init_packet(stream, header.data_size,
			&conn->protocol.data.state.receive_payload.rotate_index);
	pthread_mutex_unlock(&stream->lock);
	if (ret) {
		ERR("Failed to rotate stream output file");
		status = RELAY_CONNECTION_STATUS_ERROR;
		goto end_stream_unlock;
	}

end_stream_unlock:
	stream_put(stream);
end:
	return status;
}

static enum relay_connection_status relay_process_data_receive_payload(
		struct relay_connection *conn)
{
	int ret;
	enum relay_connection_status status = RELAY_CONNECTION_STATUS_OK;
	struct relay_stream *stream;
	struct data_connection_state_receive_payload *state =
			&conn->protocol.data.state.receive_payload;
	const size_t chunk_size = RECV_DATA_BUFFER_SIZE;
	char data_buffer[chunk_size];
	bool partial_recv = false;
	bool new_stream = false, close_requested = false, index_flushed = false;
	uint64_t left_to_receive = state->left_to_receive;
	struct relay_session *session;

	DBG3("Receiving data for stream id %" PRIu64 " seqnum %" PRIu64 ", %" PRIu64" bytes received, %" PRIu64 " bytes left to receive",
			state->header.stream_id, state->header.net_seq_num,
			state->received, left_to_receive);

	stream = stream_get_by_id(state->header.stream_id);
	if (!stream) {
		/* Protocol error. */
		ERR("relay_process_data_receive_payload: cannot find stream %" PRIu64,
				state->header.stream_id);
		status = RELAY_CONNECTION_STATUS_ERROR;
		goto end;
	}

	pthread_mutex_lock(&stream->lock);
	session = stream->trace->session;
	if (!conn->session) {
		ret = connection_set_session(conn, session);
		if (ret) {
			status = RELAY_CONNECTION_STATUS_ERROR;
			goto end_stream_unlock;
		}
	}

	/*
	 * The size of the "chunk" received on any iteration is bounded by:
	 *   - the data left to receive,
	 *   - the data immediately available on the socket,
	 *   - the on-stack data buffer
	 */
	while (left_to_receive > 0 && !partial_recv) {
		size_t recv_size = min(left_to_receive, chunk_size);
		struct lttng_buffer_view packet_chunk;

		ret = conn->sock->ops->recvmsg(conn->sock, data_buffer,
				recv_size, MSG_DONTWAIT);
		if (ret < 0) {
			if (errno != EAGAIN && errno != EWOULDBLOCK) {
				PERROR("Socket %d error", conn->sock->fd);
				status = RELAY_CONNECTION_STATUS_ERROR;
			}
			goto end_stream_unlock;
		} else if (ret == 0) {
			/* No more data ready to be consumed on socket. */
			DBG3("No more data ready for consumption on data socket of stream id %" PRIu64,
					state->header.stream_id);
			status = RELAY_CONNECTION_STATUS_CLOSED;
			break;
		} else if (ret < (int) recv_size) {
			/*
			 * All the data available on the socket has been
			 * consumed.
			 */
			partial_recv = true;
			recv_size = ret;
		}

		packet_chunk = lttng_buffer_view_init(data_buffer,
				0, recv_size);
		assert(packet_chunk.data);

		ret = stream_write(stream, &packet_chunk, 0);
		if (ret) {
			ERR("Relay error writing data to file");
			status = RELAY_CONNECTION_STATUS_ERROR;
			goto end_stream_unlock;
		}

		left_to_receive -= recv_size;
		state->received += recv_size;
		state->left_to_receive = left_to_receive;
	}

	if (state->left_to_receive > 0) {
		/*
		 * Did not receive all the data expected, wait for more data to
		 * become available on the socket.
		 */
		DBG3("Partial receive on data connection of stream id %" PRIu64 ", %" PRIu64 " bytes received, %" PRIu64 " bytes left to receive",
				state->header.stream_id, state->received,
				state->left_to_receive);
		goto end_stream_unlock;
	}

	ret = stream_write(stream, NULL, state->header.padding_size);
	if (ret) {
		status = RELAY_CONNECTION_STATUS_ERROR;
		goto end_stream_unlock;
	}

	if (session_streams_have_index(session)) {
		ret = stream_update_index(stream, state->header.net_seq_num,
				state->rotate_index, &index_flushed,
				state->header.data_size + state->header.padding_size);
		if (ret < 0) {
			ERR("Failed to update index: stream %" PRIu64 " net_seq_num %" PRIu64 " ret %d",
					stream->stream_handle,
					state->header.net_seq_num, ret);
			status = RELAY_CONNECTION_STATUS_ERROR;
			goto end_stream_unlock;
		}
	}

	if (stream->prev_data_seq == -1ULL) {
		new_stream = true;
	}

	ret = stream_complete_packet(stream, state->header.data_size +
			state->header.padding_size, state->header.net_seq_num,
			index_flushed);
	if (ret) {
		status = RELAY_CONNECTION_STATUS_ERROR;
		goto end_stream_unlock;
	}

	/*
	 * Resetting the protocol state (to RECEIVE_HEADER) will trash the
	 * contents of *state which are aliased (union) to the same location as
	 * the new state. Don't use it beyond this point.
	 */
	connection_reset_protocol_state(conn);
	state = NULL;

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
	return status;
}

/*
 * relay_process_data: Process the data received on the data socket
 */
static enum relay_connection_status relay_process_data(
		struct relay_connection *conn)
{
	enum relay_connection_status status;

	switch (conn->protocol.data.state_id) {
	case DATA_CONNECTION_STATE_RECEIVE_HEADER:
		status = relay_process_data_receive_header(conn);
		break;
	case DATA_CONNECTION_STATE_RECEIVE_PAYLOAD:
		status = relay_process_data_receive_payload(conn);
		break;
	default:
		ERR("Unexpected data connection communication state.");
		abort();
	}

	return status;
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

	ret = create_named_thread_poll_set(&events, 2, "Worker thread epoll");
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
					ret = lttng_poll_add(&events,
							conn->sock->fd,
							LPOLLIN | LPOLLRDHUP);
					if (ret) {
						ERR("Failed to add new connection file descriptor to poll set");
						goto error;
					}
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
					enum relay_connection_status status;

					status = relay_process_control(ctrl_conn);
					if (status != RELAY_CONNECTION_STATUS_OK) {
						/*
						 * On socket error flag the session as aborted to force
						 * the cleanup of its stream otherwise it can leak
						 * during the lifetime of the relayd.
						 *
						 * This prevents situations in which streams can be
						 * left opened because an index was received, the
						 * control connection is closed, and the data
						 * connection is closed (uncleanly) before the packet's
						 * data provided.
						 *
						 * Since the control connection encountered an error,
						 * it is okay to be conservative and close the
						 * session right now as we can't rely on the protocol
						 * being respected anymore.
						 */
						if (status == RELAY_CONNECTION_STATUS_ERROR) {
							session_abort(ctrl_conn->session);
						}

						/* Clear the connection on error or close. */
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
				enum relay_connection_status status;

				status = relay_process_data(data_conn);
				/* Connection closed or error. */
				if (status != RELAY_CONNECTION_STATUS_OK) {
					/*
					 * On socket error flag the session as aborted to force
					 * the cleanup of its stream otherwise it can leak
					 * during the lifetime of the relayd.
					 *
					 * This prevents situations in which streams can be
					 * left opened because an index was received, the
					 * control connection is closed, and the data
					 * connection is closed (uncleanly) before the packet's
					 * data provided.
					 *
					 * Since the data connection encountered an error,
					 * it is okay to be conservative and close the
					 * session right now as we can't rely on the protocol
					 * being respected anymore.
					 */
					if (status == RELAY_CONNECTION_STATUS_ERROR) {
						session_abort(data_conn->session);
					}
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
	/* Cleanup remaining connection object. */
	rcu_read_lock();
	cds_lfht_for_each_entry(relay_connections_ht->ht, &iter.iter,
			destroy_conn,
			sock_n.node) {
		health_code_update();

		session_abort(destroy_conn->session);

		/*
		 * No need to grab another ref, because we own
		 * destroy_conn.
		 */
		relay_thread_close_connection(&events, destroy_conn->sock->fd,
				destroy_conn);
	}
	rcu_read_unlock();

	(void) fd_tracker_util_poll_clean(the_fd_tracker, &events);
error_poll_create:
	lttng_ht_destroy(relay_connections_ht);
relay_connections_ht_error:
	/* Close relay conn pipes */
	(void) fd_tracker_util_pipe_close(the_fd_tracker,
			relay_conn_pipe);
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
	return fd_tracker_util_pipe_open_cloexec(the_fd_tracker,
			"Relayd connection pipe", relay_conn_pipe);
}

/*
 * main
 */
int main(int argc, char **argv)
{
	bool thread_is_rcu_registered = false;
	int ret = 0, retval = 0;
	void *status;

	/* Parse environment variables */
	ret = parse_env_options();
	if (ret) {
		retval = -1;
		goto exit_options;
	}

	/*
	 * Parse arguments.
	 * Command line arguments overwrite environment.
	 */
	progname = argv[0];
	if (set_options(argc, argv)) {
		retval = -1;
		goto exit_options;
	}

	if (set_signal_handler()) {
		retval = -1;
		goto exit_options;
	}

	relayd_config_log();

	if (opt_print_version) {
		print_version();
		retval = 0;
		goto exit_options;
	}

	ret = fclose(stdin);
	if (ret) {
		PERROR("Failed to close stdin");
		goto exit_options;
	}

	DBG("Clear command %s", opt_allow_clear ? "allowed" : "disallowed");

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
		ret = lttng_daemonize(&child_ppid, &recv_child_signal,
			!opt_background);
		if (ret < 0) {
			retval = -1;
			goto exit_options;
		}
	}

	if (opt_working_directory) {
		ret = utils_change_working_directory(opt_working_directory);
		if (ret) {
			/* All errors are already logged. */
			goto exit_options;
		}
	}

	sessiond_trace_chunk_registry = sessiond_trace_chunk_registry_create();
	if (!sessiond_trace_chunk_registry) {
		ERR("Failed to initialize session daemon trace chunk registry");
		retval = -1;
		goto exit_options;
	}

	/*
	 * The RCU thread registration (and use, through the fd-tracker's
	 * creation) is done after the daemonization to allow us to not
	 * deal with liburcu's fork() management as the call RCU needs to
	 * be restored.
	 */
	rcu_register_thread();
	thread_is_rcu_registered = true;

	the_fd_tracker = fd_tracker_create(lttng_opt_fd_cap);
	if (!the_fd_tracker) {
		retval = -1;
		goto exit_options;
	}

	/* Initialize thread health monitoring */
	health_relayd = health_app_create(NR_HEALTH_RELAYD_TYPES);
	if (!health_relayd) {
		PERROR("health_app_create error");
		retval = -1;
		goto exit_options;
	}

	/* Create thread quit pipe */
	if (init_thread_quit_pipe()) {
		retval = -1;
		goto exit_options;
	}

	/* Setup the thread apps communication pipe. */
	if (create_relay_conn_pipe()) {
		retval = -1;
		goto exit_options;
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
		goto exit_options;
	}

	/* tables of streams indexed by stream ID */
	relay_streams_ht = lttng_ht_new(0, LTTNG_HT_TYPE_U64);
	if (!relay_streams_ht) {
		retval = -1;
		goto exit_options;
	}

	/* tables of streams indexed by stream ID */
	viewer_streams_ht = lttng_ht_new(0, LTTNG_HT_TYPE_U64);
	if (!viewer_streams_ht) {
		retval = -1;
		goto exit_options;
	}

	ret = init_health_quit_pipe();
	if (ret) {
		retval = -1;
		goto exit_options;
	}

	/* Create thread to manage the client socket */
	ret = pthread_create(&health_thread, default_pthread_attr(),
			thread_manage_health, (void *) NULL);
	if (ret) {
		errno = ret;
		PERROR("pthread_create health");
		retval = -1;
		goto exit_options;
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

	if (thread_is_rcu_registered) {
		rcu_unregister_thread();
	}

	if (!retval) {
		exit(EXIT_SUCCESS);
	} else {
		exit(EXIT_FAILURE);
	}
}
