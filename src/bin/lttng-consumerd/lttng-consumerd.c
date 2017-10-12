/*
 * Copyright (C) 2011 - Julien Desfossez <julien.desfossez@polymtl.ca>
 *                      Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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
#include <fcntl.h>
#include <getopt.h>
#include <grp.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/resource.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <urcu/list.h>
#include <poll.h>
#include <unistd.h>
#include <sys/mman.h>
#include <assert.h>
#include <urcu/compiler.h>
#include <ulimit.h>

#include <common/defaults.h>
#include <common/common.h>
#include <common/consumer/consumer.h>
#include <common/consumer/consumer-timer.h>
#include <common/compat/poll.h>
#include <common/compat/getenv.h>
#include <common/sessiond-comm/sessiond-comm.h>
#include <common/utils.h>

#include "lttng-consumerd.h"
#include "health-consumerd.h"

/* threads (channel handling, poll, metadata, sessiond) */

static pthread_t channel_thread, data_thread, metadata_thread,
		sessiond_thread, metadata_timer_thread, health_thread;
static bool metadata_timer_thread_online;

/* to count the number of times the user pressed ctrl+c */
static int sigintcount = 0;

/* Argument variables */
int lttng_opt_quiet;    /* not static in error.h */
int lttng_opt_verbose;  /* not static in error.h */
int lttng_opt_mi;       /* not static in error.h */

static int opt_daemon;
static const char *progname;
static char command_sock_path[PATH_MAX]; /* Global command socket path */
static char error_sock_path[PATH_MAX]; /* Global error path */
static enum lttng_consumer_type opt_type = LTTNG_CONSUMER_KERNEL;

/* the liblttngconsumerd context */
static struct lttng_consumer_local_data *ctx;

/* Consumerd health monitoring */
struct health_app *health_consumerd;

const char *tracing_group_name = DEFAULT_TRACING_GROUP;

int lttng_consumer_ready = NR_LTTNG_CONSUMER_READY;

enum lttng_consumer_type lttng_consumer_get_type(void)
{
	if (!ctx) {
		return LTTNG_CONSUMER_UNKNOWN;
	}
	return ctx->type;
}

/*
 * Signal handler for the daemon
 */
static void sighandler(int sig)
{
	if (sig == SIGINT && sigintcount++ == 0) {
		DBG("ignoring first SIGINT");
		return;
	}

	if (ctx) {
		lttng_consumer_should_exit(ctx);
	}
}

/*
 * Setup signal handler for :
 *      SIGINT, SIGTERM, SIGPIPE
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

	sa.sa_handler = SIG_IGN;
	if ((ret = sigaction(SIGPIPE, &sa, NULL)) < 0) {
		PERROR("sigaction");
		return ret;
	}

	return ret;
}

/*
 * Usage function on stream file.
 */
static void usage(FILE *fp)
{
	fprintf(fp, "Usage: %s OPTIONS\n\nOptions:\n", progname);
	fprintf(fp, "  -h, --help                         "
			"Display this usage.\n");
	fprintf(fp, "  -c, --consumerd-cmd-sock PATH      "
			"Specify path for the command socket\n");
	fprintf(fp, "  -e, --consumerd-err-sock PATH      "
			"Specify path for the error socket\n");
	fprintf(fp, "  -d, --daemonize                    "
			"Start as a daemon.\n");
	fprintf(fp, "  -q, --quiet                        "
			"No output at all.\n");
	fprintf(fp, "  -v, --verbose                      "
			"Verbose mode. Activate DBG() macro.\n");
	fprintf(fp, "  -V, --version                      "
			"Show version number.\n");
	fprintf(fp, "  -g, --group NAME                   "
			"Specify the tracing group name. (default: tracing)\n");
	fprintf(fp, "  -k, --kernel                       "
			"Consumer kernel buffers (default).\n");
	fprintf(fp, "  -u, --ust                          "
			"Consumer UST buffers.%s\n",
#ifdef HAVE_LIBLTTNG_UST_CTL
			""
#else
			" (support not compiled in)"
#endif
			);
}

/*
 * daemon argument parsing
 */
static int parse_args(int argc, char **argv)
{
	int c, ret = 0;

	static struct option long_options[] = {
		{ "consumerd-cmd-sock", 1, 0, 'c' },
		{ "consumerd-err-sock", 1, 0, 'e' },
		{ "daemonize", 0, 0, 'd' },
		{ "group", 1, 0, 'g' },
		{ "help", 0, 0, 'h' },
		{ "quiet", 0, 0, 'q' },
		{ "verbose", 0, 0, 'v' },
		{ "version", 0, 0, 'V' },
		{ "kernel", 0, 0, 'k' },
#ifdef HAVE_LIBLTTNG_UST_CTL
		{ "ust", 0, 0, 'u' },
#endif
		{ NULL, 0, 0, 0 }
	};

	while (1) {
		int option_index = 0;
		c = getopt_long(argc, argv, "dhqvVku" "c:e:g:",
				long_options, &option_index);
		if (c == -1) {
			break;
		}

		switch (c) {
		case 0:
			fprintf(stderr, "option %s",
				long_options[option_index].name);
			if (optarg) {
				fprintf(stderr, " with arg %s\n", optarg);
				ret = -1;
				goto end;
			}
			break;
		case 'c':
			if (lttng_is_setuid_setgid()) {
				WARN("Getting '%s' argument from setuid/setgid binary refused for security reasons.",
					"-c, --consumerd-cmd-sock");
			} else {
				snprintf(command_sock_path, PATH_MAX, "%s", optarg);
			}
			break;
		case 'e':
			if (lttng_is_setuid_setgid()) {
				WARN("Getting '%s' argument from setuid/setgid binary refused for security reasons.",
					"-e, --consumerd-err-sock");
			} else {
				snprintf(error_sock_path, PATH_MAX, "%s", optarg);
			}
			break;
		case 'd':
			opt_daemon = 1;
			break;
		case 'g':
			if (lttng_is_setuid_setgid()) {
				WARN("Getting '%s' argument from setuid/setgid binary refused for security reasons.",
					"-g, --group");
			} else {
				tracing_group_name = optarg;
			}
			break;
		case 'h':
			usage(stdout);
			exit(EXIT_SUCCESS);
		case 'q':
			lttng_opt_quiet = 1;
			break;
		case 'v':
			lttng_opt_verbose = 1;
			break;
		case 'V':
			fprintf(stdout, "%s\n", VERSION);
			exit(EXIT_SUCCESS);
		case 'k':
			opt_type = LTTNG_CONSUMER_KERNEL;
			break;
#ifdef HAVE_LIBLTTNG_UST_CTL
		case 'u':
# if (CAA_BITS_PER_LONG == 64)
			opt_type = LTTNG_CONSUMER64_UST;
# elif (CAA_BITS_PER_LONG == 32)
			opt_type = LTTNG_CONSUMER32_UST;
# else
#  error "Unknown bitness"
# endif
			break;
#endif
		default:
			usage(stderr);
			ret = -1;
			goto end;
		}
	}
end:
	return ret;
}

/*
 * Set open files limit to unlimited. This daemon can open a large number of
 * file descriptors in order to consumer multiple kernel traces.
 */
static void set_ulimit(void)
{
	int ret;
	struct rlimit lim;

	/* The kernel does not allowed an infinite limit for open files */
	lim.rlim_cur = 65535;
	lim.rlim_max = 65535;

	ret = setrlimit(RLIMIT_NOFILE, &lim);
	if (ret < 0) {
		PERROR("failed to set open files limit");
	}
}

/*
 * main
 */
int main(int argc, char **argv)
{
	int ret = 0, retval = 0;
	void *status;
	struct lttng_consumer_local_data *tmp_ctx;

	rcu_register_thread();

	if (set_signal_handler()) {
		retval = -1;
		goto exit_set_signal_handler;
	}

	/* Parse arguments */
	progname = argv[0];
	if (parse_args(argc, argv)) {
		retval = -1;
		goto exit_options;
	}

	/* Daemonize */
	if (opt_daemon) {
		int i;

		/*
		 * fork
		 * child: setsid, close FD 0, 1, 2, chdir /
		 * parent: exit (if fork is successful)
		 */
		ret = daemon(0, 0);
		if (ret < 0) {
			PERROR("daemon");
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

	/*
	 * Starting from here, we can create threads. This needs to be after
	 * lttng_daemonize due to RCU.
	 */

	health_consumerd = health_app_create(NR_HEALTH_CONSUMERD_TYPES);
	if (!health_consumerd) {
		retval = -1;
		goto exit_health_consumerd_cleanup;
	}

	if (*command_sock_path == '\0') {
		switch (opt_type) {
		case LTTNG_CONSUMER_KERNEL:
			ret = snprintf(command_sock_path, PATH_MAX,
					DEFAULT_KCONSUMERD_CMD_SOCK_PATH,
					DEFAULT_LTTNG_RUNDIR);
			if (ret < 0) {
				retval = -1;
				goto exit_init_data;
			}
			break;
		case LTTNG_CONSUMER64_UST:
			ret = snprintf(command_sock_path, PATH_MAX,
					DEFAULT_USTCONSUMERD64_CMD_SOCK_PATH,
					DEFAULT_LTTNG_RUNDIR);
			if (ret < 0) {
				retval = -1;
				goto exit_init_data;
			}
			break;
		case LTTNG_CONSUMER32_UST:
			ret = snprintf(command_sock_path, PATH_MAX,
					DEFAULT_USTCONSUMERD32_CMD_SOCK_PATH,
					DEFAULT_LTTNG_RUNDIR);
			if (ret < 0) {
				retval = -1;
				goto exit_init_data;
			}
			break;
		default:
			ERR("Unknown consumerd type");
			retval = -1;
			goto exit_init_data;
		}
	}

	/* Init */
	if (lttng_consumer_init()) {
		retval = -1;
		goto exit_init_data;
	}

	/* Initialize communication library */
	lttcomm_init();
	/* Initialize TCP timeout values */
	lttcomm_inet_init();

	if (!getuid()) {
		/* Set limit for open files */
		set_ulimit();
	}

	if (run_as_create_worker(argv[0]) < 0) {
		goto exit_init_data;
	}

	/* create the consumer instance with and assign the callbacks */
	ctx = lttng_consumer_create(opt_type, lttng_consumer_read_subbuffer,
		NULL, lttng_consumer_on_recv_stream, NULL);
	if (!ctx) {
		retval = -1;
		goto exit_init_data;
	}

	lttng_consumer_set_command_sock_path(ctx, command_sock_path);
	if (*error_sock_path == '\0') {
		switch (opt_type) {
		case LTTNG_CONSUMER_KERNEL:
			ret = snprintf(error_sock_path, PATH_MAX,
					DEFAULT_KCONSUMERD_ERR_SOCK_PATH,
					DEFAULT_LTTNG_RUNDIR);
			if (ret < 0) {
				retval = -1;
				goto exit_init_data;
			}
			break;
		case LTTNG_CONSUMER64_UST:
			ret = snprintf(error_sock_path, PATH_MAX,
					DEFAULT_USTCONSUMERD64_ERR_SOCK_PATH,
					DEFAULT_LTTNG_RUNDIR);
			if (ret < 0) {
				retval = -1;
				goto exit_init_data;
			}
			break;
		case LTTNG_CONSUMER32_UST:
			ret = snprintf(error_sock_path, PATH_MAX,
					DEFAULT_USTCONSUMERD32_ERR_SOCK_PATH,
					DEFAULT_LTTNG_RUNDIR);
			if (ret < 0) {
				retval = -1;
				goto exit_init_data;
			}
			break;
		default:
			ERR("Unknown consumerd type");
			retval = -1;
			goto exit_init_data;
		}
	}

	/* Connect to the socket created by lttng-sessiond to report errors */
	DBG("Connecting to error socket %s", error_sock_path);
	ret = lttcomm_connect_unix_sock(error_sock_path);
	/*
	 * Not a fatal error, but all communication with lttng-sessiond will
	 * fail.
	 */
	if (ret < 0) {
		WARN("Cannot connect to error socket (is lttng-sessiond started?)");
	}
	lttng_consumer_set_error_sock(ctx, ret);

	/*
	 * Block RT signals used for UST periodical metadata flush and the live
	 * timer in main, and create a dedicated thread to handle these signals.
	 */
	if (consumer_signal_init()) {
		retval = -1;
		goto exit_init_data;
	}

	ctx->type = opt_type;

	if (utils_create_pipe(health_quit_pipe)) {
		retval = -1;
		goto exit_health_pipe;
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

	/*
	 * Wait for health thread to be initialized before letting the
	 * sessiond thread reply to the sessiond that we are ready.
	 */
	while (uatomic_read(&lttng_consumer_ready)) {
		usleep(100000);
	}
	cmm_smp_mb();	/* Read ready before following operations */

	/*
	 * Create the thread to manage the UST metadata periodic timer and
	 * live timer.
	 */
	ret = pthread_create(&metadata_timer_thread, NULL,
			consumer_timer_thread, (void *) ctx);
	if (ret) {
		errno = ret;
		PERROR("pthread_create");
		retval = -1;
		goto exit_metadata_timer_thread;
	}
	metadata_timer_thread_online = true;

	/* Create thread to manage channels */
	ret = pthread_create(&channel_thread, default_pthread_attr(),
			consumer_thread_channel_poll,
			(void *) ctx);
	if (ret) {
		errno = ret;
		PERROR("pthread_create");
		retval = -1;
		goto exit_channel_thread;
	}

	/* Create thread to manage the polling/writing of trace metadata */
	ret = pthread_create(&metadata_thread, default_pthread_attr(),
			consumer_thread_metadata_poll,
			(void *) ctx);
	if (ret) {
		errno = ret;
		PERROR("pthread_create");
		retval = -1;
		goto exit_metadata_thread;
	}

	/* Create thread to manage the polling/writing of trace data */
	ret = pthread_create(&data_thread, default_pthread_attr(),
			consumer_thread_data_poll, (void *) ctx);
	if (ret) {
		errno = ret;
		PERROR("pthread_create");
		retval = -1;
		goto exit_data_thread;
	}

	/* Create the thread to manage the reception of fds */
	ret = pthread_create(&sessiond_thread, default_pthread_attr(),
			consumer_thread_sessiond_poll,
			(void *) ctx);
	if (ret) {
		errno = ret;
		PERROR("pthread_create");
		retval = -1;
		goto exit_sessiond_thread;
	}


	/*
	 * This is where we start awaiting program completion (e.g. through
	 * signal that asks threads to teardown.
	 */

	ret = pthread_join(sessiond_thread, &status);
	if (ret) {
		errno = ret;
		PERROR("pthread_join sessiond_thread");
		retval = -1;
	}
exit_sessiond_thread:

	ret = pthread_join(data_thread, &status);
	if (ret) {
		errno = ret;
		PERROR("pthread_join data_thread");
		retval = -1;
	}
exit_data_thread:

	ret = pthread_join(metadata_thread, &status);
	if (ret) {
		errno = ret;
		PERROR("pthread_join metadata_thread");
		retval = -1;
	}
exit_metadata_thread:

	ret = pthread_join(channel_thread, &status);
	if (ret) {
		errno = ret;
		PERROR("pthread_join channel_thread");
		retval = -1;
	}
exit_channel_thread:

exit_metadata_timer_thread:

	ret = pthread_join(health_thread, &status);
	if (ret) {
		errno = ret;
		PERROR("pthread_join health_thread");
		retval = -1;
	}
exit_health_thread:

	utils_close_pipe(health_quit_pipe);
exit_health_pipe:

exit_init_data:
	/*
	 * Wait for all pending call_rcu work to complete before tearing
	 * down data structures. call_rcu worker may be trying to
	 * perform lookups in those structures.
	 */
	rcu_barrier();
	lttng_consumer_cleanup();
	/*
	 * Tearing down the metadata timer thread in a
	 * non-fully-symmetric fashion compared to its creation in case
	 * lttng_consumer_cleanup() ends up tearing down timers (which
	 * requires the timer thread to be alive).
	 */
	if (metadata_timer_thread_online) {
		/*
		 * Ensure the metadata timer thread exits only after all other
		 * threads are gone, because it is required to perform timer
		 * teardown synchronization.
		 */
		kill(getpid(), LTTNG_CONSUMER_SIG_EXIT);
		ret = pthread_join(metadata_timer_thread, &status);
		if (ret) {
			errno = ret;
			PERROR("pthread_join metadata_timer_thread");
			retval = -1;
		}
		ret = consumer_timer_thread_get_channel_monitor_pipe();
		if (ret >= 0) {
			ret = close(ret);
			if (ret) {
				PERROR("close channel monitor pipe");
			}
		}
		metadata_timer_thread_online = false;
	}
	tmp_ctx = ctx;
	ctx = NULL;
	cmm_barrier();	/* Clear ctx for signal handler. */
	lttng_consumer_destroy(tmp_ctx);

	if (health_consumerd) {
		health_app_destroy(health_consumerd);
	}
	/* Ensure all prior call_rcu are done. */
	rcu_barrier();

	run_as_destroy_worker();

exit_health_consumerd_cleanup:
exit_options:
exit_set_signal_handler:

	rcu_unregister_thread();

	if (!retval) {
		exit(EXIT_SUCCESS);
	} else {
		exit(EXIT_FAILURE);
	}
}
