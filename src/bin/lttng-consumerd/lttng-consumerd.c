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

#define _GNU_SOURCE
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
#include <config.h>
#include <urcu/compiler.h>
#include <ulimit.h>

#include <common/defaults.h>
#include <common/common.h>
#include <common/consumer.h>
#include <common/consumer-timer.h>
#include <common/compat/poll.h>
#include <common/sessiond-comm/sessiond-comm.h>
#include <common/utils.h>

#include "lttng-consumerd.h"
#include "health-consumerd.h"

/* TODO : support UST (all direct kernel-ctl accesses). */

/* threads (channel handling, poll, metadata, sessiond) */

static pthread_t channel_thread, data_thread, metadata_thread,
		sessiond_thread, metadata_timer_thread, health_thread;

/* to count the number of times the user pressed ctrl+c */
static int sigintcount = 0;

/* Argument variables */
int lttng_opt_quiet;    /* not static in error.h */
int lttng_opt_verbose;  /* not static in error.h */
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

	/*
	 * Ignore SIGPIPE because it should not stop the consumer whenever a
	 * SIGPIPE is catched through a FD operation.
	 */
	if (sig == SIGPIPE) {
		return;
	}

	lttng_consumer_should_exit(ctx);
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
		perror("sigemptyset");
		return ret;
	}

	sa.sa_handler = sighandler;
	sa.sa_mask = sigset;
	sa.sa_flags = 0;
	if ((ret = sigaction(SIGTERM, &sa, NULL)) < 0) {
		perror("sigaction");
		return ret;
	}

	if ((ret = sigaction(SIGINT, &sa, NULL)) < 0) {
		perror("sigaction");
		return ret;
	}

	if ((ret = sigaction(SIGPIPE, &sa, NULL)) < 0) {
		perror("sigaction");
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
static void parse_args(int argc, char **argv)
{
	int c;

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
		c = getopt_long(argc, argv, "dhqvVku" "c:e:g:", long_options, &option_index);
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
		case 'c':
			snprintf(command_sock_path, PATH_MAX, "%s", optarg);
			break;
		case 'e':
			snprintf(error_sock_path, PATH_MAX, "%s", optarg);
			break;
		case 'd':
			opt_daemon = 1;
			break;
		case 'g':
			tracing_group_name = optarg;
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
			exit(EXIT_FAILURE);
		}
	}
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
	int ret = 0;
	void *status;

	/* Parse arguments */
	progname = argv[0];
	parse_args(argc, argv);

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
			goto error;
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

	/* Set up max poll set size */
	lttng_poll_set_max_size();

	if (*command_sock_path == '\0') {
		switch (opt_type) {
		case LTTNG_CONSUMER_KERNEL:
			snprintf(command_sock_path, PATH_MAX, DEFAULT_KCONSUMERD_CMD_SOCK_PATH,
					DEFAULT_LTTNG_RUNDIR);
			break;
		case LTTNG_CONSUMER64_UST:
			snprintf(command_sock_path, PATH_MAX,
					DEFAULT_USTCONSUMERD64_CMD_SOCK_PATH, DEFAULT_LTTNG_RUNDIR);
			break;
		case LTTNG_CONSUMER32_UST:
			snprintf(command_sock_path, PATH_MAX,
					DEFAULT_USTCONSUMERD32_CMD_SOCK_PATH, DEFAULT_LTTNG_RUNDIR);
			break;
		default:
			WARN("Unknown consumerd type");
			goto error;
		}
	}

	/* Init */
	lttng_consumer_init();
	/* Init socket timeouts */
	lttcomm_init();
	lttcomm_inet_init();

	if (!getuid()) {
		/* Set limit for open files */
		set_ulimit();
	}

	health_consumerd = health_app_create(NR_HEALTH_CONSUMERD_TYPES);
	if (!health_consumerd) {
		goto error;
	}

	/* create the consumer instance with and assign the callbacks */
	ctx = lttng_consumer_create(opt_type, lttng_consumer_read_subbuffer,
		NULL, lttng_consumer_on_recv_stream, NULL);
	if (ctx == NULL) {
		goto error;
	}

	lttng_consumer_set_command_sock_path(ctx, command_sock_path);
	if (*error_sock_path == '\0') {
		switch (opt_type) {
		case LTTNG_CONSUMER_KERNEL:
			snprintf(error_sock_path, PATH_MAX, DEFAULT_KCONSUMERD_ERR_SOCK_PATH,
					DEFAULT_LTTNG_RUNDIR);
			break;
		case LTTNG_CONSUMER64_UST:
			snprintf(error_sock_path, PATH_MAX,
					DEFAULT_USTCONSUMERD64_ERR_SOCK_PATH, DEFAULT_LTTNG_RUNDIR);
			break;
		case LTTNG_CONSUMER32_UST:
			snprintf(error_sock_path, PATH_MAX,
					DEFAULT_USTCONSUMERD32_ERR_SOCK_PATH, DEFAULT_LTTNG_RUNDIR);
			break;
		default:
			WARN("Unknown consumerd type");
			goto error;
		}
	}

	if (set_signal_handler() < 0) {
		goto error;
	}

	/* Connect to the socket created by lttng-sessiond to report errors */
	DBG("Connecting to error socket %s", error_sock_path);
	ret = lttcomm_connect_unix_sock(error_sock_path);
	/* not a fatal error, but all communication with lttng-sessiond will fail */
	if (ret < 0) {
		WARN("Cannot connect to error socket (is lttng-sessiond started?)");
	}
	lttng_consumer_set_error_sock(ctx, ret);

	/*
	 * Block RT signals used for UST periodical metadata flush and the live
	 * timer in main, and create a dedicated thread to handle these signals.
	 */
	consumer_signal_init();

	ctx->type = opt_type;

	/* Initialize communication library */
	lttcomm_init();

	ret = utils_create_pipe(health_quit_pipe);
	if (ret < 0) {
		goto error_health_pipe;
	}

	/* Create thread to manage the client socket */
	ret = pthread_create(&health_thread, NULL,
			thread_manage_health, (void *) NULL);
	if (ret != 0) {
		PERROR("pthread_create health");
		goto health_error;
	}

	/* Create thread to manage channels */
	ret = pthread_create(&channel_thread, NULL, consumer_thread_channel_poll,
			(void *) ctx);
	if (ret != 0) {
		perror("pthread_create");
		goto channel_error;
	}

	/* Create thread to manage the polling/writing of trace metadata */
	ret = pthread_create(&metadata_thread, NULL, consumer_thread_metadata_poll,
			(void *) ctx);
	if (ret != 0) {
		perror("pthread_create");
		goto metadata_error;
	}

	/* Create thread to manage the polling/writing of trace data */
	ret = pthread_create(&data_thread, NULL, consumer_thread_data_poll,
			(void *) ctx);
	if (ret != 0) {
		perror("pthread_create");
		goto data_error;
	}

	/* Create the thread to manage the receive of fd */
	ret = pthread_create(&sessiond_thread, NULL, consumer_thread_sessiond_poll,
			(void *) ctx);
	if (ret != 0) {
		perror("pthread_create");
		goto sessiond_error;
	}

	/*
	 * Create the thread to manage the UST metadata periodic timer and
	 * live timer.
	 */
	ret = pthread_create(&metadata_timer_thread, NULL,
			consumer_timer_thread, (void *) ctx);
	if (ret != 0) {
		perror("pthread_create");
		goto metadata_timer_error;
	}

	ret = pthread_detach(metadata_timer_thread);
	if (ret) {
		errno = ret;
		perror("pthread_detach");
	}

metadata_timer_error:
	ret = pthread_join(sessiond_thread, &status);
	if (ret != 0) {
		perror("pthread_join");
		goto error;
	}

sessiond_error:
	ret = pthread_join(data_thread, &status);
	if (ret != 0) {
		perror("pthread_join");
		goto error;
	}

data_error:
	ret = pthread_join(metadata_thread, &status);
	if (ret != 0) {
		perror("pthread_join");
		goto error;
	}

metadata_error:
	ret = pthread_join(channel_thread, &status);
	if (ret != 0) {
		perror("pthread_join");
		goto error;
	}

channel_error:
	ret = pthread_join(health_thread, &status);
	if (ret != 0) {
		PERROR("pthread_join health thread");
		goto error;	/* join error, exit without cleanup */
	}

health_error:
	utils_close_pipe(health_quit_pipe);

error_health_pipe:
	if (!ret) {
		ret = EXIT_SUCCESS;
		lttng_consumer_send_error(ctx, LTTCOMM_CONSUMERD_EXIT_SUCCESS);
		goto end;
	}

error:
	ret = EXIT_FAILURE;
	if (ctx) {
		lttng_consumer_send_error(ctx, LTTCOMM_CONSUMERD_EXIT_FAILURE);
	}

end:
	lttng_consumer_destroy(ctx);
	lttng_consumer_cleanup();
	if (health_consumerd) {
		health_app_destroy(health_consumerd);
	}

	return ret;
}
