/*
 * Copyright (C) 2011 - Julien Desfossez <julien.desfossez@polymtl.ca>
 *                      Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; only version 2
 * of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
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

#include <common/defaults.h>
#include <common/common.h>
#include <common/kernel-consumer/kernel-consumer.h>
#include <common/kernel-ctl/kernel-ctl.h>
#include <common/sessiond-comm/sessiond-comm.h>
#include <common/ust-consumer/ust-consumer.h>

#include "lttng-consumerd.h"

/* TODO : support UST (all direct kernctl accesses). */

/* the two threads (receive fd and poll) */
static pthread_t threads[2];

/* to count the number of time the user pressed ctrl+c */
static int sigintcount = 0;

/* Argument variables */
int opt_quiet;
int opt_verbose;
static int opt_daemon;
static const char *progname;
static char command_sock_path[PATH_MAX]; /* Global command socket path */
static char error_sock_path[PATH_MAX]; /* Global error path */
static enum lttng_consumer_type opt_type = LTTNG_CONSUMER_KERNEL;

/* the liblttngconsumerd context */
static struct lttng_consumer_local_data *ctx;

/*
 * Signal handler for the daemon
 */
static void sighandler(int sig)
{
	if (sig == SIGINT && sigintcount++ == 0) {
		DBG("ignoring first SIGINT");
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
 * usage function on stderr
 */
static void usage(void)
{
	fprintf(stderr, "Usage: %s OPTIONS\n\nOptions:\n", progname);
	fprintf(stderr, "  -h, --help                         "
			"Display this usage.\n");
	fprintf(stderr, "  -c, --consumerd-cmd-sock PATH     "
			"Specify path for the command socket\n");
	fprintf(stderr, "  -e, --consumerd-err-sock PATH     "
			"Specify path for the error socket\n");
	fprintf(stderr, "  -d, --daemonize                    "
			"Start as a daemon.\n");
	fprintf(stderr, "  -q, --quiet                        "
			"No output at all.\n");
	fprintf(stderr, "  -v, --verbose                      "
			"Verbose mode. Activate DBG() macro.\n");
	fprintf(stderr, "  -V, --version                      "
			"Show version number.\n");
	fprintf(stderr, "  -k, --kernel                       "
			"Consumer kernel buffers (default).\n");
	fprintf(stderr, "  -u, --ust                          "
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
		c = getopt_long(argc, argv, "dhqvVku" "c:e:", long_options, &option_index);
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
		case 'h':
			usage();
			exit(EXIT_FAILURE);
		case 'q':
			opt_quiet = 1;
			break;
		case 'v':
			opt_verbose = 1;
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
			usage();
			exit(EXIT_FAILURE);
		}
	}
}

/*
 * main
 */
int main(int argc, char **argv)
{
	int i;
	int ret = 0;
	void *status;

	/* Parse arguments */
	progname = argv[0];
	parse_args(argc, argv);

	/* Daemonize */
	if (opt_daemon) {
		ret = daemon(0, 0);
		if (ret < 0) {
			perror("daemon");
			goto error;
		}
	}

	if (strlen(command_sock_path) == 0) {
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

	/* create the consumer instance with and assign the callbacks */
	ctx = lttng_consumer_create(opt_type, lttng_consumer_read_subbuffer,
		NULL, lttng_consumer_on_recv_stream, NULL);
	if (ctx == NULL) {
		goto error;
	}

	lttng_consumer_set_command_sock_path(ctx, command_sock_path);
	if (strlen(error_sock_path) == 0) {
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
		WARN("Cannot connect to error socket, is lttng-sessiond started ?");
	}
	lttng_consumer_set_error_sock(ctx, ret);

	/* Create the thread to manage the receive of fd */
	ret = pthread_create(&threads[0], NULL, lttng_consumer_thread_receive_fds,
			(void *) ctx);
	if (ret != 0) {
		perror("pthread_create");
		goto error;
	}

	/* Create thread to manage the polling/writing of traces */
	ret = pthread_create(&threads[1], NULL, lttng_consumer_thread_poll_fds,
			(void *) ctx);
	if (ret != 0) {
		perror("pthread_create");
		goto error;
	}

	for (i = 0; i < 2; i++) {
		ret = pthread_join(threads[i], &status);
		if (ret != 0) {
			perror("pthread_join");
			goto error;
		}
	}
	ret = EXIT_SUCCESS;
	lttng_consumer_send_error(ctx, CONSUMERD_EXIT_SUCCESS);
	goto end;

error:
	ret = EXIT_FAILURE;
	lttng_consumer_send_error(ctx, CONSUMERD_EXIT_FAILURE);

end:
	lttng_consumer_destroy(ctx);
	lttng_consumer_cleanup();

	return ret;
}
