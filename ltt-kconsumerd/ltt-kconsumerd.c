/*
 * Copyright (C) 2011 - Julien Desfossez <julien.desfossez@polymtl.ca>
 *                      Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
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

#include "lttngerr.h"
#include "libkernelctl.h"
#include "liblttkconsumerd.h"

/* the two threads (receive fd and poll) */
pthread_t threads[2];

/* to count the number of time the user pressed ctrl+c */
static int sigintcount = 0;

/* Argument variables */
int opt_quiet;
int opt_verbose;
static int opt_daemon;
static const char *progname;
char command_sock_path[PATH_MAX]; /* Global command socket path */
char error_sock_path[PATH_MAX]; /* Global error path */

/*
 *  sighandler
 *
 *  Signal handler for the daemon
 */
static void sighandler(int sig)
{
	if (sig == SIGINT && sigintcount++ == 0) {
		DBG("ignoring first SIGINT");
		return;
	}

	kconsumerd_cleanup();
}

/*
 *  set_signal_handler
 *
 *  Setup signal handler for :
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
	fprintf(stderr, "  -c, --kconsumerd-cmd-sock PATH     "
			"Specify path for the command socket\n");
	fprintf(stderr, "  -e, --kconsumerd-err-sock PATH     "
			"Specify path for the error socket\n");
	fprintf(stderr, "  -d, --daemonize                    "
			"Start as a daemon.\n");
	fprintf(stderr, "  -q, --quiet                        "
			"No output at all.\n");
	fprintf(stderr, "  -v, --verbose                      "
			"Verbose mode. Activate DBG() macro.\n");
	fprintf(stderr, "  -V, --version                      "
			"Show version number.\n");
}

/*
 * daemon argument parsing
 */
static void parse_args(int argc, char **argv)
{
	int c;

	static struct option long_options[] = {
		{ "kconsumerd-cmd-sock", 1, 0, 'c' },
		{ "kconsumerd-err-sock", 1, 0, 'e' },
		{ "daemonize", 0, 0, 'd' },
		{ "help", 0, 0, 'h' },
		{ "quiet", 0, 0, 'q' },
		{ "verbose", 0, 0, 'v' },
		{ "version", 0, 0, 'V' },
		{ NULL, 0, 0, 0 }
	};

	while (1) {
		int option_index = 0;
		c = getopt_long(argc, argv, "dhqvV" "c:e:", long_options, &option_index);
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
		snprintf(command_sock_path, PATH_MAX,
				KCONSUMERD_CMD_SOCK_PATH);
	}
	kconsumerd_set_command_socket_path(command_sock_path);
	if (strlen(error_sock_path) == 0) {
		snprintf(error_sock_path, PATH_MAX,
				KCONSUMERD_ERR_SOCK_PATH);
	}

	if (set_signal_handler() < 0) {
		goto error;
	}

	/* create the pipe to wake to polling thread when needed */
	ret = kconsumerd_create_poll_pipe();
	if (ret < 0) {
		perror("Error creating poll pipe");
		goto end;
	}

	/* Connect to the socket created by ltt-sessiond to report errors */
	DBG("Connecting to error socket %s", error_sock_path);
	ret = lttcomm_connect_unix_sock(error_sock_path);
	/* not a fatal error, but all communication with ltt-sessiond will fail */
	if (ret < 0) {
		WARN("Cannot connect to error socket, is ltt-sessiond started ?");
	}
	kconsumerd_set_error_socket(ret);

	/* Create the thread to manage the receive of fd */
	ret = pthread_create(&threads[0], NULL, kconsumerd_thread_receive_fds,
			(void *) NULL);
	if (ret != 0) {
		perror("pthread_create");
		goto error;
	}

	/* Create thread to manage the polling/writing of traces */
	ret = pthread_create(&threads[1], NULL, kconsumerd_thread_poll_fds,
			(void *) NULL);
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
	kconsumerd_send_error(KCONSUMERD_EXIT_SUCCESS);
	goto end;

error:
	ret = EXIT_FAILURE;
	kconsumerd_send_error(KCONSUMERD_EXIT_FAILURE);

end:
	kconsumerd_cleanup();

	return ret;
}
