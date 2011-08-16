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

#include <lttng/lttng-kconsumerd.h>

#include "lttngerr.h"
#include "kernelctl.h"
#include "ltt-kconsumerd.h"
#include "lttng-sessiond-comm.h"

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

/* the liblttngkconsumerd context */
static struct lttng_kconsumerd_local_data *ctx;

/*
 * Signal handler for the daemon
 */
static void sighandler(int sig)
{
	if (sig == SIGINT && sigintcount++ == 0) {
		DBG("ignoring first SIGINT");
		return;
	}

	lttng_kconsumerd_should_exit(ctx);
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
 * Consume data on a file descriptor and write it on a trace file.
 */
static int read_subbuffer(struct lttng_kconsumerd_fd *kconsumerd_fd)
{
	unsigned long len;
	int err;
	long ret = 0;
	int infd = kconsumerd_fd->consumerd_fd;

	DBG("In kconsumerd_read_subbuffer (infd : %d)", infd);
	/* Get the next subbuffer */
	err = kernctl_get_next_subbuf(infd);
	if (err != 0) {
		ret = errno;
		/*
		 * This is a debug message even for single-threaded consumer,
		 * because poll() have more relaxed criterions than get subbuf,
		 * so get_subbuf may fail for short race windows where poll()
		 * would issue wakeups.
		 */
		DBG("Reserving sub buffer failed (everything is normal, "
				"it is due to concurrency)");
		goto end;
	}

	switch (kconsumerd_fd->output) {
		case LTTNG_EVENT_SPLICE:
			/* read the whole subbuffer */
			err = kernctl_get_padded_subbuf_size(infd, &len);
			if (err != 0) {
				ret = errno;
				perror("Getting sub-buffer len failed.");
				goto end;
			}

			/* splice the subbuffer to the tracefile */
			ret = lttng_kconsumerd_on_read_subbuffer_splice(ctx, kconsumerd_fd, len);
			if (ret < 0) {
				/*
				 * display the error but continue processing to try
				 * to release the subbuffer
				 */
				ERR("Error splicing to tracefile");
			}
			break;
		case LTTNG_EVENT_MMAP:
			/* read the used subbuffer size */
			err = kernctl_get_padded_subbuf_size(infd, &len);
			if (err != 0) {
				ret = errno;
				perror("Getting sub-buffer len failed.");
				goto end;
			}
			/* write the subbuffer to the tracefile */
			ret = lttng_kconsumerd_on_read_subbuffer_mmap(ctx, kconsumerd_fd, len);
			if (ret < 0) {
				/*
				 * display the error but continue processing to try
				 * to release the subbuffer
				 */
				ERR("Error writing to tracefile");
			}
			break;
		default:
			ERR("Unknown output method");
			ret = -1;
	}

	err = kernctl_put_next_subbuf(infd);
	if (err != 0) {
		ret = errno;
		if (errno == EFAULT) {
			perror("Error in unreserving sub buffer\n");
		} else if (errno == EIO) {
			/* Should never happen with newer LTTng versions */
			perror("Reader has been pushed by the writer, last sub-buffer corrupted.");
		}
		goto end;
	}

end:
	return ret;
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
	/* create the pipe to wake to receiving thread when needed */
	ctx = lttng_kconsumerd_create(read_subbuffer);
	if (ctx == NULL) {
		goto error;
	}

	lttng_kconsumerd_set_command_sock_path(ctx, command_sock_path);
	if (strlen(error_sock_path) == 0) {
		snprintf(error_sock_path, PATH_MAX,
				KCONSUMERD_ERR_SOCK_PATH);
	}

	if (set_signal_handler() < 0) {
		goto error;
	}

	/* Connect to the socket created by ltt-sessiond to report errors */
	DBG("Connecting to error socket %s", error_sock_path);
	ret = lttcomm_connect_unix_sock(error_sock_path);
	/* not a fatal error, but all communication with ltt-sessiond will fail */
	if (ret < 0) {
		WARN("Cannot connect to error socket, is ltt-sessiond started ?");
	}
	lttng_kconsumerd_set_error_sock(ctx, ret);

	/* Create the thread to manage the receive of fd */
	ret = pthread_create(&threads[0], NULL, lttng_kconsumerd_thread_receive_fds,
			(void *) ctx);
	if (ret != 0) {
		perror("pthread_create");
		goto error;
	}

	/* Create thread to manage the polling/writing of traces */
	ret = pthread_create(&threads[1], NULL, lttng_kconsumerd_thread_poll_fds,
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
	lttng_kconsumerd_send_error(ctx, KCONSUMERD_EXIT_SUCCESS);
	goto end;

error:
	ret = EXIT_FAILURE;
	lttng_kconsumerd_send_error(ctx, KCONSUMERD_EXIT_FAILURE);

end:
	lttng_kconsumerd_destroy(ctx);
	lttng_kconsumerd_cleanup();

	return ret;
}
