/*
 * Copyright (c)  2011 David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
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
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <grp.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <lttng/liblttngctl.h>

#include "lttng.h"
#include "lttngerr.h"

/* Variables */
static char *progname;

/* Prototypes */
static int process_client_opt(void);
static int process_opt_list_apps(void);
static int process_opt_list_sessions(void);
static void sighandler(int sig);
static int set_signal_handler(void);

/*
 *  start_client
 *
 *  Process client request from the command line
 *  options. Every tracing action is done by the
 *  liblttngctl API.
 */
static int process_client_opt(void)
{
	int ret;

	/* Connect to the session daemon */
	ret = lttng_connect_sessiond();
	if (ret < 0) {
		goto end;
	}

	if (opt_list_apps) {
		ret = process_opt_list_apps();
		if (ret < 0) {
			goto end;
		}
	}

	if (opt_list_session) {
		ret = process_opt_list_sessions();
		if (ret < 0) {
			goto end;
		}
	}

	return 0;

end:
	ERR("%s", lttng_get_readable_code(ret));
	return ret;
}

/*
 *  process_opt_list_sessions
 *
 *  Get the list of available sessions from
 *  the session daemon and print it to user.
 */
static int process_opt_list_sessions(void)
{
	int ret, count, i;
	struct lttng_session *sess;

	count = lttng_list_sessions(&sess);
	if (count < 0) {
		ret = count;
		goto error;
	}

	MSG("Available sessions [Name (uuid)]:");
	for (i = 0; i < count; i++) {
		MSG("\tName: %s (uuid: %s)", sess[i].name, sess[i].uuid);
	}

	free(sess);
	MSG("\nTo select a session, use --session UUID.");

	return 0;

error:
	return ret;
}

/*
 *  process_opt_list_apps
 *
 *  Get the UST traceable pid list and print
 *  them to the user.
 */
static int process_opt_list_apps(void)
{
	int i, ret;
	pid_t *pids;
	FILE *fp;
	char path[24];	/* Can't go bigger than /proc/65535/cmdline */
	char cmdline[PATH_MAX];

	ret = lttng_ust_list_apps(&pids);
	if (ret < 0) {
		goto error;
	}

	MSG("LTTng UST traceable application [name (pid)]:");
	for (i=0; i < ret; i++) {
		snprintf(path, sizeof(path), "/proc/%d/cmdline", pids[i]);
		fp = fopen(path, "r");
		if (fp == NULL) {
			continue;
		}
		ret = fread(cmdline, 1, sizeof(cmdline), fp);
		MSG("\t%s (%d)", cmdline, pids[i]);
		fclose(fp);
	}

	/* Allocated by lttng_ust_list_apps() */
	free(pids);

	return 0;

error:
	return ret;
}

/*
 *  spawn_sessiond
 *
 *  Spawn a session daemon by forking and execv.
 */
static int spawn_sessiond(char *pathname)
{
	int ret = 0;
	pid_t pid;

	MSG("Spawning session daemon");
	pid = fork();
	if (pid == 0) {
		/* Spawn session daemon and tell
		 * it to signal us when ready.
		 */
		ret = execlp(pathname, "ltt-sessiond", "--sig-parent", NULL);
		if (ret < 0) {
			if (errno == ENOENT) {
				ERR("No session daemon found. Use --sessiond-path.");
			} else {
				perror("execlp");
			}
			kill(getppid(), SIGTERM);
			exit(EXIT_FAILURE);
		}
		exit(EXIT_SUCCESS);
	} else if (pid > 0) {
		/* Wait for ltt-sessiond to start */
		pause();
		goto end;
	} else {
		perror("fork");
		ret = -1;
		goto end;
	}

end:
	return ret;
}

/*
 *  check_ltt_sessiond
 *
 *  Check if the session daemon is available using
 *  the liblttngctl API for the check. If not, try to
 *  spawn a daemon.
 */
static int check_ltt_sessiond(void)
{
	int ret;
	char *pathname = NULL;

	ret = lttng_check_session_daemon();
	if (ret < 0) {
		/* Try command line option path */
		if (opt_sessiond_path != NULL) {
			ret = access(opt_sessiond_path, F_OK | X_OK);
			if (ret < 0) {
				ERR("No such file: %s", opt_sessiond_path);
				goto end;
			}
			pathname = opt_sessiond_path;
		} else {
			/* Try LTTNG_SESSIOND_PATH env variable */
			pathname = strdup(getenv(LTTNG_SESSIOND_PATH_ENV));
		}

		/* Let's rock and roll */
		if (pathname == NULL) {
			ret = asprintf(&pathname, "ltt-sessiond");
			if (ret < 0) {
				goto end;
			}
		}

		ret = spawn_sessiond(pathname);
		free(pathname);
		if (ret < 0) {
			ERR("Problem occurs when starting %s", pathname);
			goto end;
		}
	}

end:
	return ret;
}

/*
 *  set_signal_handler
 *
 *  Setup signal handler for SIGCHLD and SIGTERM.
 */
static int set_signal_handler(void)
{
	int ret = 0;
	struct sigaction sa;
	sigset_t sigset;

	if ((ret = sigemptyset(&sigset)) < 0) {
		perror("sigemptyset");
		goto end;
	}

	sa.sa_handler = sighandler;
	sa.sa_mask = sigset;
	sa.sa_flags = 0;
	if ((ret = sigaction(SIGCHLD, &sa, NULL)) < 0) {
		perror("sigaction");
		goto end;
	}

	if ((ret = sigaction(SIGTERM, &sa, NULL)) < 0) {
		perror("sigaction");
		goto end;
	}

end:
	return ret;
}

/*
 *  sighandler
 *
 *  Signal handler for the daemon
 */
static void sighandler(int sig)
{
	DBG("%d received", sig);
	switch (sig) {
		case SIGTERM:
			clean_exit(EXIT_FAILURE);
			break;
		case SIGCHLD:
			/* Notify is done */
			break;
		default:
			break;
	}

	return;
}
/*
 * clean_exit
 */
void clean_exit(int code)
{
	DBG("Clean exit");
	exit(code);
}

/*
 *  main
 */
int main(int argc, char *argv[])
{
	int ret;

	progname = argv[0] ? argv[0] : "lttng";

	/* For Mathieu Desnoyers aka Dr Tracing */
	if (strncmp(progname, "drtrace", 7) == 0) {
		MSG("%c[%d;%dmWelcome back Dr Tracing!%c[%dm\n\n", 27,1,33,27,0);
	}

	ret = parse_args(argc, (const char **) argv);
	if (ret < 0) {
		return EXIT_FAILURE;
	}

	ret = set_signal_handler();
	if (ret < 0) {
		return ret;
	}

	if (opt_tracing_group != NULL) {
		DBG("Set tracing group to '%s'", opt_tracing_group);
		lttng_set_tracing_group(opt_tracing_group);
	}

	/* If ask for kernel tracing, need root perms */
	if (opt_trace_kernel) {
		DBG("Kernel tracing activated");
		if (getuid() != 0) {
			ERR("%s must be setuid root", progname);
			return -EPERM;
		}
	}

	/* Check if the lttng session daemon is running.
	 * If no, a daemon will be spawned.
	 */
	if (opt_no_sessiond == 0 && (check_ltt_sessiond() < 0)) {
		return EXIT_FAILURE;
	}

	ret = process_client_opt();
	if (ret < 0) {
		return ret;
	}

	return 0;
}
