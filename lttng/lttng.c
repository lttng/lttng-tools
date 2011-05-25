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

#include <lttng/lttng.h>

#include "lttng.h"
#include "lttngerr.h"

/* Variables */
static char *progname;
static char *session_name;
static uuid_t current_uuid;
static int auto_session;
static int auto_trace;

/* Prototypes */
static int process_client_opt(void);
static int process_opt_list_apps(void);
static int process_opt_list_sessions(void);
static int process_opt_list_traces(void);
static int process_opt_create_session(void);
static int process_kernel_create_trace(void);
static int process_opt_kernel_event(void);
static int process_kernel_start_trace(void);
static int set_session_uuid(void);
static void sighandler(int sig);
static int set_signal_handler(void);
static int validate_options(void);
static char *get_cmdline_by_pid(pid_t pid);
static void set_opt_session_info(void);

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

	set_opt_session_info();

	if (opt_list_apps) {
		ret = process_opt_list_apps();
		if (ret < 0) {
			goto end;
		}
		goto error;
	}

	if (opt_list_session) {
		ret = process_opt_list_sessions();
		if (ret < 0) {
			goto end;
		}
		goto error;
	}

	/* Session creation or auto session set on */
	if (auto_session || opt_create_session) {
		DBG("Creating a new session");
		ret = process_opt_create_session();
		if (ret < 0) {
			goto end;
		}
	}

	ret = set_session_uuid();
	if (ret < 0) {
		ERR("Session %s not found", opt_session_name);
		goto error;
	}

	if (opt_destroy_session) {
		ret = lttng_destroy_session(&current_uuid);
		if (ret < 0) {
			goto end;
		}
		MSG("Session %s destroyed.", opt_session_name);
	}

	if (opt_list_traces) {
		ret = process_opt_list_traces();
		if (ret < 0) {
			goto end;
		}
	}

	/*
	 * Action on traces (kernel or/and userspace).
	 */

	if (opt_trace_kernel) {
		if (auto_trace || opt_create_trace) {
			DBG("Creating a kernel trace");
			ret = process_kernel_create_trace();
			if (ret < 0) {
				goto end;
			}
		}

		if (opt_event_list != NULL) {
			ret = process_opt_kernel_event();
			if (ret < 0) {
				goto end;
			}
		} else {
			// Enable all events
		}

		if (auto_trace || opt_start_trace) {
			DBG("Starting kernel tracing");
			ret = process_kernel_start_trace();
			if (ret < 0) {
				goto end;
			}
		}

		if (opt_stop_trace) {
			DBG("Stopping kernel tracing");
			ret = lttng_kernel_stop_tracing();
			if (ret < 0) {
				goto end;
			}
		}
	}

	if (opt_trace_pid != 0) {
		if (auto_trace || opt_create_trace) {
			DBG("Create a userspace trace for pid %d", opt_trace_pid);
			ret = lttng_ust_create_trace(opt_trace_pid);
			if (ret < 0) {
				goto end;
			}
			MSG("Trace created successfully!");
		}

		if (auto_trace || opt_start_trace) {
			DBG("Start trace for pid %d", opt_trace_pid);
			ret = lttng_ust_start_trace(opt_trace_pid);
			if (ret < 0) {
				goto end;
			}
			MSG("Trace started successfully!");
		} else if (opt_stop_trace) {
			DBG("Stop trace for pid %d", opt_trace_pid);
			ret = lttng_ust_stop_trace(opt_trace_pid);
			if (ret < 0) {
				goto end;
			}
			MSG("Trace stopped successfully!");
		}

	}

	return 0;

end:
	ERR("%s", lttng_get_readable_code(ret));
error:	/* fall through */
	return ret;
}

/*
 *  process_kernel_start_trace
 *
 *  Start a kernel trace.
 */
static int process_kernel_start_trace(void)
{
	int ret;

	ret = lttng_kernel_create_stream();
	if (ret < 0) {
		goto error;
	}

	ret = lttng_kernel_start_tracing();
	if (ret < 0) {
		goto error;
	}

	MSG("Kernel tracing started");

	return 0;

error:
	return ret;
}

/*
 *  process_kernel_create_trace
 *
 *  Create a kernel trace.
 */
static int process_kernel_create_trace(void)
{
	int ret;

	/* Setup kernel session */
	ret = lttng_kernel_create_session();
	if (ret < 0) {
		goto error;
	}

	/* Create an empty channel (with no event) */
	ret = lttng_kernel_create_channel();
	if (ret < 0) {
		goto error;
	}

	/* Opening metadata for session */
	ret = lttng_kernel_open_metadata();
	if (ret < 0) {
		goto error;
	}

	return 0;

error:
	return ret;
}

/*
 *  process_kernel_event
 *
 *  Enable kernel event from the command line list given.
 */
static int process_opt_kernel_event(void)
{
	int ret;
	char *event_name;

	event_name = strtok(opt_event_list, ",");
	while (event_name != NULL) {
		DBG("Enabling kernel event %s", event_name);
		ret = lttng_kernel_enable_event(event_name);
		if (ret < 0) {
			ERR("%s %s", lttng_get_readable_code(ret), event_name);
		} else {
			MSG("Kernel event %s enabled.", event_name);
		}
		/* Next event */
		event_name = strtok(NULL, ",");
	}

	return 0;
}

/*
 *  set_opt_session_info
 *
 *  Setup session_name, current_uuid, short_str_uuid and
 *  long_str_uuid using the command line options.
 */
static void set_opt_session_info(void)
{
	if (opt_session_name != NULL) {
		session_name = strndup(opt_session_name, NAME_MAX);
		DBG("Session name set to %s", session_name);
	}
}

/*
 *  set_session_uuid
 *
 *  Set current session uuid to the current flow of command(s) using the
 *  session_name.
 */
static int set_session_uuid(void)
{
	int ret, count, i, found = 0;
	struct lttng_session *sessions;

	if (!uuid_is_null(current_uuid)) {
		lttng_set_current_session_uuid(&current_uuid);
		goto end;
	}

	count = lttng_list_sessions(&sessions);
	if (count < 0) {
		ret = count;
		goto error;
	}

	for (i = 0; i < count; i++) {
		if (strncmp(sessions[i].name, session_name, NAME_MAX) == 0) {
			lttng_set_current_session_uuid(&sessions[i].uuid);
			uuid_copy(current_uuid, sessions[i].uuid);
			found = 1;
			break;
		}
	}

	free(sessions);

	if (!found) {
		return -1;
	}

end:
	DBG("Session UUID set");
	return 0;

error:
	return ret;
}

/*
 *  process_opt_list_traces
 *
 *  Get list of all traces for a specific session uuid.
 */
static int process_opt_list_traces(void)
{
	int ret, i;
	struct lttng_trace *traces;

	ret = lttng_list_traces(&current_uuid, &traces);
	DBG("Number of traces to list %d", ret);
	if (ret < 0) {
		goto error;
	}

	/* No traces */
	if (ret == 0) {
		MSG("No traces found.");
		goto error;
	}

	MSG("Userspace traces:");
	for (i = 0; i < ret; i++) {
		if (traces[i].type == USERSPACE) {
			MSG("\t%d) %s (pid: %d): %s",
					i, traces[i].name, traces[i].pid,
					get_cmdline_by_pid(traces[i].pid));
		} else {
			break;
		}
	}

	MSG("Kernel traces:");
	for (;i < ret; i++) {
		if (traces[i].type == KERNEL) {
			MSG("\t%d) %s", i, traces[i].name);
		}
	}

	free(traces);

error:
	return ret;
}

/*
 *  process_opt_create_session
 *
 *  Create a new session using the name pass
 *  to the command line.
 */
static int process_opt_create_session(void)
{
	int ret;
	char name[NAME_MAX];
	time_t rawtime;
	struct tm *timeinfo;

	/* Auto session name creation */
	if (opt_session_name == NULL) {
		time(&rawtime);
		timeinfo = localtime(&rawtime);
		strftime(name, sizeof(name), "auto-%Y%m%d-%H%M%S", timeinfo);
		session_name = strndup(name, sizeof(name));
		DBG("Auto session name set to %s", session_name);
	}

	ret = lttng_create_session(session_name);
	if (ret < 0) {
		goto error;
	}

	MSG("Session created: %s", session_name);

error:
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
	struct lttng_session *sessions;

	count = lttng_list_sessions(&sessions);
	DBG("Session count %d", count);
	if (count < 0) {
		ret = count;
		goto error;
	}

	MSG("Available sessions (UUIDs):");
	for (i = 0; i < count; i++) {
		MSG("    %d) %s", i+1, sessions[i].name);
	}

	free(sessions);
	MSG("\nTo select a session, use -s, --session UUID.");

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
	int i, ret, count;
	pid_t *pids;
	char *cmdline;

	count = lttng_ust_list_apps(&pids);
	if (count < 0) {
		ret = count;
		goto error;
	}

	MSG("LTTng UST traceable application [name (pid)]:");
	for (i=0; i < count; i++) {
		cmdline = get_cmdline_by_pid(pids[i]);
		if (cmdline == NULL) {
			MSG("\t(not running) (%d)", pids[i]);
			continue;
		}
		MSG("\t%s (%d)", cmdline, pids[i]);
		free(cmdline);
	}

	/* Allocated by lttng_ust_list_apps() */
	free(pids);

	return 0;

error:
	return ret;
}

/*
 *  get_cmdline_by_pid
 *
 *  Get command line from /proc for a specific pid.
 *
 *  On success, return an allocated string pointer pointing to
 *  the proc cmdline.
 *  On error, return NULL.
 */
static char *get_cmdline_by_pid(pid_t pid)
{
	int ret;
	FILE *fp;
	char *cmdline = NULL;
	char path[24];	/* Can't go bigger than /proc/65535/cmdline */

	snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
	fp = fopen(path, "r");
	if (fp == NULL) {
		goto end;
	}

	/* Caller must free() *cmdline */
	cmdline = malloc(PATH_MAX);
	ret = fread(cmdline, 1, PATH_MAX, fp);
	fclose(fp);

end:
	return cmdline;
}

/*
 *  validate_options
 *
 *  Make sure that all options passed to the command line are compatible with
 *  each others.
 *
 *  On error, return -1
 *  On success, return 0
 */
static int validate_options(void)
{
	/* If listing options, jump validation */
	if (opt_list_apps || opt_list_session) {
		goto end;
	}
	/* Conflicting command */
	if (opt_start_trace && opt_stop_trace) {
		ERR("Can't use --start and --stop together.");
		goto error;
	/* If no PID specified and trace_kernel is off */
	} else if ((opt_trace_pid == 0 && !opt_trace_kernel) &&
			(opt_create_trace || opt_start_trace || opt_stop_trace || opt_destroy_trace)) {
		ERR("Please specify for which tracer (-k or -p PID).");
		goto error;
	/* List traces, we need a session name */
	} else if (opt_list_traces && opt_session_name == NULL) {
		ERR("Can't use -t without -s, --session option.");
		goto error;
	/* Can't set event for both kernel and userspace at the same time */
	} else if (opt_event_list != NULL && (opt_trace_kernel && opt_trace_pid)) {
		ERR("Please don't use --event for both kernel and userspace.\nOne at a time to enable events.");
		goto error;
	/* Don't need a trace name for kernel tracig */
	} else if (opt_trace_name != NULL && opt_trace_kernel) {
		ERR("For action on a kernel trace, please don't specify a trace name.");
		goto error;
	} else if (opt_destroy_trace && opt_session_name == NULL) {
		ERR("Please specify a session in order to destroy a trace");
		goto error;
	} else if (opt_create_trace || opt_destroy_trace) {
		/* Both kernel and user-space are denied for these options */
		if (opt_trace_pid != 0 && opt_trace_kernel) {
			ERR("Kernel and user-space trace creation and destruction can't be used together.");
			goto error;
		/* Need a trace name for user-space tracing */
		} else if (opt_trace_name == NULL && opt_trace_pid != 0) {
			ERR("Please specify a trace name for user-space tracing");
			goto error;
		}
	} else if (opt_stop_trace && opt_trace_pid != 0 && opt_trace_name == NULL) {
		ERR("Please specify a trace name for user-space tracing");
		goto error;
	}

	/* If start trace, auto start tracing */
	if (opt_start_trace || opt_event_list != NULL) {
		DBG("Requesting auto tracing");
		auto_trace = 1;
	}

	/* If no session, auto create one */
	if (opt_session_name == NULL) {
		DBG("Requesting an auto session creation");
		auto_session = 1;
	}

end:
	return 0;

error:
	return -1;
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
		/*
		 * Spawn session daemon and tell
		 * it to signal us when ready.
		 */
		execlp(pathname, "ltt-sessiond", "--sig-parent", "--quiet", NULL);
		/* execlp only returns if error happened */
		if (errno == ENOENT) {
			ERR("No session daemon found. Use --sessiond-path.");
		} else {
			perror("execlp");
		}
		kill(getppid(), SIGTERM);	/* unpause parent */
		exit(EXIT_FAILURE);
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
	char *pathname = NULL, *alloc_pathname = NULL;

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
			pathname = getenv(LTTNG_SESSIOND_PATH_ENV);
		}

		/* Let's rock and roll */
		if (pathname == NULL) {
			ret = asprintf(&alloc_pathname, "ltt-sessiond");
			if (ret < 0) {
				goto end;
			}
			pathname = alloc_pathname;
		}

		ret = spawn_sessiond(pathname);
		free(alloc_pathname);
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
	switch (sig) {
		case SIGTERM:
			DBG("SIGTERM catched");
			clean_exit(EXIT_FAILURE);
			break;
		case SIGCHLD:
			/* Notify is done */
			DBG("SIGCHLD catched");
			break;
		default:
			DBG("Unknown signal %d catched", sig);
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
	if (session_name) {
		free(session_name);
	}

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
		clean_exit(EXIT_FAILURE);
	}

	ret = validate_options();
	if (ret < 0) {
		return EXIT_FAILURE;
	}

	ret = set_signal_handler();
	if (ret < 0) {
		clean_exit(ret);
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
			clean_exit(-EPERM);
		}
	}

	/* Check if the lttng session daemon is running.
	 * If no, a daemon will be spawned.
	 */
	if (opt_no_sessiond == 0 && (check_ltt_sessiond() < 0)) {
		clean_exit(EXIT_FAILURE);
	}

	ret = process_client_opt();
	if (ret < 0) {
		clean_exit(ret);
	}

	clean_exit(0);

	return 0;
}
