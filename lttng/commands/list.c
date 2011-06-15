/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
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
#include <popt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cmd.h"

static int opt_pid;
static int opt_channels;

enum {
	OPT_HELP = 1,
	OPT_EVENTS,
	OPT_KERNEL,
	OPT_APPS,
	OPT_SESSIONS,
	OPT_CHANNEL,
};

static struct poptOption long_options[] = {
	/* longName, shortName, argInfo, argPtr, value, descrip, argDesc */
	{"help",      'h', POPT_ARG_NONE, 0, OPT_HELP, 0, 0},
	{"events",    'e', POPT_ARG_NONE, 0, OPT_EVENTS, 0, 0},
	{"kernel",    'k', POPT_ARG_NONE, 0, OPT_KERNEL, 0, 0},
	{"pid",       'p', POPT_ARG_INT,  &opt_pid, 0, 0, 0},
	{"apps",      'a', POPT_ARG_NONE, 0, OPT_APPS, 0, 0},
	{"session",   's', POPT_ARG_NONE, 0, OPT_SESSIONS, 0, 0},
	{"channel",   'c', POPT_ARG_VAL,  &opt_channels, 1, 0, 0},
	{0, 0, 0, 0, 0, 0, 0}
};

/*
 * usage
 */
static void usage(FILE *ofp)
{
	fprintf(ofp, "usage: lttng list [options] [<executable>]\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "  -h, --help         Show this help\n");
	fprintf(ofp, "  -e, --events       List all available instrumentation\n");
	fprintf(ofp, "  -k, --kernel       List kernel instrumentation\n");
	fprintf(ofp, "  -p, --pid PID      List user-space instrumentation by PID\n");
	fprintf(ofp, "  -a, --apps         List traceable user-space applications/pids\n");
	fprintf(ofp, "  -s, --sessions     List tracing session\n");
	fprintf(ofp, "\n");
}

/*
 *  get_cmdline_by_pid
 *
 *  Get command line from /proc for a specific pid.
 *
 *  On success, return an allocated string pointer pointing to the proc
 *  cmdline.
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
 *  list_kernel
 *
 *  Ask for all trace events in the kernel and pretty print them.
 */
static int list_kernel(void)
{
	int ret, pos, size;
	char *event_list, *event, *ptr;

	DBG("Getting all tracing events");

	ret = lttng_kernel_list_events(&event_list);
	if (ret < 0) {
		ERR("Unable to list kernel instrumentation");
		return ret;
	}

	MSG("Kernel tracepoints:\n-------------");

	ptr = event_list;
	while ((size = sscanf(ptr, "event { name = %m[^;]; };%n\n", &event, &pos)) == 1) {
		MSG("    - %s", event);
		/* Move pointer to the next line */
		ptr += pos + 1;
		free(event);
	}

	free(event_list);

	return CMD_SUCCESS;
}

/*
 *  list_sessions
 *
 *  Get the list of available sessions from the session daemon and print it to
 *  user.
 */
static int list_sessions(void)
{
	int ret, count, i;
	struct lttng_session *sessions;

	count = lttng_list_sessions(&sessions);
	DBG("Session count %d", count);
	if (count < 0) {
		ret = count;
		goto error;
	}

	MSG("Available sessions:");
	for (i = 0; i < count; i++) {
		MSG("    %d) %s (%s)", i+1, sessions[i].name, sessions[i].path);
	}

	free(sessions);

	return CMD_SUCCESS;

error:
	return ret;
}

/*
 *  list_apps
 *
 *  Get the UST traceable pid list and print them to the user.
 */
static int list_apps(void)
{
	int i, ret, count;
	pid_t *pids;
	char *cmdline;

	count = 0;
	//count = lttng_ust_list_traceable_apps(&pids);
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

	return CMD_SUCCESS;

error:
	return ret;
}

/*
 *  list_pid
 *
 *  List all instrumentation for a specific pid
 */
/*
static int list_pid(int pid)
{
	int ret;

	return CMD_SUCCESS;

error:
	return ret;
}
*/

/*
 *  list_executable
 *
 *  List all instrumentation for an executable on the system
 */
/*
static int list_executable(char *name)
{
}
*/

/*
 *  cmd_list
 *
 *  The 'list <options>' first level command
 */
int cmd_list(int argc, const char **argv)
{
	int opt, ret = CMD_SUCCESS;
	const char *command_name;
	static poptContext pc;

	if (argc < 2) {
		usage(stderr);
		goto end;
	}

	pc = poptGetContext(NULL, argc, argv, long_options, 0);
	poptReadDefaultConfig(pc, 0);

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case OPT_HELP:
			usage(stderr);
			goto end;
		case OPT_EVENTS:
			ret = CMD_NOT_IMPLEMENTED;
			goto end;
		case OPT_APPS:
			ret = list_apps();
			break;
		case OPT_KERNEL:
			ret = list_kernel();
			break;
		case OPT_SESSIONS:
			ret = list_sessions();
			break;
		default:
			usage(stderr);
			ret = CMD_UNDEFINED;
			goto end;
		}
	}

	if (opt_pid != 0) {
		//ret = list_pid(pid);
		ret = CMD_NOT_IMPLEMENTED;
	}

	command_name = poptGetArg(pc);
	if (command_name != NULL) {
		// ret = list_executable(command_name);
		ret = CMD_NOT_IMPLEMENTED;
	}

end:
	return ret;
}
