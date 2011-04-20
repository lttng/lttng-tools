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
		ERR("%s", lttng_get_readable_code(ret));
		goto end;
	}

	if (opt_list_apps) {
		ret = process_opt_list_apps();
		if (ret < 0) {
			ERR("%s", lttng_get_readable_code(ret));
			goto end;
		}
	}

	return 0;

end:
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
 *  check_ltt_sessiond
 *
 *  Check if the session daemon is available using
 *  the liblttngctl API for the check.
 */
static int check_ltt_sessiond(void)
{
	int ret;

	ret = lttng_check_session_daemon();
	if (ret < 0) {
		ERR("No session daemon found. Aborting.");
	}

	return ret;
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
 * main
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
	if (check_ltt_sessiond() < 0) {
		return EXIT_FAILURE;
	}

	ret = process_client_opt();
	if (ret < 0) {
		return ret;
	}

	return 0;
}
