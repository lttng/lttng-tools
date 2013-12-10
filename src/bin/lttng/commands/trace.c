/*
 * Copyright (C) 2011 - David Goulet <dgoulet@efficios.com>
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
#include <popt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "../command.h"
#include <config.h>

enum {
	OPT_HELP = 1,
	OPT_LIST_OPTIONS,
};

static struct poptOption long_options[] = {
	/* longName, shortName, argInfo, argPtr, value, descrip, argDesc */
	{"help",        'h', POPT_ARG_NONE, 0, OPT_HELP, 0, 0},
	{"list-options", 0,  POPT_ARG_NONE, NULL, OPT_LIST_OPTIONS, NULL, NULL},
	{0, 0, 0, 0, 0, 0, 0}
};

/*
 * usage
 */
static void usage(FILE *ofp)
{
	fprintf(ofp, "usage: lttng trace CMD\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Options:\n");
	fprintf(ofp, "  -h, --help               Show this help\n");
	fprintf(ofp, "      --list-options       Simple listing of options\n");
	fprintf(ofp, "\n");
}

static int spawn_relayd(void)
{
	int ret;
	pid_t pid;

	pid = fork();
	if (pid == 0) {
		execl(INSTALL_BIN_PATH "/lttng-relayd",
				"--output", mkdtemp("lttng.XXXXXX"), NULL);
		ret = 0;
	} else if (pid > 0) {
		ret = pid;
	} else {
		PERROR("start relayd");
		ret = -errno;
	}

	return ret;
}

/*
 * Exec viewer if found and use session name path.
 */
static int trace_cmd(void)
{
	int ret;
	char *session_name, *trace_path;
	struct lttng_session *sessions = NULL;

	/*
	 * Safety net. If lttng is suid at some point for *any* useless reasons,
	 * this prevent any bad execution of binaries.
	 */
	if (getuid() != 0) {
		if (getuid() != geteuid()) {
			ERR("UID does not match effective UID.");
			ret = CMD_ERROR;
			goto error;
		} else if (getgid() != getegid()) {
			ERR("GID does not match effective GID.");
			ret = CMD_ERROR;
			goto error;
		}
	}

	ret = spawn_relayd();
	if (ret < 0) {
		goto error;
	}

	ret = lttng_create_session_live("lttng-trace-cmd", "net://localhost",
			1000000);
	if (ret < 0) {
		ERR("%s", lttng_strerror(ret));
		goto error;
	}

error:
	return ret;
}

/*
 * The 'trace <options>' first level command
 */
int cmd_trace(int argc, const char **argv)
{
	int opt, ret = CMD_SUCCESS;
	static poptContext pc;

	pc = poptGetContext(NULL, argc, argv, long_options, 0);
	poptReadDefaultConfig(pc, 0);

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case OPT_HELP:
			usage(stdout);
			goto end;
		case OPT_LIST_OPTIONS:
			list_cmd_options(stdout, long_options);
			goto end;
		default:
			usage(stderr);
			ret = CMD_UNDEFINED;
			goto end;
		}
	}

	ret = trace_cmd();

end:
	poptFreeContext(pc);
	return ret;
}
