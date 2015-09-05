/*
 * Copyright (C) 2015 - Philippe Proulx <pproulx@efficios.com>
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
#define _LGPL_SOURCE
#include <popt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "../command.h"
#include "../utils.h"
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
	fprintf(ofp, "Usage: lttng status [options]\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Options:\n");
	fprintf(ofp, "  -h, --help          Show this help\n");
	fprintf(ofp, "      --list-options  List options\n");
}

static int status(void)
{
	int ret = CMD_SUCCESS;
	char *session_name = NULL;
	const char *argv[2];

	session_name = get_session_name();

	if (!session_name) {
		ret = CMD_ERROR;
		goto end;
	}

	argv[0] = "list";
	argv[1] = session_name;

	ret = cmd_list(2, argv);

end:
	free(session_name);

	return ret;
}

/*
 * The 'status <options>' first level command
 */
int cmd_status(int argc, const char **argv)
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

	if (poptPeekArg(pc) != NULL) {
		ERR("This command does not accept positional arguments.\n");
		usage(stderr);
		ret = CMD_UNDEFINED;
		goto end;
	}

	ret = status();

end:
	poptFreeContext(pc);

	return ret;
}
