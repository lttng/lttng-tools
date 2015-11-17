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

#define _LGPL_SOURCE
#include <popt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../command.h"

enum {
	OPT_HELP = 1,
	OPT_LIST_OPTIONS,
};

static struct poptOption long_options[] = {
	/* longName, shortName, argInfo, argPtr, value, descrip, argDesc */
	{"help",      'h', POPT_ARG_NONE, 0, OPT_HELP, 0, 0},
	{"list-options", 0, POPT_ARG_NONE, NULL, OPT_LIST_OPTIONS, NULL, NULL},
	{0, 0, 0, 0, 0, 0, 0}
};

/*
 *  cmd_help
 */
int cmd_help(int argc, const char **argv, const struct cmd_struct commands[])
{
	int opt, ret = CMD_SUCCESS;
	char *cmd_name;
	static poptContext pc;
	const struct cmd_struct *cmd;
	int found = 0;

	pc = poptGetContext(NULL, argc, argv, long_options, 0);
	poptReadDefaultConfig(pc, 0);

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case OPT_HELP:
			SHOW_HELP();
			goto end;
		case OPT_LIST_OPTIONS:
			list_cmd_options(stdout, long_options);
			goto end;
		default:
			ret = CMD_UNDEFINED;
			goto end;
		}
	}

	/* Get command name */
	cmd_name = (char *) poptGetArg(pc);

	if (cmd_name == NULL) {
		/* Fall back to lttng(1) */
		ret = show_man_page(1, "lttng");

		if (ret) {
			ERR("Cannot view man page lttng(1)");
			perror("exec");
			ret = CMD_ERROR;
			goto end;
		}
	}

	/* Make sure command name exists */
	cmd = &commands[0];

	while (cmd->name != NULL) {
		if (strcmp(cmd->name, cmd_name) == 0) {
			found = 1;
			break;
		}

		cmd++;
	}

	if (!found) {
		ERR("Unknown command \"%s\"", cmd_name);
		ret = CMD_ERROR;
		goto end;
	}

	/* Show command's man page */
	ret = show_cmd_man_page(cmd_name);

	if (ret) {
		ERR("Cannot view man page lttng-%s(1)", cmd_name);
		perror("exec");
		ret = CMD_ERROR;
	}

end:
	poptFreeContext(pc);
	return ret;
}
