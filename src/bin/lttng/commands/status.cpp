/*
 * Copyright (C) 2015 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include "../command.hpp"
#include "../utils.hpp"

#include <config.h>
#include <popt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef LTTNG_EMBED_HELP
static const char help_msg[] =
#include <lttng-status.1.h>
	;
#endif

enum {
	OPT_HELP = 1,
	OPT_LIST_OPTIONS,
};

static struct poptOption long_options[] = {
	/* longName, shortName, argInfo, argPtr, value, descrip, argDesc */
	{ "help", 'h', POPT_ARG_NONE, NULL, OPT_HELP, NULL, NULL },
	{ "list-options", 0, POPT_ARG_NONE, NULL, OPT_LIST_OPTIONS, NULL, NULL },
	{ 0, 0, 0, 0, 0, 0, 0 }
};

static int status(void)
{
	const char *argv[2];
	int ret = CMD_SUCCESS;
	char *session_name = NULL;

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

	if (poptPeekArg(pc) != NULL) {
		ERR("This command does not accept positional arguments.\n");
		ret = CMD_UNDEFINED;
		goto end;
	}

	ret = status();
end:
	poptFreeContext(pc);
	return ret;
}
