/*
 * Copyright (C) 2015 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include "../command.hpp"

#include <common/utils.hpp>

#include <popt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef LTTNG_EMBED_HELP
static const char *help_msg =
#include <lttng-help.1.h>
	;
#endif

static const char *lttng_help_msg =
#ifdef LTTNG_EMBED_HELP
#include <lttng.1.h>
#else
	nullptr
#endif
	;

enum {
	OPT_HELP = 1,
	OPT_LIST_OPTIONS,
};

static struct poptOption long_options[] = {
	/* longName, shortName, argInfo, argPtr, value, descrip, argDesc */
	{ "help", 'h', POPT_ARG_NONE, nullptr, OPT_HELP, nullptr, nullptr },
	{ "list-options", 0, POPT_ARG_NONE, nullptr, OPT_LIST_OPTIONS, nullptr, nullptr },
	{ nullptr, 0, 0, nullptr, 0, nullptr, nullptr }
};

/*
 *  cmd_help
 */
int cmd_help(int argc, const char **argv, const struct cmd_struct commands[])
{
	int opt, ret = CMD_SUCCESS;
	const char *arg_cmd_name;
	static poptContext pc;
	const struct cmd_struct *cmd;
	int found = 0;
	const char *cmd_argv[2];

	pc = poptGetContext(nullptr, argc, argv, long_options, 0);
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
	arg_cmd_name = poptGetArg(pc);
	if (arg_cmd_name == nullptr) {
		/* Fall back to lttng(1) */
		ret = utils_show_help(1, "lttng", lttng_help_msg);
		if (ret) {
			ERR("Cannot show --help for `lttng`");
			perror("exec");
			ret = CMD_ERROR;
		}

		goto end;
	}

	/* Help about help? */
	if (strcmp(arg_cmd_name, "help") == 0) {
		SHOW_HELP();
		goto end;
	}

	/* Make sure command name exists */
	cmd = &commands[0];

	while (cmd->name != nullptr) {
		if (strcmp(cmd->name, arg_cmd_name) == 0) {
			found = 1;
			break;
		}

		cmd++;
	}

	if (!found) {
		ERR("Unknown command \"%s\"", arg_cmd_name);
		ret = CMD_ERROR;
		goto end;
	}

	/* Show command's help */
	cmd_argv[0] = cmd->name;
	cmd_argv[1] = "--help";
	LTTNG_ASSERT(cmd->func);
	ret = cmd->func(2, cmd_argv);

end:
	poptFreeContext(pc);
	return ret;
}
