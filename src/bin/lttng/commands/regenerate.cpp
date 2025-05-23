/*
 * SPDX-FileCopyrightText: 2015 Julien Desfossez <jdesfossez@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include "../command.hpp"

#include <common/mi-lttng.hpp>

#include <ctype.h>
#include <popt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static char *opt_session_name;
static char *session_name = nullptr;

static int regenerate_metadata(int argc, const char **argv);
static int regenerate_statedump(int argc, const char **argv);

#ifdef LTTNG_EMBED_HELP
static const char help_msg[] =
#include <lttng-regenerate.1.h>
	;
#endif

enum {
	OPT_HELP = 1,
	OPT_LIST_OPTIONS,
	OPT_LIST_COMMANDS,
};

static struct mi_writer *writer;

/* clang-format off */
static struct poptOption long_options[] = {
	/* { longName, shortName, argInfo, argPtr, value, descrip, argDesc, } */
	{ "help", 'h', POPT_ARG_NONE, nullptr, OPT_HELP, nullptr, nullptr },
	{ "session", 's', POPT_ARG_STRING, &opt_session_name, 0, nullptr, nullptr },
	{ "list-options", 0, POPT_ARG_NONE, nullptr, OPT_LIST_OPTIONS, nullptr, nullptr },
	{ "list-commands", 0, POPT_ARG_NONE, nullptr, OPT_LIST_COMMANDS, nullptr, nullptr },
	{ nullptr, 0, 0, nullptr, 0, nullptr, nullptr },
};
/* clang-format on */

static struct cmd_struct actions[] = {
	{ "metadata", regenerate_metadata },
	{ "statedump", regenerate_statedump },
	{ nullptr, nullptr } /* Array closure */
};

/*
 * Count and return the number of arguments in argv.
 */
static int count_arguments(const char **argv)
{
	int i = 0;

	LTTNG_ASSERT(argv);

	while (argv[i] != nullptr) {
		i++;
	}

	return i;
}

static int regenerate_metadata(int argc, const char **argv __attribute__((unused)))
{
	int ret;

	if (argc > 1) {
		ret = CMD_UNDEFINED;
		goto end;
	}
	ret = lttng_regenerate_metadata(session_name);
	if (ret == 0) {
		MSG("Metadata successfully regenerated for session %s", session_name);
	} else {
		ERR("%s", lttng_strerror(ret));
	}

end:
	return ret;
}

static int regenerate_statedump(int argc, const char **argv __attribute__((unused)))
{
	int ret;

	if (argc > 1) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}
	ret = lttng_regenerate_statedump(session_name);
	if (ret == 0) {
		MSG("State dump successfully regenerated for session %s", session_name);
	}

end:
	return ret;
}

static int handle_command(const char **argv)
{
	struct cmd_struct *cmd;
	int ret = CMD_SUCCESS, i = 0, argc, command_ret = CMD_SUCCESS;

	if (argv == nullptr) {
		ERR("No object specified for regenerate command.");
		command_ret = CMD_ERROR;
		goto end;
	}

	argc = count_arguments(argv);
	LTTNG_ASSERT(argc >= 1);

	cmd = &actions[i];
	while (cmd->func != nullptr) {
		/* Find command */
		if (strcmp(argv[0], cmd->name) == 0) {
			if (lttng_opt_mi) {
				/* Action element */
				ret = mi_lttng_writer_open_element(
					writer, mi_lttng_element_command_regenerate_action);
				if (ret) {
					ret = CMD_ERROR;
					goto end;
				}

				/* Name of the action */
				ret = mi_lttng_writer_write_element_string(
					writer, config_element_name, argv[0]);
				if (ret) {
					ret = CMD_ERROR;
					goto end;
				}
			}
			command_ret = cmd->func(argc, argv);
			if (lttng_opt_mi) {
				/* Close output and action element */
				ret = mi_lttng_writer_close_element(writer);
				if (ret) {
					ret = CMD_ERROR;
					goto end;
				}
			}
			goto end;
		}

		cmd = &actions[i++];
	}

	ret = CMD_UNDEFINED;

end:
	/* Overwrite ret if an error occurred in cmd->func() */
	ret = command_ret ? command_ret : ret;
	return ret;
}

/*
 * regenerate command handling.
 */
int cmd_regenerate(int argc, const char **argv)
{
	int opt, ret = CMD_SUCCESS, command_ret = CMD_SUCCESS, success = 1;
	static poptContext pc;

	if (argc < 1) {
		SHOW_HELP();
		ret = CMD_ERROR;
		goto end;
	}

	pc = poptGetContext(nullptr, argc, argv, long_options, 0);
	poptReadDefaultConfig(pc, 0);

	if (lttng_opt_mi) {
		writer = mi_lttng_writer_create(fileno(stdout), lttng_opt_mi);
		if (!writer) {
			ret = -LTTNG_ERR_NOMEM;
			goto end;
		}
		/* Open command element */
		ret = mi_lttng_writer_command_open(writer, mi_lttng_element_command_regenerate);
		if (ret) {
			ret = CMD_ERROR;
			goto end;
		}

		/* Open output element */
		ret = mi_lttng_writer_open_element(writer, mi_lttng_element_command_output);
		if (ret) {
			ret = CMD_ERROR;
			goto end;
		}
	}

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case OPT_HELP:
			SHOW_HELP();
			goto end;
		case OPT_LIST_OPTIONS:
			list_cmd_options(stdout, long_options);
			goto end;
		case OPT_LIST_COMMANDS:
			list_commands(actions, stdout);
			goto end;
		default:
			SHOW_HELP();
			ret = CMD_UNDEFINED;
			goto end;
		}
	}

	if (!opt_session_name) {
		session_name = get_session_name();
		if (session_name == nullptr) {
			ret = CMD_ERROR;
			goto end;
		}
	} else {
		session_name = opt_session_name;
	}

	command_ret = handle_command(poptGetArgs(pc));
	if (command_ret) {
		success = 0;
	}

	if (lttng_opt_mi) {
		/* Close output element */
		ret = mi_lttng_writer_close_element(writer);
		if (ret) {
			ret = CMD_ERROR;
			goto end;
		}

		/* Success ? */
		ret = mi_lttng_writer_write_element_bool(
			writer, mi_lttng_element_command_success, success);
		if (ret) {
			ret = CMD_ERROR;
			goto end;
		}

		/* Command element close */
		ret = mi_lttng_writer_command_close(writer);
		if (ret) {
			ret = CMD_ERROR;
			goto end;
		}
	}

end:
	/* Mi clean-up */
	if (writer && mi_lttng_writer_destroy(writer)) {
		/* Preserve original error code */
		ret = ret ? ret : -LTTNG_ERR_MI_IO_FAIL;
	}

	if (!opt_session_name) {
		free(session_name);
	}

	/* Overwrite ret if an error occurred during handle_command() */
	ret = command_ret ? command_ret : ret;

	poptFreeContext(pc);
	return ret;
}
