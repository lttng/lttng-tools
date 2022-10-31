/*
 * Copyright (C) 2011 EfficiOS Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include <popt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <assert.h>

#include <common/mi-lttng.h>

#include "../command.h"

#ifdef LTTNG_EMBED_HELP
static const char help_msg[] =
#include <lttng-set-session.1.h>
;
#endif

enum {
	OPT_HELP = 1,
	OPT_LIST_OPTIONS,
};

static struct mi_writer *writer;

static struct poptOption long_options[] = {
	/* longName, shortName, argInfo, argPtr, value, descrip, argDesc */
	{"help",           'h', POPT_ARG_NONE, 0, OPT_HELP, 0, 0},
	{"list-options",   0, POPT_ARG_NONE, NULL, OPT_LIST_OPTIONS, NULL, NULL},
	{0, 0, 0, 0, 0, 0, 0}
};

/*
 * Print the necessary mi for a session and name.
 */
static int mi_print(const char *session_name)
{
	int ret;

	assert(writer);
	assert(session_name);

	/*
	 * Open a sessions element
	 * This is purely for validation purpose
	 */
	ret = mi_lttng_sessions_open(writer);
	if (ret) {
		goto end;
	}

	/* Open a session element */
	ret = mi_lttng_writer_open_element(writer, config_element_session);
	if (ret) {
		goto end;
	}

	/* Session name */
	ret = mi_lttng_writer_write_element_string(writer , config_element_name,
			session_name);
	if (ret) {
		goto end;
	}

	/* Close session and sessions element */
	ret = mi_lttng_close_multi_element(writer, 2);
	if (ret) {
		goto end;
	}
end:
	return ret;
}

/*
 *  set_session
 */
static int set_session(const char *session_name)
{
	int ret = CMD_SUCCESS;
	int count, i;
	unsigned int session_found = 0;
	struct lttng_session *sessions;

	if (session_name && strlen(session_name) > NAME_MAX) {
		ERR("Session name too long. Length must be lower or equal to %d",
			NAME_MAX);
		ret = CMD_ERROR;
		goto end;
	}

	count = lttng_list_sessions(&sessions);
	if (count < 0) {
		ret = CMD_ERROR;
		ERR("%s", lttng_strerror(count));
		goto end;
	}

	for (i = 0; i < count; i++) {
		if (strncmp(sessions[i].name, session_name, NAME_MAX) == 0) {
			session_found = 1;
			break;
		}
	}

	if (!session_found) {
		ERR("Session '%s' not found", session_name);
		ret = CMD_ERROR;
		goto error;
	}

	ret = config_init(session_name);
	if (ret < 0) {
		ERR("Unable to set session name");
		ret = CMD_ERROR;
		goto error;
	}

	MSG("Session set to %s", session_name);
	if (lttng_opt_mi) {
		ret = mi_print(session_name);
		if (ret) {
			ret = CMD_ERROR;
			goto error;
		}
	}

	ret = CMD_SUCCESS;

error:
	free(sessions);
end:
	return ret;
}

/*
 *  cmd_set_session
 */
int cmd_set_session(int argc, const char **argv)
{
	int opt, ret = CMD_SUCCESS, command_ret = CMD_SUCCESS, success = 1;
	static poptContext pc;
	const char *arg_session_name = NULL;

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

	arg_session_name = poptGetArg(pc);
	if (arg_session_name == NULL) {
		ERR("Missing session name");
		ret = CMD_ERROR;
		goto end;
	}

	/* Mi check */
	if (lttng_opt_mi) {
		writer = mi_lttng_writer_create(fileno(stdout), lttng_opt_mi);
		if (!writer) {
			ret = -LTTNG_ERR_NOMEM;
			goto end;
		}

		/* Open command element */
		ret = mi_lttng_writer_command_open(writer,
				mi_lttng_element_command_set_session);
		if (ret) {
			ret = CMD_ERROR;
			goto end;
		}

		/* Open output element */
		ret = mi_lttng_writer_open_element(writer,
				mi_lttng_element_command_output);
		if (ret) {
			ret = CMD_ERROR;
			goto end;
		}
	}

	command_ret = set_session(arg_session_name);
	if (command_ret) {
		success = 0;
	}

	/* Mi closing */
	if (lttng_opt_mi) {
		/* Close  output element */
		ret = mi_lttng_writer_close_element(writer);
		if (ret) {
			ret = CMD_ERROR;
			goto end;
		}

		/* Success ? */
		ret = mi_lttng_writer_write_element_bool(writer,
				mi_lttng_element_command_success, success);
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
		ret = ret ? ret : LTTNG_ERR_MI_IO_FAIL;
	}

	/* Overwrite ret if an error occurred during set_session() */
	ret = command_ret ? command_ret : ret;

	poptFreeContext(pc);
	return ret;
}
