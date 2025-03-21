/*
 * SPDX-FileCopyrightText: 2013 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include "../command.hpp"

#include <common/mi-lttng.hpp>

#include <lttng/lttng.h>

#include <inttypes.h>
#include <popt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *opt_output_path;
static bool opt_force;
static bool opt_save_all;
static struct mi_writer *writer;

#ifdef LTTNG_EMBED_HELP
static const char help_msg[] =
#include <lttng-save.1.h>
	;
#endif

enum {
	OPT_HELP = 1,
	OPT_ALL,
	OPT_FORCE,
	OPT_LIST_OPTIONS,
};

static struct poptOption save_opts[] = {
	/* longName, shortName, argInfo, argPtr, value, descrip, argDesc */
	{ "help", 'h', POPT_ARG_NONE, nullptr, OPT_HELP, nullptr, nullptr },
	{ "all", 'a', POPT_ARG_NONE, nullptr, OPT_ALL, nullptr, nullptr },
	{ "output-path", 'o', POPT_ARG_STRING, &opt_output_path, 0, nullptr, nullptr },
	{ "force", 'f', POPT_ARG_NONE, nullptr, OPT_FORCE, nullptr, nullptr },
	{ "list-options", 0, POPT_ARG_NONE, nullptr, OPT_LIST_OPTIONS, nullptr, nullptr },
	{ nullptr, 0, 0, nullptr, 0, nullptr, nullptr }
};

static int mi_partial_session(const char *session_name)
{
	int ret;
	LTTNG_ASSERT(writer);
	LTTNG_ASSERT(session_name);

	/* Open session element */
	ret = mi_lttng_writer_open_element(writer, config_element_session);
	if (ret) {
		goto end;
	}

	ret = mi_lttng_writer_write_element_string(writer, config_element_name, session_name);
	if (ret) {
		goto end;
	}

	/* Closing session element */
	ret = mi_lttng_writer_close_element(writer);
end:
	return ret;
}

/*
 * Mi print of save command
 */
static int mi_save_print(const char *session_name)
{
	int ret;
	LTTNG_ASSERT(writer);

	if (opt_save_all) {
		/* We use a wildcard to represent all sessions */
		session_name = "*";
	}

	/* Print save element */
	ret = mi_lttng_writer_open_element(writer, mi_lttng_element_save);
	if (ret) {
		goto end;
	}

	/* Print session element */
	ret = mi_partial_session(session_name);
	if (ret) {
		goto end;
	}

	/* Path element */
	if (opt_output_path) {
		ret = mi_lttng_writer_write_element_string(
			writer, config_element_path, opt_output_path);
		if (ret) {
			goto end;
		}
	}

	/* Close save element */
	ret = mi_lttng_writer_close_element(writer);
end:
	return ret;
}

/*
 * The 'save <options>' first level command
 */
int cmd_save(int argc, const char **argv)
{
	int ret = CMD_SUCCESS, command_ret = CMD_SUCCESS, success;
	int opt;
	const char *arg_session_name = nullptr, *leftover = nullptr;
	poptContext pc;
	struct lttng_save_session_attr *attr;

	pc = poptGetContext(nullptr, argc, argv, save_opts, 0);
	poptReadDefaultConfig(pc, 0);

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case OPT_HELP:
			SHOW_HELP();
			goto end;
		case OPT_ALL:
			opt_save_all = true;
			break;
		case OPT_FORCE:
			opt_force = true;
			break;
		case OPT_LIST_OPTIONS:
			list_cmd_options(stdout, save_opts);
			goto end;
		default:
			ret = CMD_UNDEFINED;
			goto end;
		}
	}

	if (!opt_save_all) {
		arg_session_name = poptGetArg(pc);
		if (arg_session_name) {
			DBG2("Session name: %s", arg_session_name);
		} else {
			/* default to opt_save_all */
			opt_save_all = true;
		}
	}

	leftover = poptGetArg(pc);
	if (leftover) {
		ERR("Unknown argument: %s", leftover);
		ret = CMD_ERROR;
		goto end;
	}

	attr = lttng_save_session_attr_create();
	if (!attr) {
		ret = CMD_FATAL;
		goto end_destroy;
	}

	if (lttng_save_session_attr_set_session_name(attr, arg_session_name)) {
		ret = CMD_ERROR;
		goto end_destroy;
	}

	if (lttng_save_session_attr_set_overwrite(attr, opt_force)) {
		ret = CMD_ERROR;
		goto end_destroy;
	}

	if (lttng_save_session_attr_set_output_url(attr, opt_output_path)) {
		ret = CMD_ERROR;
		goto end_destroy;
	}

	/* Mi check */
	if (lttng_opt_mi) {
		writer = mi_lttng_writer_create(fileno(stdout), lttng_opt_mi);
		if (!writer) {
			ret = -LTTNG_ERR_NOMEM;
			goto end_destroy;
		}

		/* Open command element */
		ret = mi_lttng_writer_command_open(writer, mi_lttng_element_command_save);
		if (ret) {
			ret = CMD_ERROR;
			goto end_destroy;
		}

		/* Open output element */
		ret = mi_lttng_writer_open_element(writer, mi_lttng_element_command_output);
		if (ret) {
			ret = CMD_ERROR;
			goto end_destroy;
		}
	}

	command_ret = lttng_save_session(attr);
	if (command_ret < 0) {
		ERR("%s", lttng_strerror(command_ret));
		success = 0;
	} else {
		/* Inform the user of what just happened on success. */
		if (arg_session_name && opt_output_path) {
			MSG("Session %s saved successfully in %s.",
			    arg_session_name,
			    opt_output_path);
		} else if (arg_session_name && !opt_output_path) {
			MSG("Session %s saved successfully.", arg_session_name);
		} else if (!arg_session_name && opt_output_path) {
			MSG("All sessions have been saved successfully in %s.", opt_output_path);
		} else {
			MSG("All sessions have been saved successfully.");
		}
		success = 1;
	}

	/* Mi Printing and closing */
	if (lttng_opt_mi) {
		/* Mi print */
		ret = mi_save_print(arg_session_name);
		if (ret) {
			ret = CMD_ERROR;
			goto end_destroy;
		}

		/* Close  output element */
		ret = mi_lttng_writer_close_element(writer);
		if (ret) {
			ret = CMD_ERROR;
			goto end_destroy;
		}

		/* Success ? */
		ret = mi_lttng_writer_write_element_bool(
			writer, mi_lttng_element_command_success, success);
		if (ret) {
			ret = CMD_ERROR;
			goto end_destroy;
		}

		/* Command element close */
		ret = mi_lttng_writer_command_close(writer);
		if (ret) {
			ret = CMD_ERROR;
			goto end_destroy;
		}
	}
end_destroy:
	lttng_save_session_attr_destroy(attr);
end:
	/* Mi clean-up */
	if (writer && mi_lttng_writer_destroy(writer)) {
		/* Preserve original error code */
		ret = ret ? ret : -LTTNG_ERR_MI_IO_FAIL;
	}

	/* Overwrite ret if command failed */
	ret = command_ret ? -command_ret : ret;

	poptFreeContext(pc);
	return ret;
}
