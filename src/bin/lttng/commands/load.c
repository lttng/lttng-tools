/*
 * Copyright (C) 2014 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
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
#include <inttypes.h>
#include <popt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <common/mi-lttng.h>
#include <common/config/session-config.h>

#include "../command.h"

static char *opt_input_path;
static int opt_force;
static int opt_load_all;

static const char *session_name;

enum {
	OPT_HELP = 1,
	OPT_ALL,
	OPT_FORCE,
	OPT_LIST_OPTIONS,
};

static struct mi_writer *writer;

static struct poptOption load_opts[] = {
	/* longName, shortName, argInfo, argPtr, value, descrip, argDesc */
	{"help",        'h',  POPT_ARG_NONE, 0, OPT_HELP, 0, 0},
	{"all",         'a',  POPT_ARG_NONE, 0, OPT_ALL, 0, 0},
	{"input-path",  'i',  POPT_ARG_STRING, &opt_input_path, 0, 0, 0},
	{"force",       'f',  POPT_ARG_NONE, 0, OPT_FORCE, 0, 0},
	{"list-options",  0,  POPT_ARG_NONE, NULL, OPT_LIST_OPTIONS, NULL, NULL},
	{0, 0, 0, 0, 0, 0, 0}
};

/*
 * usage
 */
static void usage(FILE *ofp)
{
	fprintf(ofp, "usage: lttng load [OPTIONS] [SESSION]\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Options:\n");
	fprintf(ofp, "  -h, --help               Show this help\n");
	fprintf(ofp, "  -a, --all                Load all sessions (default)\n");
	fprintf(ofp, "  -i, --input-path PATH    Input path of the session file(s).\n");
	fprintf(ofp, "                           If a directory, load all files in it\n");
	fprintf(ofp, "                           else try to load the given file.\n");
	fprintf(ofp, "  -f, --force              Override existing session(s).\n");
	fprintf(ofp, "                           This will destroy existing session(s)\n");
	fprintf(ofp, "                           before creating new one(s).\n");
}

static int mi_partial_session(const char *session_name)
{
	int ret;
	assert(writer);
	assert(session_name);

	/* Open session element */
	ret = mi_lttng_writer_open_element(writer, config_element_session);
	if (ret) {
		goto end;
	}

	ret = mi_lttng_writer_write_element_string(writer, config_element_name,
			session_name);
	if (ret) {
		goto end;
	}

	/* Closing session element */
	ret = mi_lttng_writer_close_element(writer);
end:
	return ret;
}

/*
 * Mi print of load command
 */
static int mi_load_print(const char *session_name)
{
	int ret;
	assert(writer);

	if (opt_load_all) {
		/* We use a wildcard to represent all sessions */
		session_name = "*";
	}

	/* Print load element */
	ret = mi_lttng_writer_open_element(writer, mi_lttng_element_load);
	if (ret) {
		goto end;
	}

	/* Print session element */
	ret = mi_partial_session(session_name);
	if (ret) {
		goto end;
	}

	/* Path element */
	if (opt_input_path) {
		ret = mi_lttng_writer_write_element_string(writer, config_element_path,
				opt_input_path);
		if (ret) {
			goto end;
		}
	}

	/* Close load element */
	ret = mi_lttng_writer_close_element(writer);

end:
	return ret;
}

/*
 * The 'load <options>' first level command
 */
int cmd_load(int argc, const char **argv)
{
	int ret = CMD_SUCCESS, command_ret = CMD_SUCCESS, success;
	int opt;
	poptContext pc;

	pc = poptGetContext(NULL, argc, argv, load_opts, 0);
	poptReadDefaultConfig(pc, 0);

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case OPT_HELP:
			usage(stdout);
			goto end;
		case OPT_ALL:
			opt_load_all = 1;
			break;
		case OPT_LIST_OPTIONS:
			list_cmd_options(stdout, load_opts);
			goto end;
		case OPT_FORCE:
			opt_force = 1;
			break;
		default:
			usage(stderr);
			ret = CMD_UNDEFINED;
			goto end;
		}
	}

	if (!opt_load_all) {
		session_name = poptGetArg(pc);
		if (session_name) {
			DBG2("Loading session name: %s", session_name);
		} else {
			/* Default to load_all */
			opt_load_all = 1;
		}
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
				mi_lttng_element_command_load);
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

	command_ret = config_load_session(opt_input_path, session_name, opt_force, 0);
	if (command_ret) {
		ERR("%s", lttng_strerror(command_ret));
		success = 0;
	} else {
		if (opt_load_all) {
			MSG("All sessions have been loaded successfully");
		} else if (session_name) {
			ret = config_init((char *)session_name);
			if (ret < 0) {
				ret = CMD_WARNING;
			}
			MSG("Session %s has been loaded successfully", session_name);
		} else {
			MSG("Session has been loaded successfully");
		}
		success = 1;
	}

	/* Mi Printing and closing */
	if (lttng_opt_mi) {
		/* Mi print */
		ret = mi_load_print(session_name);
		if (ret) {
			ret = CMD_ERROR;
			goto end;
		}

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
	if (writer && mi_lttng_writer_destroy(writer)) {
		/* Preserve original error code */
		ret = ret ? ret : -LTTNG_ERR_MI_IO_FAIL;
	}

	/* Overwrite ret if the was an error with the load command */
	ret = command_ret ? -command_ret : ret;

	poptFreeContext(pc);
	return ret;
}
