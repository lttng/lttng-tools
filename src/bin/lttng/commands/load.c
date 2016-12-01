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
#include <lttng/load.h>

#include "../command.h"

static char *opt_input_path;
static char *opt_override_url;
static char *opt_override_session_name;
static int opt_force;
static int opt_load_all;

static const char *session_name;

#ifdef LTTNG_EMBED_HELP
static const char help_msg[] =
#include <lttng-load.1.h>
;
#endif

enum {
	OPT_HELP = 1,
	OPT_ALL,
	OPT_FORCE,
	OPT_LIST_OPTIONS,
};

static struct mi_writer *writer;

static struct poptOption load_opts[] = {
	/* longName, shortName, argInfo, argPtr, value, descrip, argDesc */
	{"help",          'h', POPT_ARG_NONE, 0, OPT_HELP, 0, 0},
	{"all",           'a', POPT_ARG_NONE, 0, OPT_ALL, 0, 0},
	{"input-path",    'i', POPT_ARG_STRING, &opt_input_path, 0, 0, 0},
	{"force",         'f', POPT_ARG_NONE, 0, OPT_FORCE, 0, 0},
	{"override-url",    0, POPT_ARG_STRING, &opt_override_url, 0, 0, 0},
	{"override-name",   0, POPT_ARG_STRING, &opt_override_session_name, 0, 0, 0},
	{"list-options",    0, POPT_ARG_NONE, NULL, OPT_LIST_OPTIONS, NULL, NULL},
	{0, 0, 0, 0, 0, 0, 0}
};

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

	/* Print override elements */
	ret = mi_lttng_writer_open_element(writer, mi_lttng_element_load_overrides);
	if (ret) {
		goto end;
	}

	/* Session name override element */
	if (opt_override_session_name) {
		ret = mi_lttng_writer_write_element_string(writer,
				config_element_name, opt_override_session_name);
		if (ret) {
			goto end;
		}
	}

	/* Session url override element */
	if (opt_override_url) {
		ret = mi_lttng_writer_write_element_string(writer,
				mi_lttng_element_load_override_url,
				opt_override_url);
		if (ret) {
			goto end;
		}
	}

	/* Close override and load element */
	ret = mi_lttng_close_multi_element(writer, 2);
end:
	return ret;
}

/*
 * The 'load <options>' first level command
 */
int cmd_load(int argc, const char **argv)
{
	int ret, success;
	int opt;
	poptContext pc;
	struct lttng_load_session_attr *session_attr = NULL;
	char *input_path = NULL;

	pc = poptGetContext(NULL, argc, argv, load_opts, 0);
	poptReadDefaultConfig(pc, 0);

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case OPT_HELP:
			SHOW_HELP();
			ret = CMD_SUCCESS;
			goto end;
		case OPT_ALL:
			opt_load_all = 1;
			break;
		case OPT_LIST_OPTIONS:
			list_cmd_options(stdout, load_opts);
			ret = CMD_SUCCESS;
			goto end;
		case OPT_FORCE:
			opt_force = 1;
			break;
		default:
			ret = CMD_UNDEFINED;
			goto end;
		}
	}

	ret = lttng_session_daemon_alive();
	if (!ret) {
		ERR("No session daemon is available");
		ret = CMD_ERROR;
		goto end;
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
			ret = CMD_ERROR;
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

	/* Prepare load attributes */
	session_attr = lttng_load_session_attr_create();
	if (!session_attr) {
		ERR("Failed to create load session attributes");
		ret = CMD_ERROR;
		goto end;
	}

	/*
	 * Set the input url
	 * lttng_load_session_attr_set_input_url only suppports absolute path.
	 * Use realpath to resolve any relative path.
	 * */
	if (opt_input_path) {
		input_path = realpath(opt_input_path, NULL);
		if (!input_path) {
			PERROR("Invalid input path");
			ret = CMD_ERROR;
			goto end;
		}
	} else {
		input_path = NULL;
	}

	ret = lttng_load_session_attr_set_input_url(session_attr,
			input_path);
	if (ret) {
		ERR("Invalid input path");
		ret = CMD_ERROR;
		goto end;
	}

	/* Set the session name. NULL means all sessions should be loaded */
	ret = lttng_load_session_attr_set_session_name(session_attr,
			session_name);
	if (ret) {
		ERR("Invalid session name");
		ret = CMD_ERROR;
		goto end;
	}

	/* Set the overwrite attribute */
	ret = lttng_load_session_attr_set_overwrite(session_attr, opt_force);
	if (ret) {
		ERR("Force argument could not be applied");
		ret = CMD_ERROR;
		goto end;
	}

	/* Set the overrides attributes if any */
	if (opt_override_url) {
		ret = lttng_load_session_attr_set_override_url(session_attr,
				opt_override_url);
		if (ret) {
			ERR("Url override is invalid");
			goto end;
		}
	}

	if (opt_override_session_name) {
		if (opt_load_all) {
			ERR("Options --all and --override-name cannot be used simultaneously");
			ret = CMD_ERROR;
			goto end;
		}
		ret = lttng_load_session_attr_set_override_session_name(session_attr,
				opt_override_session_name);
		if (ret) {
			ERR("Failed to set session name override");
			ret = CMD_ERROR;
			goto end;
		}
	}

	ret = lttng_load_session(session_attr);
	if (ret) {
		ERR("%s", lttng_strerror(ret));
		success = 0;
		ret = CMD_ERROR;
	} else {
		if (opt_load_all) {
			MSG("All sessions have been loaded successfully");
		} else if (session_name) {
			ret = config_init((char *) session_name);
			if (ret < 0) {
				WARN("Could not set %s as the default session",
						session_name);
			}
			MSG("Session %s has been loaded successfully", session_name);
		} else {
			MSG("Session has been loaded successfully");
		}

		if (opt_override_session_name) {
			MSG("Session name overridden with %s",
					opt_override_session_name);
		}

		if (opt_override_url) {
			MSG("Session output url overridden with %s", opt_override_url);
		}
		success = 1;
		ret = CMD_SUCCESS;
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
		ERR("Failed to destroy mi lttng writer");
	}

	lttng_load_session_attr_destroy(session_attr);
	free(input_path);
	poptFreeContext(pc);
	return ret;
}
