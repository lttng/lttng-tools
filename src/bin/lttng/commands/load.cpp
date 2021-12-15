/*
 * Copyright (C) 2014 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include <inttypes.h>
#include <popt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <common/mi-lttng.hpp>
#include <common/config/session-config.hpp>
#include <lttng/lttng.h>

#include "../command.hpp"

static char *the_opt_input_path;
static char *the_opt_override_url;
static char *the_opt_override_session_name;
static int the_opt_force;
static int the_opt_load_all;

static const char *the_session_name;

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

static struct mi_writer *the_writer;

static struct poptOption the_load_opts[] = {
	/* longName, shortName, argInfo, argPtr, value, descrip, argDesc */
	{"help",          'h', POPT_ARG_NONE, 0, OPT_HELP, 0, 0},
	{"all",           'a', POPT_ARG_NONE, 0, OPT_ALL, 0, 0},
	{"input-path",    'i', POPT_ARG_STRING, &the_opt_input_path, 0, 0, 0},
	{"force",         'f', POPT_ARG_NONE, 0, OPT_FORCE, 0, 0},
	{"override-url",    0, POPT_ARG_STRING, &the_opt_override_url, 0, 0, 0},
	{"override-name",   0, POPT_ARG_STRING, &the_opt_override_session_name, 0, 0, 0},
	{"list-options",    0, POPT_ARG_NONE, NULL, OPT_LIST_OPTIONS, NULL, NULL},
	{0, 0, 0, 0, 0, 0, 0}
};

static int mi_partial_session(const char *session_name)
{
	int ret;
	LTTNG_ASSERT(the_writer);
	LTTNG_ASSERT(session_name);

	/* Open session element */
	ret = mi_lttng_writer_open_element(the_writer, config_element_session);
	if (ret) {
		goto end;
	}

	ret = mi_lttng_writer_write_element_string(the_writer, config_element_name,
			session_name);
	if (ret) {
		goto end;
	}

	/* Closing session element */
	ret = mi_lttng_writer_close_element(the_writer);
end:
	return ret;
}

/*
 * Mi print of load command
 */
static int mi_load_print(const char *session_name)
{
	int ret;
	LTTNG_ASSERT(the_writer);

	if (the_opt_load_all) {
		/* We use a wildcard to represent all sessions */
		session_name = "*";
	}

	/* Print load element */
	ret = mi_lttng_writer_open_element(the_writer, mi_lttng_element_load);
	if (ret) {
		goto end;
	}

	/* Print session element */
	ret = mi_partial_session(session_name);
	if (ret) {
		goto end;
	}

	/* Path element */
	if (the_opt_input_path) {
		ret = mi_lttng_writer_write_element_string(the_writer, config_element_path,
				the_opt_input_path);
		if (ret) {
			goto end;
		}
	}

	/* Print override elements */
	ret = mi_lttng_writer_open_element(the_writer, mi_lttng_element_load_overrides);
	if (ret) {
		goto end;
	}

	/* Session name override element */
	if (the_opt_override_session_name) {
		ret = mi_lttng_writer_write_element_string(the_writer,
				config_element_name, the_opt_override_session_name);
		if (ret) {
			goto end;
		}
	}

	/* Session url override element */
	if (the_opt_override_url) {
		ret = mi_lttng_writer_write_element_string(the_writer,
				mi_lttng_element_load_override_url,
				the_opt_override_url);
		if (ret) {
			goto end;
		}
	}

	/* Close override and load element */
	ret = mi_lttng_close_multi_element(the_writer, 2);
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
	const char *leftover = NULL;

	pc = poptGetContext(NULL, argc, argv, the_load_opts, 0);
	poptReadDefaultConfig(pc, 0);

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case OPT_HELP:
			SHOW_HELP();
			ret = CMD_SUCCESS;
			goto end;
		case OPT_ALL:
			the_opt_load_all = 1;
			break;
		case OPT_LIST_OPTIONS:
			list_cmd_options(stdout, the_load_opts);
			ret = CMD_SUCCESS;
			goto end;
		case OPT_FORCE:
			the_opt_force = 1;
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

	if (!the_opt_load_all) {
		the_session_name = poptGetArg(pc);
		if (the_session_name) {
			DBG2("Loading session name: %s", the_session_name);
		} else {
			/* Default to load_all */
			the_opt_load_all = 1;
		}
	}

	leftover = poptGetArg(pc);
	if (leftover) {
		ERR("Unknown argument: %s", leftover);
		ret = CMD_ERROR;
		goto end;
	}

	/* Mi check */
	if (lttng_opt_mi) {
		the_writer = mi_lttng_writer_create(fileno(stdout), lttng_opt_mi);
		if (!the_writer) {
			ret = CMD_ERROR;
			goto end;
		}

		/* Open command element */
		ret = mi_lttng_writer_command_open(the_writer,
				mi_lttng_element_command_load);
		if (ret) {
			ret = CMD_ERROR;
			goto end;
		}

		/* Open output element */
		ret = mi_lttng_writer_open_element(the_writer,
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
	if (the_opt_input_path) {
		input_path = realpath(the_opt_input_path, NULL);
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
			the_session_name);
	if (ret) {
		ERR("Invalid session name");
		ret = CMD_ERROR;
		goto end;
	}

	/* Set the overwrite attribute */
	ret = lttng_load_session_attr_set_overwrite(session_attr, the_opt_force);
	if (ret) {
		ERR("Force argument could not be applied");
		ret = CMD_ERROR;
		goto end;
	}

	/* Set the overrides attributes if any */
	if (the_opt_override_url) {
		ret = lttng_load_session_attr_set_override_url(session_attr,
				the_opt_override_url);
		if (ret) {
			ERR("Url override is invalid");
			goto end;
		}
	}

	if (the_opt_override_session_name) {
		if (the_opt_load_all) {
			ERR("Options --all and --override-name cannot be used simultaneously");
			ret = CMD_ERROR;
			goto end;
		}
		ret = lttng_load_session_attr_set_override_session_name(session_attr,
				the_opt_override_session_name);
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
		if (the_opt_load_all) {
			MSG("All sessions have been loaded successfully");
		} else if (the_session_name) {
			ret = config_init((char *) the_session_name);
			if (ret < 0) {
				WARN("Could not set %s as the default session",
						the_session_name);
			}
			MSG("Session %s has been loaded successfully", the_session_name);
		} else {
			MSG("Session has been loaded successfully");
		}

		if (the_opt_override_session_name) {
			MSG("Session name overridden with %s",
					the_opt_override_session_name);
		}

		if (the_opt_override_url) {
			MSG("Session output url overridden with %s", the_opt_override_url);
		}
		success = 1;
		ret = CMD_SUCCESS;
	}

	/* Mi Printing and closing */
	if (lttng_opt_mi) {
		/* Mi print */
		ret = mi_load_print(the_session_name);
		if (ret) {
			ret = CMD_ERROR;
			goto end;
		}

		/* Close  output element */
		ret = mi_lttng_writer_close_element(the_writer);
		if (ret) {
			ret = CMD_ERROR;
			goto end;
		}

		/* Success ? */
		ret = mi_lttng_writer_write_element_bool(the_writer,
				mi_lttng_element_command_success, success);
		if (ret) {
			ret = CMD_ERROR;
			goto end;
		}

		/* Command element close */
		ret = mi_lttng_writer_command_close(the_writer);
		if (ret) {
			ret = CMD_ERROR;
			goto end;
		}
	}
end:
	if (the_writer && mi_lttng_writer_destroy(the_writer)) {
		ERR("Failed to destroy mi lttng writer");
	}

	lttng_load_session_attr_destroy(session_attr);
	free(input_path);
	poptFreeContext(pc);
	return ret;
}
