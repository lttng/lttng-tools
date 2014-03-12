/*
 * Copyright (C) 2013 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
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
#include <inttypes.h>
#include <popt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "../command.h"
#include <lttng/save.h>

static char *opt_output_path;
static int opt_force;
static int opt_save_all;

enum {
	OPT_HELP = 1,
	OPT_ALL,
	OPT_FORCE,
};

static struct poptOption save_opts[] = {
	/* longName, shortName, argInfo, argPtr, value, descrip, argDesc */
	{"help",        'h', POPT_ARG_NONE, 0, OPT_HELP, 0, 0},
	{"all",         'a', POPT_ARG_NONE, 0, OPT_ALL, 0, 0},
	{"output-path", 'o', POPT_ARG_STRING, &opt_output_path, 0, 0, 0},
	{"force",       'f', POPT_ARG_NONE, 0, OPT_FORCE, 0, 0},
	{0, 0, 0, 0, 0, 0, 0}
};

/*
 * usage
 */
static void usage(FILE *ofp)
{
	fprintf(ofp, "usage: lttng save [OPTIONS] [SESSION]\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Options:\n");
	fprintf(ofp, "  -h, --help           Show this help\n");
	fprintf(ofp, "  -a, --all            Save all sessions (default)\n");
	fprintf(ofp, "  -o, --output-path    Output path of the session configuration(s)\n");
	fprintf(ofp, "  -f, --force          Overwrite existing session configuration(s)\n");
}

/*
 * The 'save <options>' first level command
 */
int cmd_save(int argc, const char **argv)
{
	int ret = CMD_SUCCESS;
	int opt;
	const char *session_name = NULL;
	poptContext pc;
	struct lttng_save_session_attr *attr;

	pc = poptGetContext(NULL, argc, argv, save_opts, 0);
	poptReadDefaultConfig(pc, 0);

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case OPT_HELP:
			usage(stdout);
			goto end;
		case OPT_ALL:
			opt_save_all = 1;
			break;
		case OPT_FORCE:
			opt_force = 1;
			break;
		default:
			usage(stderr);
			ret = CMD_UNDEFINED;
			goto end;
		}
	}

	if (!opt_save_all) {
		session_name = poptGetArg(pc);
		if (!session_name) {
			ERR("A session name must be provided if the \"all\" option is not used.");
			ret = CMD_ERROR;
			goto end;
		}
		DBG2("Session name: %s", session_name);
	}

	attr = lttng_save_session_attr_create();
	if (!attr) {
		ret = CMD_FATAL;
		goto end_destroy;
	}

	if (lttng_save_session_attr_set_session_name(attr, session_name)) {
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

	ret = lttng_save_session(attr);
	if (ret < 0) {
		ERR("%s", lttng_strerror(ret));
	} else {
		/* Inform the user of what just happened on success. */
		if (session_name && opt_output_path) {
			MSG("Session %s saved successfully in %s.", session_name,
					opt_output_path);
		} else if (session_name && !opt_output_path) {
			MSG("Session %s saved successfully.", session_name);
		} else if (!session_name && opt_output_path) {
			MSG("All sessions have been saved successfully in %s.",
					opt_output_path);
		} else {
			MSG("All sessions have been saved successfully.");
		}
	}
end_destroy:
	lttng_save_session_attr_destroy(attr);
end:
	poptFreeContext(pc);
	return ret;
}
