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

#define _GNU_SOURCE
#include <inttypes.h>
#include <popt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <common/config/config.h>
#include "../command.h"

static char *opt_input_path;
static int opt_force;
static int opt_load_all;

static const char *session_name;

enum {
	OPT_HELP = 1,
	OPT_ALL,
	OPT_FORCE,
};

static struct poptOption load_opts[] = {
	/* longName, shortName, argInfo, argPtr, value, descrip, argDesc */
	{"help",        'h',  POPT_ARG_NONE, 0, OPT_HELP, 0, 0},
	{"all",         'a',  POPT_ARG_NONE, 0, OPT_ALL, 0, 0},
	{"input-path",  'i',  POPT_ARG_STRING, &opt_input_path, 0, 0, 0},
	{"force",       'f',  POPT_ARG_NONE, 0, OPT_FORCE, 0, 0},
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

/*
 * The 'load <options>' first level command
 */
int cmd_load(int argc, const char **argv)
{
	int ret = CMD_SUCCESS;
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
		}
	}

	ret = config_load_session(opt_input_path, session_name, opt_force, 0);
	if (ret) {
		ERR("%s", lttng_strerror(ret));
		ret = -ret;
	} else {
		if (opt_load_all) {
			MSG("All sessions have been loaded successfully");
		} else if (session_name) {
			MSG("Session %s has been loaded successfully", session_name);
		} else {
			MSG("Session has been loaded successfully");
		}
	}
end:
	poptFreeContext(pc);
	return ret;
}
