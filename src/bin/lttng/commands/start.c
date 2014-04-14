/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
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
#include <popt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "../command.h"

#include <common/sessiond-comm/sessiond-comm.h>

static char *opt_session_name;

enum {
	OPT_HELP = 1,
	OPT_LIST_OPTIONS,
};

static struct poptOption long_options[] = {
	/* longName, shortName, argInfo, argPtr, value, descrip, argDesc */
	{"help",      'h', POPT_ARG_NONE, 0, OPT_HELP, 0, 0},
	{"list-options", 0, POPT_ARG_NONE, NULL, OPT_LIST_OPTIONS, NULL, NULL},
	{0, 0, 0, 0, 0, 0, 0}
};

/*
 * usage
 */
static void usage(FILE *ofp)
{
	fprintf(ofp, "usage: lttng start [NAME] [OPTIONS]\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Where NAME is an optional session name. If not specified, lttng will\n");
	fprintf(ofp, "get it from the configuration directory (.lttng).\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Options:\n");
	fprintf(ofp, "  -h, --help               Show this help\n");
	fprintf(ofp, "      --list-options       Simple listing of options\n");
	fprintf(ofp, "\n");
}

/*
 *  start_tracing
 *
 *  Start tracing for all trace of the session.
 */
static int start_tracing(void)
{
	int ret;
	char *session_name;

	if (opt_session_name == NULL) {
		session_name = get_session_name();
		if (session_name == NULL) {
			ret = CMD_ERROR;
			goto error;
		}
	} else {
		session_name = opt_session_name;
	}

	DBG("Starting tracing for session %s", session_name);

	ret = lttng_start_tracing(session_name);
	if (ret < 0) {
		switch (-ret) {
		case LTTNG_ERR_TRACE_ALREADY_STARTED:
			WARN("Tracing already started for session %s", session_name);
			break;
		default:
			ERR("%s", lttng_strerror(ret));
			break;
		}
		goto free_name;
	}

	ret = CMD_SUCCESS;

	MSG("Tracing started for session %s", session_name);

free_name:
	if (opt_session_name == NULL) {
		free(session_name);
	}
error:
	return ret;
}

/*
 *  cmd_start
 *
 *  The 'start <options>' first level command
 */
int cmd_start(int argc, const char **argv)
{
	int opt, ret = CMD_SUCCESS;
	static poptContext pc;

	pc = poptGetContext(NULL, argc, argv, long_options, 0);
	poptReadDefaultConfig(pc, 0);

	/* TODO: mi support */
	if (lttng_opt_mi) {
		ret = -LTTNG_ERR_MI_NOT_IMPLEMENTED;
		ERR("mi option not supported");
		goto end;
	}

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case OPT_HELP:
			usage(stdout);
			goto end;
		case OPT_LIST_OPTIONS:
			list_cmd_options(stdout, long_options);
			goto end;
		default:
			usage(stderr);
			ret = CMD_UNDEFINED;
			goto end;
		}
	}

	opt_session_name = (char*) poptGetArg(pc);

	ret = start_tracing();

end:
	poptFreeContext(pc);
	return ret;
}
