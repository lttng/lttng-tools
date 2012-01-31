/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; only version 2
 * of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#define _GNU_SOURCE
#include <popt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "../command.h"
#include "../utils.h"

static char *opt_output_path;
static char *opt_session_name;

enum {
	OPT_HELP = 1,
	OPT_LIST_OPTIONS,
};

static struct poptOption long_options[] = {
	/* longName, shortName, argInfo, argPtr, value, descrip, argDesc */
	{"help", 'h', POPT_ARG_NONE, NULL, OPT_HELP, NULL, NULL},
	{"output", 'o', POPT_ARG_STRING, &opt_output_path, 0, NULL, NULL},
	{"list-options", 0, POPT_ARG_NONE, NULL, OPT_LIST_OPTIONS, NULL, NULL},
	{0, 0, 0, 0, 0, 0, 0}
};

/*
 * usage
 */
static void usage(FILE *ofp)
{
	fprintf(ofp, "usage: lttng create [options] [NAME]\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "  The default NAME is 'auto-yyyymmdd-hhmmss'\n");
	fprintf(ofp, "  -h, --help           Show this help\n");
	fprintf(ofp, "      --list-options   Simple listing of options\n");
	fprintf(ofp, "  -o, --output PATH    Specify output path for traces\n");
	fprintf(ofp, "\n");
}

/*
 *  Create a tracing session.
 *  If no name is specified, a default name is generated.
 *
 *  Returns one of the CMD_* result constants.
 */
static int create_session()
{
	int ret;
	char datetime[16];
	char *session_name, *traces_path = NULL, *alloc_path = NULL;
	time_t rawtime;
	struct tm *timeinfo;

	/* Get date and time for automatic session name/path */
	time(&rawtime);
	timeinfo = localtime(&rawtime);
	strftime(datetime, sizeof(datetime), "%Y%m%d-%H%M%S", timeinfo);

	/* Auto session name creation */
	if (opt_session_name == NULL) {
		ret = asprintf(&session_name, "auto");
		if (ret < 0) {
			perror("asprintf session name");
			ret = CMD_ERROR;
			goto error;
		}
		DBG("Auto session name set to %s", session_name);
	} else {
		session_name = opt_session_name;
	}

	/* Auto output path */
	if (opt_output_path == NULL) {
		alloc_path = strdup(config_get_default_path());
		if (alloc_path == NULL) {
			ERR("Home path not found.\n"
				"Please specify an output path using -o, --output PATH\n");
			ret = CMD_FATAL;
			goto error;
		}

		ret = asprintf(&traces_path, "%s/" DEFAULT_TRACE_DIR_NAME "/%s-%s",
				alloc_path, session_name, datetime);
		if (ret < 0) {
			perror("asprintf trace dir name");
			ret = CMD_ERROR;
			goto error;
		}
	} else {
		traces_path = opt_output_path;
	}

	ret = lttng_create_session(session_name, traces_path);
	if (ret < 0) {
		ret = CMD_ERROR;
		goto error;
	}

	/* Init lttng session config */
	ret = config_init(session_name);
	if (ret < 0) {
		ret = CMD_ERROR;
		goto error;
	}

	MSG("Session %s created.", session_name);
	MSG("Traces will be written in %s" , traces_path);

	ret = CMD_SUCCESS;

error:
	if (opt_session_name == NULL) {
		free(session_name);
	}

	if (alloc_path) {
		free(alloc_path);
	}

	if (traces_path) {
		free(traces_path);
	}
	return ret;
}

/*
 *  The 'create <options>' first level command
 *
 *  Returns one of the CMD_* result constants.
 */
int cmd_create(int argc, const char **argv)
{
	int opt, ret = CMD_SUCCESS;
	static poptContext pc;

	pc = poptGetContext(NULL, argc, argv, long_options, 0);
	poptReadDefaultConfig(pc, 0);

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

	ret = create_session();

end:
	return ret;
}
