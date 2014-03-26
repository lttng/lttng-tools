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
static int opt_destroy_all;

enum {
	OPT_HELP = 1,
	OPT_LIST_OPTIONS,
};

static struct poptOption long_options[] = {
	/* longName, shortName, argInfo, argPtr, value, descrip, argDesc */
	{"help",      'h', POPT_ARG_NONE, 0, OPT_HELP, 0, 0},
	{"all",       'a', POPT_ARG_VAL, &opt_destroy_all, 1, 0, 0},
	{"list-options", 0, POPT_ARG_NONE, NULL, OPT_LIST_OPTIONS, NULL, NULL},
	{0, 0, 0, 0, 0, 0, 0}
};

/*
 * usage
 */
static void usage(FILE *ofp)
{
	fprintf(ofp, "usage: lttng destroy [NAME] [OPTIONS]\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Where NAME is an optional session name. If not specified, lttng will\n");
	fprintf(ofp, "get it from the configuration directory (.lttng).\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Options:\n");
	fprintf(ofp, "  -h, --help           Show this help\n");
	fprintf(ofp, "  -a, --all            Destroy all sessions\n");
	fprintf(ofp, "      --list-options   Simple listing of options\n");
	fprintf(ofp, "\n");
}

/*
 * destroy_session
 *
 * Unregister the provided session to the session daemon. On success, removes
 * the default configuration.
 */
static int destroy_session(const char *session_name)
{
	int ret;

	ret = lttng_destroy_session(session_name);
	if (ret < 0) {
		switch (-ret) {
		case LTTNG_ERR_SESS_NOT_FOUND:
			WARN("Session name %s not found", session_name);
			break;
		default:
			ERR("%s", lttng_strerror(ret));
			break;
		}
		goto error;
	}

	MSG("Session %s destroyed", session_name);
	conf_destroy_default();
	ret = CMD_SUCCESS;
error:
	return ret;
}

/*
 * destroy_all_sessions
 *
 * Call destroy_sessions for each registered sessions
 */
static int destroy_all_sessions()
{
	int count, i, ret = CMD_SUCCESS;
	struct lttng_session *sessions;

	count = lttng_list_sessions(&sessions);
	if (count == 0) {
		MSG("No session found, nothing to do.");
	} else if (count < 0) {
		ERR("%s", lttng_strerror(ret));
		goto error;
	}

	for (i = 0; i < count; i++) {
		ret = destroy_session(sessions[i].name);
		if (ret < 0) {
			goto error;
		}
	}
error:
	return ret;
}

/*
 * The 'destroy <options>' first level command
 */
int cmd_destroy(int argc, const char **argv)
{
	int opt;
	int ret = CMD_SUCCESS;
	static poptContext pc;
	char *session_name = NULL;

	pc = poptGetContext(NULL, argc, argv, long_options, 0);
	poptReadDefaultConfig(pc, 0);

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case OPT_HELP:
			usage(stdout);
			break;
		case OPT_LIST_OPTIONS:
			list_cmd_options(stdout, long_options);
			break;
		default:
			usage(stderr);
			ret = CMD_UNDEFINED;
			break;
		}
		goto end;
	}

	/* Ignore session name in case all sessions are to be destroyed */
	if (opt_destroy_all) {
		ret = destroy_all_sessions();
		goto end;
	}

	opt_session_name = (char *) poptGetArg(pc);

	if (opt_session_name == NULL) {
		/* No session name specified, lookup default */
		session_name = get_session_name();
		if (session_name == NULL) {
			ret = CMD_ERROR;
			goto end;
		}
	} else {
		session_name = opt_session_name;
	}

	ret = destroy_session(session_name);

end:
	if (opt_session_name == NULL) {
		free(session_name);
	}

	poptFreeContext(pc);
	return ret;
}
