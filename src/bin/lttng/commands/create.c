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
#include <assert.h>
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

#include <common/defaults.h>
#include <common/sessiond-comm/sessiond-comm.h>
#include <common/uri.h>
#include <common/utils.h>
#include <lttng/snapshot.h>

static char *opt_output_path;
static char *opt_session_name;
static char *opt_url;
static char *opt_ctrl_url;
static char *opt_data_url;
static int opt_no_consumer;
static int opt_no_output;
static int opt_snapshot;
static int opt_disable_consumer;

enum {
	OPT_HELP = 1,
	OPT_LIST_OPTIONS,
};

static struct poptOption long_options[] = {
	/* longName, shortName, argInfo, argPtr, value, descrip, argDesc */
	{"help", 'h', POPT_ARG_NONE, NULL, OPT_HELP, NULL, NULL},
	{"output", 'o', POPT_ARG_STRING, &opt_output_path, 0, NULL, NULL},
	{"list-options", 0, POPT_ARG_NONE, NULL, OPT_LIST_OPTIONS, NULL, NULL},
	{"set-url",        'U', POPT_ARG_STRING, &opt_url, 0, 0, 0},
	{"ctrl-url",       'C', POPT_ARG_STRING, &opt_ctrl_url, 0, 0, 0},
	{"data-url",       'D', POPT_ARG_STRING, &opt_data_url, 0, 0, 0},
	{"no-output",       0, POPT_ARG_VAL, &opt_no_output, 1, 0, 0},
	{"no-consumer",     0, POPT_ARG_VAL, &opt_no_consumer, 1, 0, 0},
	{"disable-consumer", 0, POPT_ARG_VAL, &opt_disable_consumer, 1, 0, 0},
	{"snapshot",        0, POPT_ARG_VAL, &opt_snapshot, 1, 0, 0},
	{0, 0, 0, 0, 0, 0, 0}
};

/*
 * Please have a look at src/lib/lttng-ctl/lttng-ctl.c for more information on
 * why this declaration exists and used ONLY in for this command.
 */
extern int _lttng_create_session_ext(const char *name, const char *url,
		const char *datetime);

/*
 * usage
 */
static void usage(FILE *ofp)
{
	fprintf(ofp, "usage: lttng create [NAME] [OPTIONS] \n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Without a given NAME, the default is 'auto-<yyyymmdd>-<hhmmss>'\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Options:\n");
	fprintf(ofp, "  -h, --help           Show this help\n");
	fprintf(ofp, "      --list-options   Simple listing of options\n");
	fprintf(ofp, "  -o, --output PATH    Specify output path for traces\n");
	fprintf(ofp, "      --no-output      Traces will not be outputed\n");
	fprintf(ofp, "      --snasphot       Set the session in snapshot mode.\n");
	fprintf(ofp, "                       Created in no-output mode and uses the URL,\n");
	fprintf(ofp, "                       if one, as the default snapshot output.\n");
	fprintf(ofp, "                       Every channel will be set in overwrite mode\n");
	fprintf(ofp, "                       and with mmap output (splice not supported).\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Extended Options:\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Using these options, each API call can be controlled individually.\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "  -U, --set-url=URL    Set URL destination of the trace data.\n");
	fprintf(ofp, "                       It is persistent for the session lifetime.\n");
	fprintf(ofp, "                       This will set both data and control URL.\n");
	fprintf(ofp, "                       You can change it with the enable-consumer cmd\n");
	fprintf(ofp, "  -C, --ctrl-url=URL   Set control path URL. (Must use -D also)\n");
	fprintf(ofp, "  -D, --data-url=URL   Set data path URL. (Must use -C also)\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Please refer to the man page (lttng(1)) for more information on network\n");
	fprintf(ofp, "streaming mechanisms and explanation of the control and data port\n");
	fprintf(ofp, "You must have a running remote lttng-relayd for network streaming\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "URL format is has followed:\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "  proto://[HOST|IP][:PORT1[:PORT2]][/TRACE_PATH]\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "  Supported protocols are (proto):\n");
	fprintf(ofp, "  > file://...\n");
	fprintf(ofp, "    Local filesystem full path.\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "  > net[6]://...\n");
	fprintf(ofp, "    This will use the default network transport layer which is\n");
	fprintf(ofp, "    TCP for both control (PORT1) and data port (PORT2).\n");
	fprintf(ofp, "    The default ports are respectively 5342 and 5343.\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "  > tcp[6]://...\n");
	fprintf(ofp, "    Can only be used with -C and -D together\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "NOTE: IPv6 address MUST be enclosed in brackets '[]' (rfc2732)\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Examples:\n");
	fprintf(ofp, "    # lttng create -U net://192.168.1.42\n");
	fprintf(ofp, "    Uses TCP and default ports for the given destination.\n");
	fprintf(ofp, "    # lttng create -U net6://[fe80::f66d:4ff:fe53:d220]\n");
	fprintf(ofp, "    Uses TCP, default ports and IPv6.\n");
	fprintf(ofp, "    # lttng create s1 -U net://myhost.com:3229\n");
	fprintf(ofp, "    Set the consumer to the remote HOST on port 3229 for control.\n");
	fprintf(ofp, "\n");
}

/*
 * For a session name, set the consumer URLs.
 */
static int set_consumer_url(const char *session_name, const char *ctrl_url,
		const char *data_url)
{
	int ret;
	struct lttng_handle *handle;
	struct lttng_domain dom;

	assert(session_name);

	/*
	 * Set handle with the session name and the domain set to 0. This means to
	 * the session daemon that the next action applies on the tracing session
	 * rather then the domain specific session.
	 */
	memset(&dom, 0, sizeof(dom));

	handle = lttng_create_handle(session_name, &dom);
	if (handle == NULL) {
		ret = CMD_FATAL;
		goto error;
	}

	ret = lttng_set_consumer_url(handle, ctrl_url, data_url);
	if (ret < 0) {
		goto error;
	}

	if (ctrl_url) {
		MSG("Control URL %s set for session %s", ctrl_url, session_name);
	}

	if (data_url) {
		MSG("Data URL %s set for session %s", data_url, session_name);
	}

error:
	lttng_destroy_handle(handle);
	return ret;
}

static int add_snapshot_output(const char *session_name, const char *ctrl_url,
		const char *data_url)
{
	int ret;
	struct lttng_snapshot_output *output = NULL;

	assert(session_name);

	output = lttng_snapshot_output_create();
	if (!output) {
		ret = CMD_FATAL;
		goto error_create;
	}

	if (ctrl_url) {
		ret = lttng_snapshot_output_set_ctrl_url(ctrl_url, output);
		if (ret < 0) {
			goto error;
		}
	}

	if (data_url) {
		ret = lttng_snapshot_output_set_data_url(data_url, output);
		if (ret < 0) {
			goto error;
		}
	}

	/* This call, if successful, populates the id of the output object. */
	ret = lttng_snapshot_add_output(session_name, output);
	if (ret < 0) {
		goto error;
	}

error:
	lttng_snapshot_output_destroy(output);
error_create:
	return ret;
}

/*
 *  Create a tracing session.
 *  If no name is specified, a default name is generated.
 *
 *  Returns one of the CMD_* result constants.
 */
static int create_session(void)
{
	int ret;
	char *session_name = NULL, *traces_path = NULL, *alloc_path = NULL;
	char *alloc_url = NULL, *url = NULL, datetime[16];
	char session_name_date[NAME_MAX + 17], *print_str_url = NULL;
	time_t rawtime;
	struct tm *timeinfo;

	/* Get date and time for automatic session name/path */
	time(&rawtime);
	timeinfo = localtime(&rawtime);
	strftime(datetime, sizeof(datetime), "%Y%m%d-%H%M%S", timeinfo);

	/* Auto session name creation */
	if (opt_session_name == NULL) {
		ret = snprintf(session_name_date, sizeof(session_name_date),
				DEFAULT_SESSION_NAME "-%s", datetime);
		if (ret < 0) {
			PERROR("snprintf session name");
			goto error;
		}
		session_name = session_name_date;
		DBG("Auto session name set to %s", session_name_date);
	} else {
		if (strlen(opt_session_name) > NAME_MAX) {
			ERR("Session name too long. Length must be lower or equal to %d",
					NAME_MAX);
			ret = LTTNG_ERR_SESSION_FAIL;
			goto error;
		}
		/*
		 * Check if the session name begins with "auto-" or is exactly "auto".
		 * Both are reserved for the default session name. See bug #449 to
		 * understand why we need to check both here.
		 */
		if ((strncmp(opt_session_name, DEFAULT_SESSION_NAME "-",
					strlen(DEFAULT_SESSION_NAME) + 1) == 0) ||
				(strncmp(opt_session_name, DEFAULT_SESSION_NAME,
					strlen(DEFAULT_SESSION_NAME)) == 0 &&
				strlen(opt_session_name) == strlen(DEFAULT_SESSION_NAME))) {
			ERR("%s is a reserved keyword for default session(s)",
					DEFAULT_SESSION_NAME);
			ret = CMD_ERROR;
			goto error;
		}
		session_name = opt_session_name;
		ret = snprintf(session_name_date, sizeof(session_name_date),
				"%s-%s", session_name, datetime);
		if (ret < 0) {
			PERROR("snprintf session name");
			goto error;
		}
	}

	if (opt_output_path != NULL) {
		traces_path = utils_expand_path(opt_output_path);
		if (traces_path == NULL) {
			ret = CMD_ERROR;
			goto error;
		}

		/* Create URL string from the local filesytem path */
		ret = asprintf(&alloc_url, "file://%s", traces_path);
		if (ret < 0) {
			PERROR("asprintf url path");
			ret = CMD_FATAL;
			goto error;
		}
		/* URL to use in the lttng_create_session() call */
		url = alloc_url;
		print_str_url = traces_path;
	} else if (opt_url) { /* Handling URL (-U opt) */
		url = opt_url;
		print_str_url = url;
	} else if (!opt_no_output) {
		/* Auto output path */
		alloc_path = utils_get_home_dir();
		if (alloc_path == NULL) {
			ERR("HOME path not found.\n \
					Please specify an output path using -o, --output PATH");
			ret = CMD_FATAL;
			goto error;
		}
		alloc_path = strdup(alloc_path);

		ret = asprintf(&alloc_url,
				"file://%s/" DEFAULT_TRACE_DIR_NAME "/%s",
				alloc_path, session_name_date);
		if (ret < 0) {
			PERROR("asprintf trace dir name");
			ret = CMD_FATAL;
			goto error;
		}

		url = alloc_url;
		if (!opt_data_url && !opt_ctrl_url) {
			print_str_url = alloc_url + strlen("file://");
		}
	} else {
		/* No output means --no-output or --snapshot mode. */
		url = NULL;
	}

	if ((!opt_ctrl_url && opt_data_url) || (opt_ctrl_url && !opt_data_url)) {
		ERR("You need both control and data URL.");
		ret = CMD_ERROR;
		goto error;
	}

	if (opt_snapshot) {
		/* No output by default. */
		const char *snapshot_url = NULL;

		if (opt_url) {
			snapshot_url = url;
		} else if (!opt_data_url && !opt_ctrl_url) {
			/* This is the session path that we need to use as output. */
			snapshot_url = url;
		}
		ret = lttng_create_session_snapshot(session_name, snapshot_url);
	} else {
		ret = _lttng_create_session_ext(session_name, url, datetime);
	}
	if (ret < 0) {
		/* Don't set ret so lttng can interpret the sessiond error. */
		switch (-ret) {
		case LTTNG_ERR_EXIST_SESS:
			WARN("Session %s already exists", session_name);
			break;
		default:
			break;
		}
		goto error;
	}

	if (opt_ctrl_url && opt_data_url) {
		if (opt_snapshot) {
			ret = add_snapshot_output(session_name, opt_ctrl_url,
					opt_data_url);
		} else {
			/* Setting up control URI (-C or/and -D opt) */
			ret = set_consumer_url(session_name, opt_ctrl_url, opt_data_url);
		}
		if (ret < 0) {
			/* Destroy created session because the URL are not valid. */
			lttng_destroy_session(session_name);
			goto error;
		}
	}

	MSG("Session %s created.", session_name);
	if (print_str_url && !opt_snapshot) {
		MSG("Traces will be written in %s", print_str_url);
	} else if (opt_snapshot) {
		if (print_str_url) {
			MSG("Default snapshot output set to: %s", print_str_url);
		}
		MSG("Snapshot mode set. Every channel enabled for that session will "
				"be set in overwrite mode and mmap output");
	}

	/* Init lttng session config */
	ret = config_init(session_name);
	if (ret < 0) {
		ret = CMD_ERROR;
		goto error;
	}

	ret = CMD_SUCCESS;

error:
	free(alloc_url);
	free(traces_path);
	free(alloc_path);

	if (ret < 0) {
		ERR("%s", lttng_strerror(ret));
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

	if (opt_no_consumer) {
		MSG("The option --no-consumer is obsolete. Use --no-output now.");
		ret = CMD_WARNING;
		goto end;
	}

	if (opt_disable_consumer) {
		MSG("The option --disable-consumer is obsolete.");
		ret = CMD_WARNING;
		goto end;
	}

	opt_session_name = (char*) poptGetArg(pc);

	ret = create_session();

end:
	poptFreeContext(pc);
	return ret;
}
