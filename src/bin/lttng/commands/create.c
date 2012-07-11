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
#include <time.h>
#include <unistd.h>

#include "../command.h"
#include "../utils.h"

#include <common/defaults.h>
#include <common/sessiond-comm/sessiond-comm.h>
#include <common/uri.h>

static char *opt_output_path;
static char *opt_session_name;
static char *opt_uris;
static char *opt_ctrl_uris;
static char *opt_data_uris;
static int opt_no_consumer = 1;

enum {
	OPT_HELP = 1,
	OPT_LIST_OPTIONS,
};

static struct poptOption long_options[] = {
	/* longName, shortName, argInfo, argPtr, value, descrip, argDesc */
	{"help", 'h', POPT_ARG_NONE, NULL, OPT_HELP, NULL, NULL},
	{"output", 'o', POPT_ARG_STRING, &opt_output_path, 0, NULL, NULL},
	{"list-options", 0, POPT_ARG_NONE, NULL, OPT_LIST_OPTIONS, NULL, NULL},
	{"set-uri",        'U', POPT_ARG_STRING, &opt_uris, 0, 0, 0},
	{"ctrl-uri",       'C', POPT_ARG_STRING, &opt_ctrl_uris, 0, 0, 0},
	{"data-uri",       'D', POPT_ARG_STRING, &opt_data_uris, 0, 0, 0},
	{"no-consumer",      0, POPT_ARG_NONE, &opt_no_consumer, 0, 0, 0},
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
	fprintf(ofp, "  -U, --set-uri=URI    Set URI for the enable-consumer destination.\n");
	fprintf(ofp, "                       It is persistent for the session lifetime.\n");
	fprintf(ofp, "                       Redo the command to change it.\n");
	fprintf(ofp, "                       This will set both data and control URI for network.\n");
	fprintf(ofp, "  -C, --ctrl-uri=URI   Set control path URI.\n");
	fprintf(ofp, "  -D, --data-uri=URI   Set data path URI.\n");
	fprintf(ofp, "      --no-consumer    Disable consumer for entire tracing session.\n");
	fprintf(ofp, "\n");
}

/*
 * Parse URI from string to lttng_uri object array.
 */
static ssize_t parse_uri_from_str(const char *str_uri, struct lttng_uri **uris)
{
	int i;
	ssize_t size;
	struct lttng_uri *uri;

	if (*uris != NULL) {
		free(*uris);
	}

	size = uri_parse(str_uri, uris);
	if (size < 1) {
		ERR("Bad URI %s. Either the hostname or IP is invalid", str_uri);
		size = -1;
	}

	for (i = 0; i < size; i++) {
		uri = (struct lttng_uri *) &uris[i];
		/* Set default port if none was given */
		if (uri->port == 0) {
			if (uri->stype == LTTNG_STREAM_CONTROL) {
				uri->port = DEFAULT_NETWORK_CONTROL_PORT;
			} else if (uri->stype == LTTNG_STREAM_DATA) {
				uri->port = DEFAULT_NETWORK_DATA_PORT;
			}
		}
	}

	return size;
}

/*
 * Print URI message.
 */
static void print_uri_msg(struct lttng_uri *uri)
{
	char *dst;

	switch (uri->dtype) {
	case LTTNG_DST_IPV4:
		dst = uri->dst.ipv4;
		break;
	case LTTNG_DST_IPV6:
		dst = uri->dst.ipv6;
		break;
	case LTTNG_DST_PATH:
		dst = uri->dst.path;
		MSG("Consumer destination set to %s", dst);
		goto end;
	default:
		DBG("Unknown URI destination");
		goto end;
	}

	MSG("Consumer %s stream set to %s with the %s protocol on port %d",
			uri->stype == LTTNG_STREAM_CONTROL ? "control" : "data",
			dst, uri->proto == LTTNG_TCP ? "TCP" : "UNK", uri->port);

end:
	return;
}

/*
 *  Create a tracing session.
 *  If no name is specified, a default name is generated.
 *
 *  Returns one of the CMD_* result constants.
 */
static int create_session()
{
	int ret, have_name = 0, i;
	char datetime[16];
	char *session_name, *traces_path = NULL, *alloc_path = NULL;
	time_t rawtime;
	ssize_t size;
	struct tm *timeinfo;
	struct lttng_uri *uris = NULL, *ctrl_uri = NULL, *data_uri = NULL;

	/* Get date and time for automatic session name/path */
	time(&rawtime);
	timeinfo = localtime(&rawtime);
	strftime(datetime, sizeof(datetime), "%Y%m%d-%H%M%S", timeinfo);

	/* Auto session name creation */
	if (opt_session_name == NULL) {
		ret = asprintf(&session_name, "auto-%s", datetime);
		if (ret < 0) {
			perror("asprintf session name");
			goto error;
		}
		DBG("Auto session name set to %s", session_name);
	} else {
		session_name = opt_session_name;
		have_name = 1;
	}

	if (opt_output_path != NULL) {
		traces_path = expand_full_path(opt_output_path);
		if (traces_path == NULL) {
			ret = CMD_ERROR;
			goto error;
		}

		ret = asprintf(&alloc_path, "file://%s", traces_path);
		if (ret < 0) {
			PERROR("asprintf expand path");
			ret = CMD_FATAL;
			goto error;
		}

		ret = uri_parse(alloc_path, &ctrl_uri);
		if (ret < 1) {
			ret = CMD_FATAL;
			goto error;
		}
	} else if (opt_uris) { /* Handling URIs (-U opt) */
		size = parse_uri_from_str(opt_uris, &uris);
		if (size < 1) {
			ret = CMD_ERROR;
			goto error;
		} else if (size == 1 && uris[0].dtype != LTTNG_DST_PATH) {
			ERR("Only net:// and file:// are supported. "
					"Use -C and -D for more fine grained control");
			ret = CMD_ERROR;
			goto error;
		} else if (size == 2) {
			uris[0].stype = LTTNG_STREAM_CONTROL;
			uris[1].stype = LTTNG_STREAM_DATA;

			for (i = 0; i < size; i++) {
				/* Set default port if none was given */
				if (uris[i].port == 0) {
					if (uris[i].stype == LTTNG_STREAM_CONTROL) {
						uris[i].port = DEFAULT_NETWORK_CONTROL_PORT;
					} else {
						uris[i].port = DEFAULT_NETWORK_DATA_PORT;
					}
				}
			}

			ctrl_uri = &uris[0];
			print_uri_msg(ctrl_uri);
			data_uri = &uris[1];
			print_uri_msg(data_uri);
		} else {
			ctrl_uri = &uris[0];
			print_uri_msg(ctrl_uri);
		}
	} else if (opt_ctrl_uris || opt_data_uris) {
		/* Setting up control URI (-C opt) */
		if (opt_ctrl_uris) {
			size = parse_uri_from_str(opt_ctrl_uris, &uris);
			if (size < 1) {
				ret = CMD_ERROR;
				goto error;
			}
			ctrl_uri = &uris[0];
			ctrl_uri->stype = LTTNG_STREAM_CONTROL;
			/* Set default port if none specified */
			if (ctrl_uri->port == 0) {
				ctrl_uri->port = DEFAULT_NETWORK_CONTROL_PORT;
			}
			print_uri_msg(ctrl_uri);
		}

		/* Setting up data URI (-D opt) */
		if (opt_data_uris) {
			size = parse_uri_from_str(opt_data_uris, &uris);
			if (size < 1) {
				ret = CMD_ERROR;
				goto error;
			}
			data_uri = &uris[0];
			data_uri->stype = LTTNG_STREAM_DATA;
			/* Set default port if none specified */
			if (data_uri->port == 0) {
				data_uri->port = DEFAULT_NETWORK_DATA_PORT;
			}
			print_uri_msg(data_uri);
		}
	} else {
		/* Auto output path */
		alloc_path = config_get_default_path();
		if (alloc_path == NULL) {
			ERR("HOME path not found.\n \
					Please specify an output path using -o, --output PATH");
			ret = CMD_FATAL;
			goto error;
		}
		alloc_path = strdup(alloc_path);

		if (have_name) {
			ret = asprintf(&traces_path, "file://%s/" DEFAULT_TRACE_DIR_NAME
					"/%s-%s", alloc_path, session_name, datetime);
		} else {
			ret = asprintf(&traces_path, "file://%s/" DEFAULT_TRACE_DIR_NAME
					"/%s", alloc_path, session_name);
		}
		if (ret < 0) {
			PERROR("asprintf trace dir name");
			ret = CMD_FATAL;
			goto error;
		}

		ret = uri_parse(traces_path, &ctrl_uri);
		if (ret < 1) {
			ret = CMD_FATAL;
			goto error;
		}
	}

	/* If there is no subdir specified and the URI are network */
	if (strlen(ctrl_uri->subdir) == 0) {
		if (have_name) {
			ret = snprintf(ctrl_uri->subdir, sizeof(ctrl_uri->subdir), "%s-%s",
					session_name, datetime);
		} else {
			ret = snprintf(ctrl_uri->subdir, sizeof(ctrl_uri->subdir), "%s",
					session_name);
		}
		if (ret < 0) {
			PERROR("snprintf subdir");
			goto error;
		}
		DBG("Subdir update to %s", ctrl_uri->subdir);
	}

	ret = lttng_create_session_uri(session_name, ctrl_uri, data_uri,
			opt_no_consumer);
	if (ret < 0) {
		/* Don't set ret so lttng can interpret the sessiond error. */
		switch (-ret) {
		case LTTCOMM_EXIST_SESS:
			WARN("Session %s already exists", session_name);
			break;
		}
		goto error;
	}

	/* Init lttng session config */
	ret = config_init(session_name);
	if (ret < 0) {
		ret = CMD_ERROR;
		goto error;
	}

	MSG("Session %s created.", session_name);
	if (ctrl_uri->dtype == LTTNG_DST_PATH) {
		MSG("Traces will be written in %s" , ctrl_uri->dst.path);
	}

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
	poptFreeContext(pc);
	return ret;
}
