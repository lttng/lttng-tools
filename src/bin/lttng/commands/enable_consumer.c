/*
 * Copyright (C) 2012 - David Goulet <dgoulet@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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

static int opt_kernel;
static int opt_userspace;
static int opt_enable;
static char *opt_session_name;
static char *opt_uris;
static char *opt_ctrl_uris;
static char *opt_data_uris;
static char *opt_uris_arg;

static struct lttng_handle *handle;

enum {
	OPT_HELP = 1,
	OPT_LIST_OPTIONS,
};

static struct poptOption long_options[] = {
	/* longName, shortName, argInfo, argPtr, value, descrip, argDesc */
	{"help",           'h', POPT_ARG_NONE, NULL, OPT_HELP, NULL, NULL},
	{"list-options",     0, POPT_ARG_NONE, NULL, OPT_LIST_OPTIONS, NULL, NULL},
	{"session",        's', POPT_ARG_STRING, &opt_session_name, 0, 0, 0},
	{"kernel",         'k', POPT_ARG_VAL, &opt_kernel, 1, 0, 0},
	{"userspace",      'u', POPT_ARG_VAL, &opt_userspace, 1, 0, 0},
	{"set-uri",        'U', POPT_ARG_STRING, &opt_uris, 0, 0, 0},
	{"ctrl-uri",       'C', POPT_ARG_STRING, &opt_ctrl_uris, 0, 0, 0},
	{"data-uri",       'D', POPT_ARG_STRING, &opt_data_uris, 0, 0, 0},
	{"enable",         'e', POPT_ARG_VAL, &opt_enable, 1, 0, 0},
	{0, 0, 0, 0, 0, 0, 0}
};

/*
 * usage
 */
static void usage(FILE *ofp)
{
	fprintf(ofp, "usage: lttng enable-consumer [-u|-k] [URI] [OPTIONS]\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "The default behavior is to enable a consumer to the current URI.\n");
	fprintf(ofp, "The default URI is the local filesystem at the path of the session.\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "The enable-consumer feature supports both local and network transport.\n");
	fprintf(ofp, "You must have a running lttng-relayd for network transmission.\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "You can optionally specify two URIs for respectively the\n");
	fprintf(ofp, "control and data channel. URI supported:\n");
	fprintf(ofp, "  > file://PATH\n");
	fprintf(ofp, "    Local file full system path.\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "  > net://DST[:CTRL_PORT[:DATA_PORT]] and net6://...\n");
	fprintf(ofp, "    This will use the default network transport layer which is\n");
	fprintf(ofp, "    TCP for both control and data port. The default ports are\n");
	fprintf(ofp, "    respectively 5342 and 5343.\n");
	fprintf(ofp, "    Example:\n");
	fprintf(ofp, "    # lttng enable-consumer net://192.168.1.42 -k\n");
	fprintf(ofp, "    Uses TCP and default ports for the given destination.\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "  > tcp://DST:PORT and tcp6://DST:PORT\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Options:\n");
	fprintf(ofp, "  -h, --help           Show this help\n");
	fprintf(ofp, "      --list-options   Simple listing of options\n");
	fprintf(ofp, "  -s, --session=NAME   Apply to session name\n");
	fprintf(ofp, "  -k, --kernel         Apply to the kernel tracer\n");
	fprintf(ofp, "  -u, --userspace      Apply to the user-space tracer\n");
	//fprintf(ofp, "  -U, --set-uri=URI1[,URI2,...]\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Extended Options:\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Using these options, each API call is controlled individually.\n");
	fprintf(ofp, "For instance, -C does not enable the consumer automatically.\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "  -U, --set-uri=URI    Set URI for the enable-consumer destination.\n");
	fprintf(ofp, "                       It is persistent for the session lifetime.\n");
	fprintf(ofp, "                       Redo the command to change it.\n");
	fprintf(ofp, "                       This will set both data and control URI for network.\n");
	//fprintf(ofp, "  -C, --ctrl-uri=URI1[,URI2,...]\n");
	fprintf(ofp, "  -C, --ctrl-uri=URI   Set control path URI.\n");
	//fprintf(ofp, "  -D, --data-uri=URI1[,URI2,...]\n");
	fprintf(ofp, "  -D, --data-uri=URI   Set data path URI.\n");
	fprintf(ofp, "  -e, --enable         Enable consumer\n");
	fprintf(ofp, "\n");
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
 * Setting URIs taking from the command line arguments. There is some
 * manipulations and special cases using the default args.
 */
static int set_consumer_arg_uris(struct lttng_uri *uri, size_t size)
{
	int ret, i;

	if (size == 2) {
		/* URIs are the control and data stream respectively for net:// */
		uri[0].stype = LTTNG_STREAM_CONTROL;
		uri[1].stype = LTTNG_STREAM_DATA;

		for (i = 0; i < size; i++) {
			ret = lttng_set_consumer_uri(handle, &uri[i]);
			if (ret < 0) {
				ERR("Setting %s stream URI: %s",
						uri[i].stype == LTTNG_STREAM_DATA ? "data" : "control",
						lttng_strerror(ret));
				goto error;
			}
			/* Set default port if none was given */
			if (uri[i].port == 0) {
				if (uri[i].stype == LTTNG_STREAM_CONTROL) {
					uri[i].port = DEFAULT_NETWORK_CONTROL_PORT;
				} else {
					uri[i].port = DEFAULT_NETWORK_DATA_PORT;
				}
			}
			print_uri_msg(&uri[i]);
		}
	} else if (size == 1 && uri[0].dtype == LTTNG_DST_PATH) {
		/* Set URI if it's file:// */
		ret = lttng_set_consumer_uri(handle, &uri[0]);
		if (ret < 0) {
			ERR("Failed to set URI %s: %s", opt_uris_arg,
					lttng_strerror(ret));
			goto error;
		}
		print_uri_msg(&uri[0]);
	} else {
		ERR("Only net:// and file:// are supported. "
				"Use -D or -U for more fine grained control");
		ret = CMD_ERROR;
		goto error;
	}

error:
	return ret;
}

/*
 * Parse URI from string to lttng_uri object array.
 */
static ssize_t parse_uri_from_str(const char *str_uri, struct lttng_uri **uris)
{
	ssize_t size;

	if (*uris != NULL) {
		free(*uris);
	}

	size = uri_parse(str_uri, uris);
	if (size < 1) {
		ERR("Bad URI %s. Either the hostname or IP is invalid", str_uri);
		size = -1;
	}

	return size;
}

/*
 * Enable consumer command.
 */
static int enable_consumer(char *session_name)
{
	int ret = CMD_SUCCESS;
	int run_enable_cmd = 1;
	ssize_t size;
	struct lttng_domain dom;
	struct lttng_uri *uri = NULL;

	memset(&dom, 0, sizeof(dom));

	/* Create lttng domain */
	if (opt_kernel) {
		dom.type = LTTNG_DOMAIN_KERNEL;
	} else if (opt_userspace) {
		dom.type = LTTNG_DOMAIN_UST;
	} else {
		ERR("Please specify a tracer (-k/--kernel or -u/--userspace)");
		ret = CMD_ERROR;
		goto error;
	}

	handle = lttng_create_handle(session_name, &dom);
	if (handle == NULL) {
		ret = -1;
		goto error;
	}

	/* Handle trailing arguments */
	if (opt_uris_arg) {
		size = parse_uri_from_str(opt_uris_arg, &uri);
		if (size < 1) {
			ret = CMD_ERROR;
			goto error;
		}

		ret = set_consumer_arg_uris(uri, size);
		if (ret < 0) {
			goto free_uri;
		}
	}

	/* Handling URIs (-U opt) */
	if (opt_uris) {
		size = parse_uri_from_str(opt_uris, &uri);
		if (size < 1) {
			ret = CMD_ERROR;
			goto error;
		}

		ret = set_consumer_arg_uris(uri, size);
		if (ret < 0) {
			goto free_uri;
		}

		/* opt_enable will tell us to run or not the enable_consumer cmd. */
		run_enable_cmd = 0;
	}

	/* Setting up control URI (-C opt) */
	if (opt_ctrl_uris) {
		size = parse_uri_from_str(opt_ctrl_uris, &uri);
		if (size < 1) {
			ret = CMD_ERROR;
			goto error;
		}

		/* Set default port if none specified */
		if (uri[0].port == 0) {
			uri[0].port = DEFAULT_NETWORK_CONTROL_PORT;
		}

		uri[0].stype = LTTNG_STREAM_CONTROL;

		ret = lttng_set_consumer_uri(handle, &uri[0]);
		if (ret < 0) {
			ERR("Failed to set control URI %s: %s", opt_ctrl_uris,
					lttng_strerror(ret));
			goto free_uri;
		}
		print_uri_msg(&uri[0]);

		/* opt_enable will tell us to run or not the enable_consumer cmd. */
		run_enable_cmd = 0;
	}

	/* Setting up data URI (-D opt) */
	if (opt_data_uris) {
		size = parse_uri_from_str(opt_data_uris, &uri);
		if (size < 1) {
			ret = CMD_ERROR;
			goto error;
		}

		/* Set default port if none specified */
		if (uri[0].port == 0) {
			uri[0].port = DEFAULT_NETWORK_DATA_PORT;
		}

		uri[0].stype = LTTNG_STREAM_DATA;

		ret = lttng_set_consumer_uri(handle, &uri[0]);
		if (ret < 0) {
			ERR("Failed to set data URI %s: %s", opt_data_uris,
					lttng_strerror(ret));
			goto free_uri;
		}
		print_uri_msg(&uri[0]);

		/* opt_enable will tell us to run or not the enable_consumer cmd. */
		run_enable_cmd = 0;
	}

	/* Enable consumer (-e opt) */
	if (opt_enable || run_enable_cmd) {
		ret = lttng_enable_consumer(handle);
		if (ret < 0) {
			ERR("Enabling consumer for session %s: %s", session_name,
					lttng_strerror(ret));
			if (ret == -LTTCOMM_ENABLE_CONSUMER_FAIL) {
				ERR("Perhaps the session was previously started?");
			}
			goto free_uri;
		}

		MSG("Consumer enabled successfully");
	}

free_uri:
	free(uri);

error:
	lttng_destroy_handle(handle);
	return ret;
}

/*
 * The 'enable-consumer <options>' first level command
 *
 * Returns one of the CMD_* result constants.
 */
int cmd_enable_consumer(int argc, const char **argv)
{
	int opt, ret = CMD_SUCCESS;
	static poptContext pc;
	char *session_name = NULL;

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

	opt_uris_arg = (char *) poptGetArg(pc);
	DBG("URIs: %s", opt_uris_arg);

	/* Get session name */
	if (!opt_session_name) {
		session_name = get_session_name();
		if (session_name == NULL) {
			ret = CMD_ERROR;
			goto end;
		}
	} else {
		session_name = opt_session_name;
	}

	ret = enable_consumer(session_name);

end:
	if (opt_session_name == NULL) {
		free(session_name);
	}

	poptFreeContext(pc);
	return ret;
}
