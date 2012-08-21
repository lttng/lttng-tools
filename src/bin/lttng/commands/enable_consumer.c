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
static char *opt_url;
static char *opt_ctrl_url;
static char *opt_data_url;
static char *opt_url_arg;

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
	{"set-uri",        'U', POPT_ARG_STRING, &opt_url, 0, 0, 0},
	{"ctrl-uri",       'C', POPT_ARG_STRING, &opt_ctrl_url, 0, 0, 0},
	{"data-uri",       'D', POPT_ARG_STRING, &opt_data_url, 0, 0, 0},
	{"enable",         'e', POPT_ARG_VAL, &opt_enable, 1, 0, 0},
	{0, 0, 0, 0, 0, 0, 0}
};

/*
 * usage
 */
static void usage(FILE *ofp)
{
	fprintf(ofp, "usage: lttng enable-consumer [-u|-k] [URL] [OPTIONS]\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "The default behavior is to enable a consumer to the current URL.\n");
	fprintf(ofp, "The default URL is the local filesystem at the path of the session.\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "The enable-consumer feature supports both local and network transport.\n");
	fprintf(ofp, "You must have a running lttng-relayd for network transmission.\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Options:\n");
	fprintf(ofp, "  -h, --help           Show this help\n");
	fprintf(ofp, "      --list-options   Simple listing of options\n");
	fprintf(ofp, "  -s, --session NAME   Apply to session name\n");
	fprintf(ofp, "  -k, --kernel         Apply to the kernel tracer\n");
	fprintf(ofp, "  -u, --userspace      Apply to the user-space tracer\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Extended Options:\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Using these options, each API call can be controlled individually.\n");
	fprintf(ofp, "For instance, -C does not enable the consumer automatically.\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "  -U, --set-uri=URL    Set URL for the enable-consumer destination.\n");
	fprintf(ofp, "                       It is persistent for the session lifetime.\n");
	fprintf(ofp, "                       Redo the command to change it.\n");
	fprintf(ofp, "                       This will set both data and control URL for network.\n");
	fprintf(ofp, "  -C, --ctrl-url=URL   Set control path URL. (Must use -D also)\n");
	fprintf(ofp, "  -D, --data-url=URL   Set data path URL. (Must use -C also)\n");
	fprintf(ofp, "  -e, --enable         Enable consumer\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Please refer to the man page (lttng(1)) for more information on network\n");
	fprintf(ofp, "streaming mechanisms and explanation of the control and data port\n");
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
	fprintf(ofp, "  > tcp[4|6]://...\n");
	fprintf(ofp, "    Can only be used with -C and -D together\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "NOTE: IPv6 address MUST be enclosed in brackets '[]' (rfc2732)\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Examples:\n");
	fprintf(ofp, "    # lttng enable-consumer -u net://192.168.1.42\n");
	fprintf(ofp, "    Uses TCP and default ports for user space tracing (-u).\n");
	fprintf(ofp, "\n");
}

/*
 * Enable consumer command.
 */
static int enable_consumer(char *session_name)
{
	int ret = CMD_SUCCESS;
	int run_enable_cmd = 1;
	struct lttng_domain dom;

	memset(&dom, 0, sizeof(dom));

	/* Create lttng domain */
	if (opt_kernel) {
		dom.type = LTTNG_DOMAIN_KERNEL;
	} else if (opt_userspace) {
		dom.type = LTTNG_DOMAIN_UST;
	} else {
		/*
		 * Set handle with domain set to 0. This means to the session daemon
		 * that the next action applies on the tracing session rather then the
		 * domain specific session.
		 *
		 * XXX: This '0' value should be a domain enum value.
		 */
		dom.type = 0;
	}

	handle = lttng_create_handle(session_name, &dom);
	if (handle == NULL) {
		ret = -1;
		goto error;
	}

	/* Handle trailing arguments */
	if (opt_url_arg) {
		ret = lttng_set_consumer_url(handle, opt_url_arg, NULL);
		if (ret < 0) {
			ERR("%s", lttng_strerror(ret));
			goto error;
		}

		MSG("URL %s set for session %s.", opt_url_arg, session_name);
	}

	/* Handling URLs (-U opt) */
	if (opt_url) {
		ret = lttng_set_consumer_url(handle, opt_url, NULL);
		if (ret < 0) {
			ERR("%s", lttng_strerror(ret));
			goto error;
		}

		/* opt_enable will tell us to run or not the enable_consumer cmd. */
		run_enable_cmd = 0;

		MSG("URL %s set for session %s.", opt_url, session_name);
	}

	/* Setting up control URL (-C or/and -D opt) */
	if (opt_ctrl_url || opt_data_url) {
		ret = lttng_set_consumer_url(handle, opt_ctrl_url, opt_data_url);
		if (ret < 0) {
			ERR("%s", lttng_strerror(ret));
			goto error;
		}

		/* opt_enable will tell us to run or not the enable_consumer cmd. */
		run_enable_cmd = 0;

		if (opt_ctrl_url) {
			MSG("Control URL %s set for session %s.", opt_ctrl_url,
					session_name);
		}

		if (opt_data_url) {
			MSG("Data URL %s set for session %s.", opt_data_url, session_name);
		}
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
			goto error;
		}

		MSG("Consumer enabled successfully");
	}

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

	opt_url_arg = (char *) poptGetArg(pc);
	DBG("URLs: %s", opt_url_arg);

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
