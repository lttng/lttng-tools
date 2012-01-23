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
#include <unistd.h>

#include "../command.h"

static char *opt_channels;
static int opt_kernel;
static char *opt_session_name;
static int opt_userspace;
#if 0
/* Not implemented yet */
static char *opt_cmd_name;
static pid_t opt_pid;
#endif

enum {
	OPT_HELP = 1,
	OPT_USERSPACE,
};

static struct lttng_handle *handle;

static struct poptOption long_options[] = {
	/* longName, shortName, argInfo, argPtr, value, descrip, argDesc */
	{"help",           'h', POPT_ARG_NONE, 0, OPT_HELP, 0, 0},
	{"session",        's', POPT_ARG_STRING, &opt_session_name, 0, 0, 0},
	{"kernel",         'k', POPT_ARG_VAL, &opt_kernel, 1, 0, 0},
#if 0
	/* Not implemented yet */
	{"userspace",      'u', POPT_ARG_STRING | POPT_ARGFLAG_OPTIONAL, &opt_cmd_name, OPT_USERSPACE, 0, 0},
	{"pid",            'p', POPT_ARG_INT, &opt_pid, 0, 0, 0},
#else
	{"userspace",      'u', POPT_ARG_NONE, 0, OPT_USERSPACE, 0, 0},
#endif
	{0, 0, 0, 0, 0, 0, 0}
};

/*
 * usage
 */
static void usage(FILE *ofp)
{
	fprintf(ofp, "usage: lttng disable-channel NAME[,NAME2,...] [options]\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "  -h, --help               Show this help\n");
	fprintf(ofp, "  -s, --session            Apply on session name\n");
	fprintf(ofp, "  -k, --kernel             Apply for the kernel tracer\n");
#if 0
	fprintf(ofp, "  -u, --userspace [CMD]    Apply for the user-space tracer\n");
	fprintf(ofp, "                           If no CMD, the domain used is UST global\n");
	fprintf(ofp, "                           or else the domain is UST EXEC_NAME\n");
	fprintf(ofp, "  -p, --pid PID            If -u, apply to specific PID (domain: UST PID)\n");
#else
	fprintf(ofp, "  -u, --userspace          Apply for the user-space tracer\n");
#endif
	fprintf(ofp, "\n");
}

/*
 * Disabling channel using the lttng API.
 */
static int disable_channels(char *session_name)
{
	int ret = CMD_SUCCESS;
	char *channel_name;
	struct lttng_domain dom;

	/* Create lttng domain */
	if (opt_kernel) {
		dom.type = LTTNG_DOMAIN_KERNEL;
	} else if (opt_userspace) {
		dom.type = LTTNG_DOMAIN_UST;
	} else {
		ERR("Please specify a tracer (-k/--kernel or -u/--userspace)");
		ret = CMD_UNDEFINED;
		goto error;
	}

	handle = lttng_create_handle(session_name, &dom);
	if (handle == NULL) {
		ret = -1;
		goto error;
	}

	/* Strip channel list */
	channel_name = strtok(opt_channels, ",");
	while (channel_name != NULL) {
		DBG("Disabling channel %s", channel_name);

		ret = lttng_disable_channel(handle, channel_name);
		if (ret < 0) {
			goto error;
		} else {
			MSG("%s channel %s disabled for session %s",
					opt_kernel ? "Kernel" : "UST", channel_name,
					session_name);
		}

		/* Next channel */
		channel_name = strtok(NULL, ",");
	}

error:
	lttng_destroy_handle(handle);

	return ret;
}

/*
 *  cmd_disable_channels
 *
 *  Disable channel to trace session
 */
int cmd_disable_channels(int argc, const char **argv)
{
	int opt, ret;
	static poptContext pc;
	char *session_name = NULL;

	pc = poptGetContext(NULL, argc, argv, long_options, 0);
	poptReadDefaultConfig(pc, 0);

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case OPT_HELP:
			usage(stderr);
			ret = CMD_SUCCESS;
			goto end;
		case OPT_USERSPACE:
			opt_userspace = 1;
			break;
		default:
			usage(stderr);
			ret = CMD_UNDEFINED;
			goto end;
		}
	}

	opt_channels = (char*) poptGetArg(pc);
	if (opt_channels == NULL) {
		ERR("Missing channel name(s).\n");
		usage(stderr);
		ret = CMD_SUCCESS;
		goto end;
	}

	if (!opt_session_name) {
		session_name = get_session_name();
		if (session_name == NULL) {
			ret = -1;
			goto end;
		}
	} else {
		session_name = opt_session_name;
	}

	ret = disable_channels(session_name);

end:
	return ret;
}
