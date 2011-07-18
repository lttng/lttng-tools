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

#include "cmd.h"
#include "conf.h"
#include "utils.h"

static char *opt_channels;
static char *opt_kernel;
static char *opt_session_name;
static int opt_pid_all;
static int opt_userspace;
static pid_t opt_pid;

enum {
	OPT_HELP = 1,
	OPT_USERSPACE,
};

static struct poptOption long_options[] = {
	/* longName, shortName, argInfo, argPtr, value, descrip, argDesc */
	{"help",           'h', POPT_ARG_NONE, 0, OPT_HELP, 0, 0},
	{"session",        's', POPT_ARG_STRING, &opt_session_name, 0, 0, 0},
	{"kernel",         'k', POPT_ARG_VAL, &opt_kernel, 1, 0, 0},
	{"userspace",      'u', POPT_ARG_NONE, 0, OPT_USERSPACE, 0, 0},
	{"all",            0,   POPT_ARG_VAL, &opt_pid_all, 1, 0, 0},
	{"pid",            'p', POPT_ARG_INT, &opt_pid, 0, 0, 0},
	{0, 0, 0, 0, 0, 0, 0}
};

/*
 * usage
 */
static void usage(FILE *ofp)
{
	fprintf(ofp, "usage: lttng disable-channel NAME[,NAME2,...] [options]\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "  -h, --help            Show this help\n");
	fprintf(ofp, "  -s, --session            Apply on session name\n");
	fprintf(ofp, "  -k, --kernel          Apply for the kernel tracer\n");
	fprintf(ofp, "  -u, --userspace       Apply for the user-space tracer\n");
	fprintf(ofp, "      --all             If -u, apply on all traceable apps\n");
	fprintf(ofp, "  -p, --pid PID         If -u, apply on a specific PID\n");
	fprintf(ofp, "\n");
}

/*
 *  disable_channels
 *
 *  Disabling channel using the lttng API.
 */
static int disable_channels(void)
{
	int ret = CMD_SUCCESS;
	char *channel_name;
	struct lttng_domain dom;

	if (set_session_name(opt_session_name) < 0) {
		ret = CMD_ERROR;
		goto error;
	}

	if (opt_kernel) {
		dom.type = LTTNG_DOMAIN_KERNEL;
	}

	/* Strip channel list */
	channel_name = strtok(opt_channels, ",");
	while (channel_name != NULL) {
		/* Kernel tracer action */
		if (opt_kernel) {
			DBG("Disabling kernel channel %s", channel_name);
			ret = lttng_disable_channel(&dom, channel_name);
			if (ret < 0) {
				goto error;
			} else {
				MSG("Kernel channel disabled %s", channel_name);
			}
		} else if (opt_userspace) {		/* User-space tracer action */
			/*
			 * TODO: Waiting on lttng UST 2.0
			 */
			if (opt_pid_all) {
			} else if (opt_pid != 0) {
			}
			ret = CMD_NOT_IMPLEMENTED;
			goto error;
		} else {
			ERR("Please specify a tracer (kernel or user-space)");
			goto error;
		}

		/* Next channel */
		channel_name = strtok(NULL, ",");
	}

error:
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

	ret = disable_channels();

end:
	return ret;
}
