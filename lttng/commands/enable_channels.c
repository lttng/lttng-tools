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
static char *opt_cmd_name;
static char *opt_session_name;
static int opt_pid_all;
static int opt_userspace;
static pid_t opt_pid;
static struct lttng_channel chan;

enum {
	OPT_HELP = 1,
	OPT_DISCARD,
	OPT_OVERWRITE,
	OPT_SUBBUF_SIZE,
	OPT_NUM_SUBBUF,
	OPT_SWITCH_TIMER,
	OPT_READ_TIMER,
	OPT_USERSPACE,
};

static struct poptOption long_options[] = {
	/* longName, shortName, argInfo, argPtr, value, descrip, argDesc */
	{"help",           'h', POPT_ARG_NONE, 0, OPT_HELP, 0, 0},
	{"session",        's', POPT_ARG_STRING, &opt_session_name, 0, 0, 0},
	{"kernel",         'k', POPT_ARG_VAL, &opt_kernel, 1, 0, 0},
	{"userspace",      'u', POPT_ARG_STRING | POPT_ARGFLAG_OPTIONAL, 0, OPT_USERSPACE, 0, 0},
	{"all",            0,   POPT_ARG_VAL, &opt_pid_all, 1, 0, 0},
	{"pid",            'p', POPT_ARG_INT, &opt_pid, 0, 0, 0},
	{"discard",        0,   POPT_ARG_NONE, 0, OPT_DISCARD, 0, 0},
	{"overwrite",      0,   POPT_ARG_NONE, 0, OPT_OVERWRITE, 0, 0},
	{"subbuf_size",    0,   POPT_ARG_DOUBLE, 0, OPT_SUBBUF_SIZE, 0, 0},
	{"num_subbuf",     0,   POPT_ARG_INT, 0, OPT_NUM_SUBBUF, 0, 0},
	{"switch_timer",   0,   POPT_ARG_INT, 0, OPT_SWITCH_TIMER, 0, 0},
	{"read_timer",     0,   POPT_ARG_INT, 0, OPT_READ_TIMER, 0, 0},
	{0, 0, 0, 0, 0, 0, 0}
};

/*
 * usage
 */
static void usage(FILE *ofp)
{
	fprintf(ofp, "usage: lttng enable-channel NAME[,NAME2,...] [options] [channel_options]\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "  -h, --help               Show this help\n");
	fprintf(ofp, "  -s, --session            Apply on session name\n");
	fprintf(ofp, "  -k, --kernel             Apply on the kernel tracer\n");
	fprintf(ofp, "  -u, --userspace [CMD]    Apply on the user-space tracer\n");
	fprintf(ofp, "      --all                If -u, apply on all traceable apps\n");
	fprintf(ofp, "  -p, --pid PID            If -u, apply on a specific PID\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Channel options:\n");
	fprintf(ofp, "      --discard            Discard event when buffers are full (default)\n");
	fprintf(ofp, "      --overwrite          Flight recorder mode\n");
	fprintf(ofp, "      --subbuf_size        Subbuffer size in bytes (default: 4096)\n");
	fprintf(ofp, "      --num_subbuf         Number of subbufers (default: 2)\n");
	fprintf(ofp, "      --switch_timer       Switch timer interval in usec (default: 0)\n");
	fprintf(ofp, "      --read_timer         Read timer interval in usec (default: 200)\n");
	fprintf(ofp, "\n");
}

/*
 *  enable_channel
 *
 *  Adding channel using the lttng API.
 */
static int enable_channel(void)
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

	/* Strip event list */
	channel_name = strtok(opt_channels, ",");
	while (channel_name != NULL) {
		/* Kernel tracer action */
		if (opt_kernel) {
			DBG("Enabling kernel channel %s", channel_name);

			/* Copy channel name and normalize it */
			strncpy(chan.name, channel_name, NAME_MAX);
			chan.name[NAME_MAX - 1] = '\0';

			ret = lttng_enable_channel(&dom, &chan);
			if (ret < 0) {
				goto error;
			} else {
				MSG("Kernel channel enabled %s", channel_name);
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

		/* Next event */
		channel_name = strtok(NULL, ",");
	}

error:
	return ret;
}

/*
 *  init_channel_config
 *
 *  Default value for channel configuration.
 */
static void init_channel_config(void)
{
	chan.attr.overwrite = DEFAULT_CHANNEL_OVERWRITE;
	chan.attr.subbuf_size = DEFAULT_CHANNEL_SUBBUF_SIZE;
	chan.attr.num_subbuf = DEFAULT_CHANNEL_SUBBUF_NUM;
	chan.attr.switch_timer_interval = DEFAULT_CHANNEL_SWITCH_TIMER;
	chan.attr.read_timer_interval = DEFAULT_CHANNEL_READ_TIMER;
	chan.attr.output = DEFAULT_KERNEL_CHANNEL_OUTPUT;
}

/*
 *  Add channel to trace session
 */
int cmd_enable_channels(int argc, const char **argv)
{
	int opt, ret;
	static poptContext pc;

	init_channel_config();

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
			opt_cmd_name = poptGetOptArg(pc);
			break;
		case OPT_DISCARD:
			chan.attr.overwrite = 0;
			DBG("Channel set to discard");
			break;
		case OPT_OVERWRITE:
			chan.attr.overwrite = 1;
			DBG("Channel set to overwrite");
			break;
		case OPT_SUBBUF_SIZE:
			chan.attr.subbuf_size = atol(poptGetOptArg(pc));
			DBG("Channel subbuf size set to %lu", chan.attr.subbuf_size);
			break;
		case OPT_NUM_SUBBUF:
			chan.attr.num_subbuf = atoi(poptGetOptArg(pc));
			DBG("Channel subbuf num set to %lu", chan.attr.num_subbuf);
			break;
		case OPT_SWITCH_TIMER:
			chan.attr.switch_timer_interval = atoi(poptGetOptArg(pc));
			DBG("Channel switch timer interval set to %d", chan.attr.switch_timer_interval);
			break;
		case OPT_READ_TIMER:
			chan.attr.read_timer_interval = atoi(poptGetOptArg(pc));
			DBG("Channel read timer interval set to %d", chan.attr.read_timer_interval);
			break;
		default:
			usage(stderr);
			ret = CMD_UNDEFINED;
			goto end;
		}
	}

	opt_channels = (char*) poptGetArg(pc);
	if (opt_channels == NULL) {
		ERR("Missing channel name.\n");
		usage(stderr);
		ret = CMD_SUCCESS;
		goto end;
	}

	ret = enable_channel();

end:
	return ret;
}
