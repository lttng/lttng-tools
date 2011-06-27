/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
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

static char *opt_event_list;
static int opt_event_type;
static char *opt_kernel;
static char *opt_cmd_name;
static int opt_pid_all;
static int opt_userspace;
static int opt_enable_all;
static pid_t opt_pid;
static char *opt_kprobe_addr;
static char *opt_function_symbol;
static char *opt_channel_name;

enum {
	OPT_HELP = 1,
	OPT_USERSPACE,
	OPT_TRACEPOINT,
	OPT_MARKER,
	OPT_KPROBE,
	OPT_FUNCTION,
};

static struct poptOption long_options[] = {
	/* longName, shortName, argInfo, argPtr, value, descrip, argDesc */
	{"help",           'h', POPT_ARG_NONE, 0, OPT_HELP, 0, 0},
	{"all-events",     'a', POPT_ARG_VAL, &opt_enable_all, 1, 0, 0},
	{"channel",        'c', POPT_ARG_STRING, &opt_channel_name, 0, 0, 0},
	{"kernel",         'k', POPT_ARG_VAL, &opt_kernel, 1, 0, 0},
	{"userspace",      'u', POPT_ARG_STRING | POPT_ARGFLAG_OPTIONAL, 0, OPT_USERSPACE, 0, 0},
	{"all",            0,   POPT_ARG_VAL, &opt_pid_all, 1, 0, 0},
	{"pid",            'p', POPT_ARG_INT, &opt_pid, 0, 0, 0},
	{"tracepoint",     0,   POPT_ARG_NONE, 0, OPT_TRACEPOINT, 0, 0},
	{"marker",         0,   POPT_ARG_NONE, 0, OPT_MARKER, 0, 0},
	{"kprobe",         0,   POPT_ARG_STRING, 0, OPT_KPROBE, 0, 0},
	{"function",       0,   POPT_ARG_STRING, 0, OPT_FUNCTION, 0, 0},
	{0, 0, 0, 0, 0, 0, 0}
};

/*
 * usage
 */
static void usage(FILE *ofp)
{
	fprintf(ofp, "usage: lttng enable-event NAME[,NAME2,...] [options] [event_options]\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "  -h, --help               Show this help\n");
	fprintf(ofp, "  -c, --channel            Apply on this channel\n");
	fprintf(ofp, "  -a, --all-events         Enable all tracepoints\n");
	fprintf(ofp, "  -k, --kernel             Apply for the kernel tracer\n");
	fprintf(ofp, "  -u, --userspace [CMD]    Apply for the user-space tracer\n");
	fprintf(ofp, "      --all                If -u, apply on all traceable apps\n");
	fprintf(ofp, "  -p, --pid PID            If -u, apply on a specific PID\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Event options:\n");
	fprintf(ofp, "    --tracepoint           Tracepoint event (default)\n");
	fprintf(ofp, "    --kprobe ADDR          Kernel Kprobe\n");
	fprintf(ofp, "    --function SYMBOL      Function tracer event\n");
	fprintf(ofp, "    --marker               User-space marker (deprecated)\n");
	fprintf(ofp, "\n");
}

/*
 *  enable_events
 *
 *  Enabling event using the lttng API.
 */
static int enable_events(void)
{
	int err, ret = CMD_SUCCESS;
	char *event_name, *channel_name;
	struct lttng_event ev;

	if (set_session_name() < 0) {
		ret = CMD_ERROR;
		goto error;
	}

	if (opt_channel_name == NULL) {
		err = asprintf(&channel_name, DEFAULT_CHANNEL_NAME);
		if (err < 0) {
			ret = CMD_FATAL;
			goto error;
		}
	} else {
		channel_name = opt_channel_name;
	}

	if (opt_enable_all) {
		if (opt_kernel) {
			ret = lttng_kernel_enable_event(NULL, channel_name);
			goto error;
		}

		/* TODO: User-space tracer */
	}

	/* Strip event list */
	event_name = strtok(opt_event_list, ",");
	while (event_name != NULL) {
		/* Kernel tracer action */
		if (opt_kernel) {
			DBG("Enabling kernel event %s for channel %s",
					event_name, channel_name);
			/* Copy name and type of the event */
			strncpy(ev.name, event_name, LTTNG_SYMBOL_NAME_LEN);
			ev.type = opt_event_type;

			switch (opt_event_type) {
			case LTTNG_EVENT_TRACEPOINTS:
				ret = lttng_kernel_enable_event(&ev, channel_name);
				break;
			case LTTNG_EVENT_KPROBES:
				/* FIXME: check addr format */
				ev.attr.kprobe.addr = atoll(opt_kprobe_addr);
				ret = lttng_kernel_enable_event(&ev, channel_name);
				break;
			case LTTNG_EVENT_FUNCTION:
				strncpy(ev.attr.ftrace.symbol_name, opt_function_symbol, LTTNG_SYMBOL_NAME_LEN);
				ret = lttng_kernel_enable_event(&ev, channel_name);
				break;
			default:
				ret = CMD_NOT_IMPLEMENTED;
				goto error;
			}

			if (ret > 0) {
				MSG("Kernel event %s created in channel %s", event_name, channel_name);
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
		event_name = strtok(NULL, ",");
	}

error:
	return ret;
}

/*
 *  cmd_enable_events
 *
 *  Add event to trace session
 */
int cmd_enable_events(int argc, const char **argv)
{
	int opt, ret;
	static poptContext pc;

	pc = poptGetContext(NULL, argc, argv, long_options, 0);
	poptReadDefaultConfig(pc, 0);

	/* Default event type */
	opt_event_type = LTTNG_KERNEL_TRACEPOINTS;

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
		case OPT_TRACEPOINT:
			opt_event_type = LTTNG_EVENT_TRACEPOINTS;
			break;
		case OPT_MARKER:
			ret = CMD_NOT_IMPLEMENTED;
			goto end;
		case OPT_KPROBE:
			opt_event_type = LTTNG_EVENT_KPROBES;
			opt_kprobe_addr = poptGetOptArg(pc);
			break;
		case OPT_FUNCTION:
			opt_event_type = LTTNG_EVENT_FUNCTION;
			opt_function_symbol = poptGetOptArg(pc);
			break;
		default:
			usage(stderr);
			ret = CMD_UNDEFINED;
			goto end;
		}
	}

	opt_event_list = (char*) poptGetArg(pc);
	if (opt_event_list == NULL && opt_enable_all == 0) {
		ERR("Missing event name(s).\n");
		usage(stderr);
		ret = CMD_SUCCESS;
		goto end;
	}

	ret = enable_events();

end:
	return ret;
}
