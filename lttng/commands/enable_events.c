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

#include "../cmd.h"
#include "../conf.h"
#include "../utils.h"

static char *opt_event_list;
static int opt_event_type;
static char *opt_kernel;
static char *opt_cmd_name;
static char *opt_session_name;
static int opt_pid_all;
static int opt_userspace;
static int opt_enable_all;
static pid_t opt_pid;
static char *opt_kprobe;
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
	{"session",        's', POPT_ARG_STRING, &opt_session_name, 0, 0, 0},
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
	fprintf(ofp, "  -s, --session            Apply on session name\n");
	fprintf(ofp, "  -c, --channel            Apply on this channel\n");
	fprintf(ofp, "  -a, --all-events         Enable all tracepoints\n");
	fprintf(ofp, "  -k, --kernel             Apply for the kernel tracer\n");
	fprintf(ofp, "  -u, --userspace [CMD]    Apply for the user-space tracer\n");
	fprintf(ofp, "      --all                If -u, apply on all traceable apps\n");
	fprintf(ofp, "  -p, --pid PID            If -u, apply on a specific PID\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Event options:\n");
	fprintf(ofp, "    --tracepoint           Tracepoint event (default)\n");
	fprintf(ofp, "    --kprobe [addr | symbol+offset]\n");
	fprintf(ofp, "                           Kernel Kprobe. (addr or offset can be base 8,10 and 16)\n");
	fprintf(ofp, "    --function SYMBOL      Function tracer event\n");
	fprintf(ofp, "    --marker               User-space marker (deprecated)\n");
	fprintf(ofp, "\n");
}

/*
 *  parse_kprobe_addr
 *
 *  Parse kprobe options.
 */
static int parse_kprobe_opts(struct lttng_event *ev, char *opt)
{
	int ret;
	uint64_t hex;
	char name[LTTNG_SYMBOL_NAME_LEN];

	if (opt == NULL) {
		ret = -1;
		goto error;
	}

	/* Check for symbol+offset */
	ret = sscanf(opt, "%[^'+']+%li", name, &hex);
	if (ret == 2) {
		strncpy(ev->attr.probe.symbol_name, name, LTTNG_SYMBOL_NAME_LEN);
		DBG("kprobe symbol %s", ev->attr.probe.symbol_name);
		if (hex == 0) {
			ERR("Invalid kprobe offset %lu", hex);
			ret = -1;
			goto error;
		}
		ev->attr.probe.offset = hex;
		DBG("kprobe offset %lu", ev->attr.probe.offset);
		goto error;
	}

	/* Check for address */
	ret = sscanf(opt, "%li", &hex);
	if (ret > 0) {
		if (hex == 0) {
			ERR("Invalid kprobe address %lu", hex);
			ret = -1;
			goto error;
		}
		ev->attr.probe.addr = hex;
		DBG("kprobe addr %lu", ev->attr.probe.addr);
		goto error;
	}

	/* No match */
	ret = -1;

error:
	return ret;
}

/*
 *  enable_events
 *
 *  Enabling event using the lttng API.
 */
static int enable_events(void)
{
	int err, ret = CMD_SUCCESS;
	char *event_name, *channel_name = NULL;
	struct lttng_event ev;
	struct lttng_domain dom;

	if (set_session_name(opt_session_name) < 0) {
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

	/* Create lttng domain */
	if (opt_kernel) {
		dom.type = LTTNG_DOMAIN_KERNEL;
	}

	if (opt_enable_all) {
		if (opt_kernel) {
			ret = lttng_enable_event(&dom, NULL, channel_name);
			if (ret == 0) {
				MSG("All kernel events are enabled in channel %s", channel_name);
			}
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
			case LTTNG_EVENT_TRACEPOINT:
				break;
			case LTTNG_EVENT_PROBE:
				ret = parse_kprobe_opts(&ev, opt_kprobe);
				if (ret < 0) {
					ERR("Unable to parse kprobe options");
					ret = 0;
					goto error;
				}
				break;
			case LTTNG_EVENT_FUNCTION:
				strncpy(ev.attr.ftrace.symbol_name, opt_function_symbol, LTTNG_SYMBOL_NAME_LEN);
				break;
			default:
				ret = CMD_NOT_IMPLEMENTED;
				goto error;
			}

			ret = lttng_enable_event(&dom, &ev, channel_name);
			if (ret == 0) {
				MSG("Kernel event %s created in channel %s", event_name, channel_name);
			} else if (ret < 0) {
				ERR("Unable to find event %s", ev.name);
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
	if (opt_channel_name == NULL) {
		free(channel_name);
	}
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
	opt_event_type = LTTNG_EVENT_TRACEPOINT;

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
			opt_event_type = LTTNG_EVENT_TRACEPOINT;
			break;
		case OPT_MARKER:
			ret = CMD_NOT_IMPLEMENTED;
			goto end;
		case OPT_KPROBE:
			opt_event_type = LTTNG_EVENT_PROBE;
			opt_kprobe = poptGetOptArg(pc);
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
