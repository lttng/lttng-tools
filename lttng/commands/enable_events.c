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
#include <inttypes.h>
#include <ctype.h>

#include "../cmd.h"
#include "../conf.h"
#include "../utils.h"

static char *opt_event_list;
static int opt_event_type;
static int opt_kernel;
static char *opt_session_name;
static int opt_pid_all;
static int opt_userspace;
static char *opt_cmd_name;
static int opt_enable_all;
static pid_t opt_pid;
static char *opt_probe;
static char *opt_function;
static char *opt_function_entry_symbol;
static char *opt_channel_name;

enum {
	OPT_HELP = 1,
	OPT_TRACEPOINT,
	OPT_PROBE,
	OPT_FUNCTION,
	OPT_FUNCTION_ENTRY,
	OPT_SYSCALL,
	OPT_USERSPACE,
	OPT_TRACEPOINT_LOGLEVEL,
};

static struct lttng_handle *handle;

static struct poptOption long_options[] = {
	/* longName, shortName, argInfo, argPtr, value, descrip, argDesc */
	{"help",           'h', POPT_ARG_NONE, 0, OPT_HELP, 0, 0},
	{"session",        's', POPT_ARG_STRING, &opt_session_name, 0, 0, 0},
	{"all-events",     'a', POPT_ARG_VAL, &opt_enable_all, 1, 0, 0},
	{"channel",        'c', POPT_ARG_STRING, &opt_channel_name, 0, 0, 0},
	{"kernel",         'k', POPT_ARG_VAL, &opt_kernel, 1, 0, 0},
	{"userspace",      'u', POPT_ARG_STRING | POPT_ARGFLAG_OPTIONAL, &opt_cmd_name, OPT_USERSPACE, 0, 0},
	{"all",            0,   POPT_ARG_VAL, &opt_pid_all, 1, 0, 0},
	{"pid",            'p', POPT_ARG_INT, &opt_pid, 0, 0, 0},
	{"tracepoint",     0,   POPT_ARG_NONE, 0, OPT_TRACEPOINT, 0, 0},
	{"probe",          0,   POPT_ARG_STRING, &opt_probe, OPT_PROBE, 0, 0},
	{"function",       0,   POPT_ARG_STRING, &opt_function, OPT_FUNCTION, 0, 0},
#if 0
	/*
	 * Currently removed from lttng kernel tracer. Removed from
	 * lttng UI to discourage its use.
	 */
	{"function:entry", 0,   POPT_ARG_STRING, &opt_function_entry_symbol, OPT_FUNCTION_ENTRY, 0, 0},
#endif
	{"syscall",        0,   POPT_ARG_NONE, 0, OPT_SYSCALL, 0, 0},
	{"loglevel",     0,     POPT_ARG_NONE, 0, OPT_TRACEPOINT_LOGLEVEL, 0, 0},
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
	fprintf(ofp, "    --loglevel             Tracepoint loglevel\n");
	fprintf(ofp, "    --probe [addr | symbol | symbol+offset]\n");
	fprintf(ofp, "                           Dynamic probe.\n");
	fprintf(ofp, "                           Addr and offset can be octal (0NNN...),\n");
	fprintf(ofp, "                           decimal (NNN...) or hexadecimal (0xNNN...)\n");
	fprintf(ofp, "    --function [addr | symbol | symbol+offset]\n");
	fprintf(ofp, "                           Dynamic function entry/return probe.\n");
	fprintf(ofp, "                           Addr and offset can be octal (0NNN...),\n");
	fprintf(ofp, "                           decimal (NNN...) or hexadecimal (0xNNN...)\n");
#if 0
	fprintf(ofp, "    --function:entry symbol\n");
	fprintf(ofp, "                           Function tracer event\n");
#endif
	fprintf(ofp, "    --syscall              System call event\n");
	fprintf(ofp, "\n");
}

/*
 * Parse probe options.
 */
static int parse_probe_opts(struct lttng_event *ev, char *opt)
{
	int ret;
	char s_hex[19];
	char name[LTTNG_SYMBOL_NAME_LEN];

	if (opt == NULL) {
		ret = -1;
		goto end;
	}

	/* Check for symbol+offset */
	ret = sscanf(opt, "%[^'+']+%s", name, s_hex);
	if (ret == 2) {
		strncpy(ev->attr.probe.symbol_name, name, LTTNG_SYMBOL_NAME_LEN);
		ev->attr.probe.symbol_name[LTTNG_SYMBOL_NAME_LEN - 1] = '\0';
		DBG("probe symbol %s", ev->attr.probe.symbol_name);
		if (strlen(s_hex) == 0) {
			ERR("Invalid probe offset %s", s_hex);
			ret = -1;
			goto end;
		}
		ev->attr.probe.offset = strtoul(s_hex, NULL, 0);
		DBG("probe offset %" PRIu64, ev->attr.probe.offset);
		ev->attr.probe.addr = 0;
		goto end;
	}

	/* Check for symbol */
	if (isalpha(name[0])) {
		ret = sscanf(opt, "%s", name);
		if (ret == 1) {
			strncpy(ev->attr.probe.symbol_name, name, LTTNG_SYMBOL_NAME_LEN);
			ev->attr.probe.symbol_name[LTTNG_SYMBOL_NAME_LEN - 1] = '\0';
			DBG("probe symbol %s", ev->attr.probe.symbol_name);
			ev->attr.probe.offset = 0;
			DBG("probe offset %" PRIu64, ev->attr.probe.offset);
			ev->attr.probe.addr = 0;
			goto end;
		}
	}

	/* Check for address */
	ret = sscanf(opt, "%s", s_hex);
	if (ret > 0) {
		if (strlen(s_hex) == 0) {
			ERR("Invalid probe address %s", s_hex);
			ret = -1;
			goto end;
		}
		ev->attr.probe.addr = strtoul(s_hex, NULL, 0);
		DBG("probe addr %" PRIu64, ev->attr.probe.addr);
		ev->attr.probe.offset = 0;
		memset(ev->attr.probe.symbol_name, 0, LTTNG_SYMBOL_NAME_LEN);
		goto end;
	}

	/* No match */
	ret = -1;

end:
	return ret;
}

/*
 * Enabling event using the lttng API.
 */
static int enable_events(char *session_name)
{
	int err, ret = CMD_SUCCESS;
	char *event_name, *channel_name = NULL;
	struct lttng_event ev;
	struct lttng_domain dom;

	if (opt_channel_name == NULL) {
		err = asprintf(&channel_name, DEFAULT_CHANNEL_NAME);
		if (err < 0) {
			ret = CMD_FATAL;
			goto error;
		}
	} else {
		channel_name = opt_channel_name;
	}

	if (opt_kernel && opt_userspace) {
		MSG("Choose only one of --kernel or --userspace");
		ret = CMD_FATAL;
		goto error;
	}

	/* Create lttng domain */
	if (opt_kernel) {
		dom.type = LTTNG_DOMAIN_KERNEL;
	} else if (opt_pid != 0) {
		dom.type = LTTNG_DOMAIN_UST_PID;
		dom.attr.pid = opt_pid;
		DBG("PID %d set to lttng handle", opt_pid);
	} else if (opt_userspace && opt_cmd_name == NULL) {
		dom.type = LTTNG_DOMAIN_UST;
	} else if (opt_userspace && opt_cmd_name != NULL) {
		dom.type = LTTNG_DOMAIN_UST_EXEC_NAME;
		strncpy(dom.attr.exec_name, opt_cmd_name, NAME_MAX);
	} else {
		ERR("Please specify a tracer (--kernel or --userspace)");
		ret = CMD_NOT_IMPLEMENTED;
		goto error;
	}

	handle = lttng_create_handle(session_name, &dom);
	if (handle == NULL) {
		ret = -1;
		goto error;
	}

	if (opt_enable_all) {
		/* Default setup for enable all */
		ev.name[0] = '\0';
		ev.type = opt_event_type;

		ret = lttng_enable_event(handle, &ev, channel_name);
		if (ret < 0) {
			goto error;
		}

		switch (opt_event_type) {
		case LTTNG_EVENT_TRACEPOINT:
			MSG("All %s tracepoints are enabled in channel %s",
				opt_kernel ? "kernel" : "UST", channel_name);
			break;
		case LTTNG_EVENT_SYSCALL:
			if (opt_kernel) {
				MSG("All kernel system calls are enabled in channel %s",
						channel_name);
			}
			break;
		case LTTNG_EVENT_ALL:
			MSG("All %s events are enabled in channel %s",
				opt_kernel ? "kernel" : "UST", channel_name);
			break;
		default:
			/*
			 * We should not be here since lttng_enable_event should have
			 * failed on the event type.
			 */
			goto error;
		}
		goto end;
	}

	/* Strip event list */
	event_name = strtok(opt_event_list, ",");
	while (event_name != NULL) {
		/* Copy name and type of the event */
		strncpy(ev.name, event_name, LTTNG_SYMBOL_NAME_LEN);
		ev.name[LTTNG_SYMBOL_NAME_LEN - 1] = '\0';
		ev.type = opt_event_type;

		/* Kernel tracer action */
		if (opt_kernel) {
			DBG("Enabling kernel event %s for channel %s",
					event_name, channel_name);

			switch (opt_event_type) {
			case LTTNG_EVENT_ALL:	/* Default behavior is tracepoint */
				ev.type = LTTNG_EVENT_TRACEPOINT;
				/* Fall-through */
			case LTTNG_EVENT_TRACEPOINT:
				break;
			case LTTNG_EVENT_PROBE:
				ret = parse_probe_opts(&ev, opt_probe);
				if (ret < 0) {
					ERR("Unable to parse probe options");
					ret = 0;
					goto error;
				}
				break;
			case LTTNG_EVENT_FUNCTION:
				ret = parse_probe_opts(&ev, opt_function);
				if (ret < 0) {
					ERR("Unable to parse function probe options");
					ret = 0;
					goto error;
				}
				break;
			case LTTNG_EVENT_FUNCTION_ENTRY:
				strncpy(ev.attr.ftrace.symbol_name, opt_function_entry_symbol,
						LTTNG_SYMBOL_NAME_LEN);
				ev.attr.ftrace.symbol_name[LTTNG_SYMBOL_NAME_LEN - 1] = '\0';
				break;
			case LTTNG_EVENT_SYSCALL:
				MSG("per-syscall selection not supported yet. Use \"-a\" "
						"for all syscalls.");
			default:
				ret = CMD_NOT_IMPLEMENTED;
				goto error;
			}
		} else if (opt_userspace) {		/* User-space tracer action */
			if (!opt_pid_all) {
				MSG("Only supporting tracing all UST processes "
						"(-u --all) for now.");
				ret = CMD_NOT_IMPLEMENTED;
				goto error;
			}

			DBG("Enabling UST event %s for channel %s", event_name,
					channel_name);

			switch (opt_event_type) {
			case LTTNG_EVENT_ALL:	/* Default behavior is tracepoint */
				ev.type = LTTNG_EVENT_TRACEPOINT;
				/* Fall-through */
			case LTTNG_EVENT_TRACEPOINT:
				break;
			case LTTNG_EVENT_TRACEPOINT_LOGLEVEL:
				ev.type = LTTNG_EVENT_TRACEPOINT_LOGLEVEL;
				break;
			case LTTNG_EVENT_PROBE:
			case LTTNG_EVENT_FUNCTION:
			case LTTNG_EVENT_FUNCTION_ENTRY:
			case LTTNG_EVENT_SYSCALL:
			default:
				ret = CMD_NOT_IMPLEMENTED;
				goto error;
			}
		} else {
			ERR("Please specify a tracer (--kernel or --userspace)");
			goto error;
		}

		ret = lttng_enable_event(handle, &ev, channel_name);
		if (ret == 0) {
			MSG("%s event %s created in channel %s",
					opt_kernel ? "kernel": "UST", event_name, channel_name);
		}

		/* Next event */
		event_name = strtok(NULL, ",");
	}

end:
error:
	if (opt_channel_name == NULL) {
		free(channel_name);
	}
	lttng_destroy_handle(handle);

	return ret;
}

/*
 * Add event to trace session
 */
int cmd_enable_events(int argc, const char **argv)
{
	int opt, ret;
	static poptContext pc;
	char *session_name = NULL;

	pc = poptGetContext(NULL, argc, argv, long_options, 0);
	poptReadDefaultConfig(pc, 0);

	/* Default event type */
	opt_event_type = LTTNG_EVENT_ALL;

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case OPT_HELP:
			usage(stderr);
			ret = CMD_SUCCESS;
			goto end;
		case OPT_TRACEPOINT:
			opt_event_type = LTTNG_EVENT_TRACEPOINT;
			break;
		case OPT_PROBE:
			opt_event_type = LTTNG_EVENT_PROBE;
			break;
		case OPT_FUNCTION:
			opt_event_type = LTTNG_EVENT_FUNCTION;
			break;
		case OPT_FUNCTION_ENTRY:
			opt_event_type = LTTNG_EVENT_FUNCTION_ENTRY;
			break;
		case OPT_SYSCALL:
			opt_event_type = LTTNG_EVENT_SYSCALL;
			break;
		case OPT_USERSPACE:
			opt_userspace = 1;
			break;
		case OPT_TRACEPOINT_LOGLEVEL:
			opt_event_type = LTTNG_EVENT_TRACEPOINT_LOGLEVEL;
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

	if (!opt_session_name) {
		session_name = get_session_name();
		if (session_name == NULL) {
			ret = -1;
			goto end;
		}
	} else {
		session_name = opt_session_name;
	}

	ret = enable_events(session_name);

end:
	if (opt_session_name == NULL) {
		free(session_name);
	}

	return ret;
}
