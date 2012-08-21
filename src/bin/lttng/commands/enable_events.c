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
#include <unistd.h>
#include <inttypes.h>
#include <ctype.h>

#include "../command.h"
#include <src/common/sessiond-comm/sessiond-comm.h>

static char *opt_event_list;
static int opt_event_type;
static const char *opt_loglevel;
static int opt_loglevel_type;
static int opt_kernel;
static char *opt_session_name;
static int opt_userspace;
static int opt_enable_all;
static char *opt_probe;
static char *opt_function;
static char *opt_function_entry_symbol;
static char *opt_channel_name;
static char *opt_filter;
#if 0
/* Not implemented yet */
static char *opt_cmd_name;
static pid_t opt_pid;
#endif

enum {
	OPT_HELP = 1,
	OPT_TRACEPOINT,
	OPT_PROBE,
	OPT_FUNCTION,
	OPT_FUNCTION_ENTRY,
	OPT_SYSCALL,
	OPT_USERSPACE,
	OPT_LOGLEVEL,
	OPT_LOGLEVEL_ONLY,
	OPT_LIST_OPTIONS,
	OPT_FILTER,
};

static struct lttng_handle *handle;

static struct poptOption long_options[] = {
	/* longName, shortName, argInfo, argPtr, value, descrip, argDesc */
	{"help",           'h', POPT_ARG_NONE, 0, OPT_HELP, 0, 0},
	{"session",        's', POPT_ARG_STRING, &opt_session_name, 0, 0, 0},
	{"all",            'a', POPT_ARG_VAL, &opt_enable_all, 1, 0, 0},
	{"channel",        'c', POPT_ARG_STRING, &opt_channel_name, 0, 0, 0},
	{"kernel",         'k', POPT_ARG_VAL, &opt_kernel, 1, 0, 0},
	{"userspace",      'u', POPT_ARG_NONE, 0, OPT_USERSPACE, 0, 0},
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
	{"loglevel",       0,     POPT_ARG_STRING, 0, OPT_LOGLEVEL, 0, 0},
	{"loglevel-only",  0,     POPT_ARG_STRING, 0, OPT_LOGLEVEL_ONLY, 0, 0},
	{"list-options", 0, POPT_ARG_NONE, NULL, OPT_LIST_OPTIONS, NULL, NULL},
	{"filter",         'f', POPT_ARG_STRING, &opt_filter, OPT_FILTER, 0, 0},
	{0, 0, 0, 0, 0, 0, 0}
};

/*
 * usage
 */
static void usage(FILE *ofp)
{
	fprintf(ofp, "usage: lttng enable-event NAME[,NAME2,...] [-k|-u] [OPTIONS] \n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Options:\n");
	fprintf(ofp, "  -h, --help               Show this help\n");
	fprintf(ofp, "      --list-options       Simple listing of options\n");
	fprintf(ofp, "  -s, --session NAME       Apply to session name\n");
	fprintf(ofp, "  -c, --channel NAME       Apply to this channel\n");
	fprintf(ofp, "  -a, --all                Enable all tracepoints and syscalls\n");
	fprintf(ofp, "  -k, --kernel             Apply for the kernel tracer\n");
	fprintf(ofp, "  -u, --userspace          Apply to the user-space tracer\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Event options:\n");
	fprintf(ofp, "    --tracepoint           Tracepoint event (default)\n");
	fprintf(ofp, "                           - userspace tracer supports wildcards at end of string.\n");
	fprintf(ofp, "                             Don't forget to quote to deal with bash expansion.\n");
	fprintf(ofp, "                             e.g.:\n");
	fprintf(ofp, "                               \"*\"\n");
	fprintf(ofp, "                               \"app_component:na*\"\n");
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
	fprintf(ofp, "    --loglevel name\n");
	fprintf(ofp, "                           Tracepoint loglevel range from 0 to loglevel\n");
	fprintf(ofp, "    --loglevel-only name\n");
	fprintf(ofp, "                           Tracepoint loglevel (only this loglevel)\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "                           The loglevel or loglevel-only options should be\n");
	fprintf(ofp, "                           combined with a tracepoint name or tracepoint\n");
	fprintf(ofp, "                           wildcard.\n");
	fprintf(ofp, "                           Available loglevels:\n");
	fprintf(ofp, "                                              (higher value is more verbose)\n");
	fprintf(ofp, "                               TRACE_EMERG          = 0\n");
	fprintf(ofp, "                               TRACE_ALERT          = 1\n");
	fprintf(ofp, "                               TRACE_CRIT           = 2\n");
	fprintf(ofp, "                               TRACE_ERR            = 3\n");
	fprintf(ofp, "                               TRACE_WARNING        = 4\n");
	fprintf(ofp, "                               TRACE_NOTICE         = 5\n");
	fprintf(ofp, "                               TRACE_INFO           = 6\n");
	fprintf(ofp, "                               TRACE_DEBUG_SYSTEM   = 7\n");
	fprintf(ofp, "                               TRACE_DEBUG_PROGRAM  = 8\n");
	fprintf(ofp, "                               TRACE_DEBUG_PROCESS  = 9\n");
	fprintf(ofp, "                               TRACE_DEBUG_MODULE   = 10\n");
	fprintf(ofp, "                               TRACE_DEBUG_UNIT     = 11\n");
	fprintf(ofp, "                               TRACE_DEBUG_FUNCTION = 12\n");
	fprintf(ofp, "                               TRACE_DEBUG_LINE     = 13\n");
	fprintf(ofp, "                               TRACE_DEBUG          = 14\n");
	fprintf(ofp, "                               (shortcuts such as \"system\" are allowed)\n");
	fprintf(ofp, "    --filter \'expression\'\n");
	fprintf(ofp, "                           Filter expression on event fields,\n");
	fprintf(ofp, "                           event recording depends on evaluation.\n");
	fprintf(ofp, "                           Only specify on first activation of\n");
	fprintf(ofp, "                           a given event within a session.\n");
	fprintf(ofp, "                           Filter only allowed when enabling\n");
	fprintf(ofp, "                           events within a session before tracing\n");
	fprintf(ofp, "                           is started. If the filter fails to link\n");
	fprintf(ofp, "                           with the event within the traced domain,\n");
	fprintf(ofp, "                           the event will be discarded. Currently,\n");
	fprintf(ofp, "                           filter is only implemented for the user-space\n");
	fprintf(ofp, "                           tracer.\n");
	fprintf(ofp, "                           Expression examples:.\n");
	fprintf(ofp, "                           \n");
	fprintf(ofp, "                           'intfield > 500 && intfield < 503'\n");
	fprintf(ofp, "                           '(stringfield == \"test\" || intfield != 10) && intfield > 33'\n");
	fprintf(ofp, "                           'doublefield > 1.1 && intfield < 5.3'\n");
	fprintf(ofp, "                           \n");
	fprintf(ofp, "                           Wildcards are allowed at the end of strings:\n");
	fprintf(ofp, "                           'seqfield1 == \"te*\"'\n");
	fprintf(ofp, "                           In string literals, the escape character is '\\'.\n");
	fprintf(ofp, "                           Use '\\*' for the '*' character, and '\\\\' for\n");
	fprintf(ofp, "                           the '\\' character.\n");
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
 * Maps loglevel from string to value
 */
static
int loglevel_str_to_value(const char *inputstr)
{
	int i = 0;
	char str[LTTNG_SYMBOL_NAME_LEN];

	while (inputstr[i] != '\0' && i < LTTNG_SYMBOL_NAME_LEN) {
		str[i] = toupper(inputstr[i]);
		i++;
	}
	str[i] = '\0';
	if (!strcmp(str, "TRACE_EMERG") || !strcmp(str, "EMERG")) {
		return LTTNG_LOGLEVEL_EMERG;
	} else if (!strcmp(str, "TRACE_ALERT") || !strcmp(str, "ALERT")) {
		return LTTNG_LOGLEVEL_ALERT;
	} else if (!strcmp(str, "TRACE_CRIT") || !strcmp(str, "CRIT")) {
		return LTTNG_LOGLEVEL_CRIT;
	} else if (!strcmp(str, "TRACE_ERR") || !strcmp(str, "ERR")) {
		return LTTNG_LOGLEVEL_ERR;
	} else if (!strcmp(str, "TRACE_WARNING") || !strcmp(str, "WARNING")) {
		return LTTNG_LOGLEVEL_WARNING;
	} else if (!strcmp(str, "TRACE_NOTICE") || !strcmp(str, "NOTICE")) {
		return LTTNG_LOGLEVEL_NOTICE;
	} else if (!strcmp(str, "TRACE_INFO") || !strcmp(str, "INFO")) {
		return LTTNG_LOGLEVEL_INFO;
	} else if (!strcmp(str, "TRACE_DEBUG_SYSTEM") || !strcmp(str, "DEBUG_SYSTEM") || !strcmp(str, "SYSTEM")) {
		return LTTNG_LOGLEVEL_DEBUG_SYSTEM;
	} else if (!strcmp(str, "TRACE_DEBUG_PROGRAM") || !strcmp(str, "DEBUG_PROGRAM") || !strcmp(str, "PROGRAM")) {
		return LTTNG_LOGLEVEL_DEBUG_PROGRAM;
	} else if (!strcmp(str, "TRACE_DEBUG_PROCESS") || !strcmp(str, "DEBUG_PROCESS") || !strcmp(str, "PROCESS")) {
		return LTTNG_LOGLEVEL_DEBUG_PROCESS;
	} else if (!strcmp(str, "TRACE_DEBUG_MODULE") || !strcmp(str, "DEBUG_MODULE") || !strcmp(str, "MODULE")) {
		return LTTNG_LOGLEVEL_DEBUG_MODULE;
	} else if (!strcmp(str, "TRACE_DEBUG_UNIT") || !strcmp(str, "DEBUG_UNIT") || !strcmp(str, "UNIT")) {
		return LTTNG_LOGLEVEL_DEBUG_UNIT;
	} else if (!strcmp(str, "TRACE_DEBUG_FUNCTION") || !strcmp(str, "DEBUG_FUNCTION") || !strcmp(str, "FUNCTION")) {
		return LTTNG_LOGLEVEL_DEBUG_FUNCTION;
	} else if (!strcmp(str, "TRACE_DEBUG_LINE") || !strcmp(str, "DEBUG_LINE") || !strcmp(str, "LINE")) {
		return LTTNG_LOGLEVEL_DEBUG_LINE;
	} else if (!strcmp(str, "TRACE_DEBUG") || !strcmp(str, "DEBUG")) {
		return LTTNG_LOGLEVEL_DEBUG;
	} else {
		return -1;
	}
}

/*
 * Enabling event using the lttng API.
 */
static int enable_events(char *session_name)
{
	int err, ret = CMD_SUCCESS, warn = 0;
	char *event_name, *channel_name = NULL;
	struct lttng_event ev;
	struct lttng_domain dom;

	memset(&ev, 0, sizeof(ev));
	memset(&dom, 0, sizeof(dom));

	if (opt_kernel) {
		if (opt_filter) {
			ERR("Filter not implement for kernel tracing yet");
			ret = CMD_ERROR;
			goto error;
		}
	}

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

	if (opt_channel_name == NULL) {
		err = asprintf(&channel_name, DEFAULT_CHANNEL_NAME);
		if (err < 0) {
			ret = CMD_FATAL;
			goto error;
		}
	} else {
		channel_name = opt_channel_name;
	}

	handle = lttng_create_handle(session_name, &dom);
	if (handle == NULL) {
		ret = -1;
		goto error;
	}

	if (opt_enable_all) {
		/* Default setup for enable all */
		if (opt_kernel) {
			ev.type = opt_event_type;
			ev.name[0] = '\0';
			/* kernel loglevels not implemented */
			ev.loglevel_type = LTTNG_EVENT_LOGLEVEL_ALL;
		} else {
			ev.type = LTTNG_EVENT_TRACEPOINT;
			strcpy(ev.name, "*");
			ev.loglevel_type = opt_loglevel_type;
			if (opt_loglevel) {
				ev.loglevel = loglevel_str_to_value(opt_loglevel);
				if (ev.loglevel == -1) {
					ERR("Unknown loglevel %s", opt_loglevel);
					ret = -1;
					goto error;
				}
			} else {
				ev.loglevel = -1;
			}
		}

		ret = lttng_enable_event(handle, &ev, channel_name);
		if (ret < 0) {
			switch (-ret) {
			case LTTCOMM_KERN_EVENT_EXIST:
				WARN("Kernel events already enabled (channel %s, session %s)",
						channel_name, session_name);
				break;
			default:
				ERR("Events: %s (channel %s, session %s)",
						lttng_strerror(ret), channel_name, session_name);
				break;
			}
			goto end;
		}
		if (opt_filter) {
			ret = lttng_set_event_filter(handle, ev.name, channel_name,
						opt_filter);
			if (ret < 0) {
				ERR("Error setting filter");
				ret = -1;
				goto error;
			}
		}

		switch (opt_event_type) {
		case LTTNG_EVENT_TRACEPOINT:
			if (opt_loglevel) {
				MSG("All %s tracepoints are enabled in channel %s for loglevel %s",
					opt_kernel ? "kernel" : "UST", channel_name,
					opt_loglevel);
			} else {
				MSG("All %s tracepoints are enabled in channel %s",
					opt_kernel ? "kernel" : "UST", channel_name);

			}
			break;
		case LTTNG_EVENT_SYSCALL:
			if (opt_kernel) {
				MSG("All kernel system calls are enabled in channel %s",
						channel_name);
			}
			break;
		case LTTNG_EVENT_ALL:
			if (opt_loglevel) {
				MSG("All %s events are enabled in channel %s for loglevel %s",
					opt_kernel ? "kernel" : "UST", channel_name,
					opt_loglevel);
			} else {
				MSG("All %s events are enabled in channel %s",
					opt_kernel ? "kernel" : "UST", channel_name);
			}
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
				ret = CMD_UNDEFINED;
				goto error;
			}

			if (opt_loglevel) {
				MSG("Kernel loglevels are not supported.");
				ret = CMD_UNDEFINED;
				goto error;
			}

			/* kernel loglevels not implemented */
			ev.loglevel_type = LTTNG_EVENT_LOGLEVEL_ALL;
		} else if (opt_userspace) {		/* User-space tracer action */
#if 0
			if (opt_cmd_name != NULL || opt_pid) {
				MSG("Only supporting tracing all UST processes (-u) for now.");
				ret = CMD_UNDEFINED;
				goto error;
			}
#endif

			DBG("Enabling UST event %s for channel %s, loglevel %s", event_name,
					channel_name, opt_loglevel ? : "<all>");

			switch (opt_event_type) {
			case LTTNG_EVENT_ALL:	/* Default behavior is tracepoint */
				/* Fall-through */
			case LTTNG_EVENT_TRACEPOINT:
				/* Copy name and type of the event */
				ev.type = LTTNG_EVENT_TRACEPOINT;
				strncpy(ev.name, event_name, LTTNG_SYMBOL_NAME_LEN);
				ev.name[LTTNG_SYMBOL_NAME_LEN - 1] = '\0';
				break;
			case LTTNG_EVENT_PROBE:
			case LTTNG_EVENT_FUNCTION:
			case LTTNG_EVENT_FUNCTION_ENTRY:
			case LTTNG_EVENT_SYSCALL:
			default:
				ERR("Event type not available for user-space tracing");
				ret = CMD_UNDEFINED;
				goto error;
			}

			ev.loglevel_type = opt_loglevel_type;
			if (opt_loglevel) {
				ev.loglevel = loglevel_str_to_value(opt_loglevel);
				if (ev.loglevel == -1) {
					ERR("Unknown loglevel %s", opt_loglevel);
					ret = -1;
					goto error;
				}
			} else {
				ev.loglevel = -1;
			}
		} else {
			ERR("Please specify a tracer (-k/--kernel or -u/--userspace)");
			ret = CMD_ERROR;
			goto error;
		}

		ret = lttng_enable_event(handle, &ev, channel_name);
		if (ret < 0) {
			/* Turn ret to positive value to handle the positive error code */
			switch (-ret) {
			case LTTCOMM_KERN_EVENT_EXIST:
				WARN("Kernel event %s already enabled (channel %s, session %s)",
						event_name, channel_name, session_name);
				break;
			default:
				ERR("Event %s: %s (channel %s, session %s)", event_name,
						lttng_strerror(ret), channel_name, session_name);
				break;
			}
			warn = 1;
		} else {
			MSG("%s event %s created in channel %s",
					opt_kernel ? "kernel": "UST", event_name, channel_name);
		}
		if (opt_filter) {
			ret = lttng_set_event_filter(handle, ev.name,
				channel_name, opt_filter);
			if (ret < 0) {
				ERR("Error setting filter");
				ret = -1;
				goto error;
			}
		}

		/* Next event */
		event_name = strtok(NULL, ",");
	}

end:
error:
	if (warn) {
		ret = CMD_WARNING;
	}
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
	int opt, ret = CMD_SUCCESS;
	static poptContext pc;
	char *session_name = NULL;

	pc = poptGetContext(NULL, argc, argv, long_options, 0);
	poptReadDefaultConfig(pc, 0);

	/* Default event type */
	opt_event_type = LTTNG_EVENT_ALL;

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case OPT_HELP:
			usage(stdout);
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
		case OPT_LOGLEVEL:
			opt_loglevel_type = LTTNG_EVENT_LOGLEVEL_RANGE;
			opt_loglevel = poptGetOptArg(pc);
			break;
		case OPT_LOGLEVEL_ONLY:
			opt_loglevel_type = LTTNG_EVENT_LOGLEVEL_SINGLE;
			opt_loglevel = poptGetOptArg(pc);
			break;
		case OPT_LIST_OPTIONS:
			list_cmd_options(stdout, long_options);
			goto end;
		case OPT_FILTER:
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
		ret = CMD_ERROR;
		goto end;
	}

	if (!opt_session_name) {
		session_name = get_session_name();
		if (session_name == NULL) {
			ret = CMD_ERROR;
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

	poptFreeContext(pc);
	return ret;
}
