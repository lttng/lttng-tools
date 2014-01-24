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
#include <assert.h>
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
static int opt_jul;
static int opt_enable_all;
static char *opt_probe;
static char *opt_function;
static char *opt_function_entry_symbol;
static char *opt_channel_name;
static char *opt_filter;
static char *opt_exclude;
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
	OPT_EXCLUDE,
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
	{"jul",            'j', POPT_ARG_VAL, &opt_jul, 1, 0, 0},
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
	{"exclude",        'x', POPT_ARG_STRING, &opt_exclude, OPT_EXCLUDE, 0, 0},
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
	fprintf(ofp, "  -j, --jul                Apply for Java application using JUL\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Event options:\n");
	fprintf(ofp, "    --tracepoint           Tracepoint event (default)\n");
	fprintf(ofp, "                           - userspace tracer supports wildcards at end of string.\n");
	fprintf(ofp, "                             Don't forget to quote to deal with bash expansion.\n");
	fprintf(ofp, "                             e.g.:\n");
	fprintf(ofp, "                               \"*\"\n");
	fprintf(ofp, "                               \"app_component:na*\"\n");
	fprintf(ofp, "    --probe (addr | symbol | symbol+offset)\n");
	fprintf(ofp, "                           Dynamic probe.\n");
	fprintf(ofp, "                           Addr and offset can be octal (0NNN...),\n");
	fprintf(ofp, "                           decimal (NNN...) or hexadecimal (0xNNN...)\n");
	fprintf(ofp, "    --function (addr | symbol | symbol+offset)\n");
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
	fprintf(ofp, "\n");
	fprintf(ofp, "                           Available JUL domain loglevels:\n");
	fprintf(ofp, "                               JUL_OFF            = INT32_MAX\n");
	fprintf(ofp, "                               JUL_SEVERE         = %d\n", LTTNG_LOGLEVEL_JUL_SEVERE);
	fprintf(ofp, "                               JUL_WARNING        = %d\n", LTTNG_LOGLEVEL_JUL_WARNING);
	fprintf(ofp, "                               JUL_INFO           = %d\n", LTTNG_LOGLEVEL_JUL_INFO);
	fprintf(ofp, "                               JUL_CONFIG         = %d\n", LTTNG_LOGLEVEL_JUL_CONFIG);
	fprintf(ofp, "                               JUL_FINE           = %d\n", LTTNG_LOGLEVEL_JUL_FINE);
	fprintf(ofp, "                               JUL_FINER          = %d\n", LTTNG_LOGLEVEL_JUL_FINER);
	fprintf(ofp, "                               JUL_FINEST         = %d\n", LTTNG_LOGLEVEL_JUL_FINEST);
	fprintf(ofp, "                               JUL_ALL            = INT32_MIN\n");
	fprintf(ofp, "                               (shortcuts such as \"severe\" are allowed)\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "  -f, --filter \'expression\'\n");
	fprintf(ofp, "                           Filter expression on event fields and context.\n");
	fprintf(ofp, "                           Event recording depends on evaluation.\n");
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
	fprintf(ofp, "                           '(strfield == \"test\" || intfield != 10) && intfield > 33'\n");
	fprintf(ofp, "                           'doublefield > 1.1 && intfield < 5.3'\n");
	fprintf(ofp, "                           \n");
	fprintf(ofp, "                           Wildcards are allowed at the end of strings:\n");
	fprintf(ofp, "                           'seqfield1 == \"te*\"'\n");
	fprintf(ofp, "                           In string literals, the escape character is '\\'.\n");
	fprintf(ofp, "                           Use '\\*' for the '*' character, and '\\\\' for\n");
	fprintf(ofp, "                           the '\\' character. Wildcard match any sequence of,\n");
	fprintf(ofp, "                           characters including an empty sub-string (match 0 or\n");
	fprintf(ofp, "                           more characters).\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "                           Context information can be used for filtering. The\n");
	fprintf(ofp, "                           examples below show usage of context filtering on\n");
	fprintf(ofp, "                           process name (with a wildcard), process ID range, and\n");
	fprintf(ofp, "                           unique thread ID for filtering. The process and\n");
	fprintf(ofp, "                           thread ID of running applications can be found under\n");
	fprintf(ofp, "                           columns \"PID\" and \"LWP\" of the \"ps -eLf\" command.\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "                           '$ctx.procname == \"demo*\"'\n");
	fprintf(ofp, "                           '$ctx.vpid >= 4433 && $ctx.vpid < 4455'\n");
	fprintf(ofp, "                           '$ctx.vtid == 1234'\n");
	fprintf(ofp, "  -x, --exclude LIST\n");
	fprintf(ofp, "                           Add exclusions to UST tracepoints:\n");
	fprintf(ofp, "                           Events that match any of the items\n");
	fprintf(ofp, "                           in the comma-separated LIST are not\n");
	fprintf(ofp, "                           enabled, even if they match a wildcard\n");
	fprintf(ofp, "                           definition of the event.\n");
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
		if (*s_hex == '\0') {
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
		if (*s_hex == '\0') {
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
 * Maps JUL loglevel from string to value
 */
static int loglevel_jul_str_to_value(const char *inputstr)
{
	int i = 0;
	char str[LTTNG_SYMBOL_NAME_LEN];

	/*
	 * Loop up to LTTNG_SYMBOL_NAME_LEN minus one because the NULL bytes is
	 * added at the end of the loop so a the upper bound we avoid the overflow.
	 */
	while (i < (LTTNG_SYMBOL_NAME_LEN - 1) && inputstr[i] != '\0') {
		str[i] = toupper(inputstr[i]);
		i++;
	}
	str[i] = '\0';

	if (!strcmp(str, "JUL_OFF") || !strcmp(str, "OFF")) {
		return LTTNG_LOGLEVEL_JUL_OFF;
	} else if (!strcmp(str, "JUL_SEVERE") || !strcmp(str, "SEVERE")) {
		return LTTNG_LOGLEVEL_JUL_SEVERE;
	} else if (!strcmp(str, "JUL_WARNING") || !strcmp(str, "WARNING")) {
		return LTTNG_LOGLEVEL_JUL_WARNING;
	} else if (!strcmp(str, "JUL_INFO") || !strcmp(str, "INFO")) {
		return LTTNG_LOGLEVEL_JUL_INFO;
	} else if (!strcmp(str, "JUL_CONFIG") || !strcmp(str, "CONFIG")) {
		return LTTNG_LOGLEVEL_JUL_CONFIG;
	} else if (!strcmp(str, "JUL_FINE") || !strcmp(str, "FINE")) {
		return LTTNG_LOGLEVEL_JUL_FINE;
	} else if (!strcmp(str, "JUL_FINER") || !strcmp(str, "FINER")) {
		return LTTNG_LOGLEVEL_JUL_FINER;
	} else if (!strcmp(str, "JUL_FINEST") || !strcmp(str, "FINEST")) {
		return LTTNG_LOGLEVEL_JUL_FINEST;
	} else if (!strcmp(str, "JUL_ALL") || !strcmp(str, "ALL")) {
		return LTTNG_LOGLEVEL_JUL_ALL;
	} else {
		return -1;
	}
}

/*
 * Maps loglevel from string to value
 */
static
int loglevel_str_to_value(const char *inputstr)
{
	int i = 0;
	char str[LTTNG_SYMBOL_NAME_LEN];

	/*
	 * Loop up to LTTNG_SYMBOL_NAME_LEN minus one because the NULL bytes is
	 * added at the end of the loop so a the upper bound we avoid the overflow.
	 */
	while (i < (LTTNG_SYMBOL_NAME_LEN - 1) && inputstr[i] != '\0') {
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

static
const char *print_channel_name(const char *name)
{
	return name ? : DEFAULT_CHANNEL_NAME;
}

static
const char *print_raw_channel_name(const char *name)
{
	return name ? : "<default>";
}

/*
 * Return allocated string for pretty-printing exclusion names.
 */
static
char *print_exclusions(int count, char **names)
{
	int length = 0;
	int i;
	const char *preamble = " excluding ";
	char *ret;

	if (count == 0) {
		return strdup("");
	}

	/* calculate total required length */
	for (i = 0; i < count; i++) {
		length += strlen(names[i]) + 1;
	}

	/* add length of preamble + one for NUL - one for last (missing) comma */
	length += strlen(preamble);
	ret = malloc(length);
	strncpy(ret, preamble, length);
	for (i = 0; i < count; i++) {
		strcat(ret, names[i]);
		if (i != count - 1) {
			strcat(ret, ",");
		}
	}
	return ret;
}

/*
 * Compare list of exclusions against an event name.
 * Return a list of legal exclusion names.
 * Produce an error or a warning about others (depending on the situation)
 */
static
int check_exclusion_subsets(const char *event_name,
		const char *exclusions,
		int *exclusion_count_ptr,
		char ***exclusion_list_ptr)
{
	const char *excluder_ptr;
	const char *event_ptr;
	const char *next_excluder;
	int excluder_length;
	int exclusion_count = 0;
	char **exclusion_list = NULL;
	int ret = CMD_SUCCESS;

	if (event_name[strlen(event_name) - 1] != '*') {
		ERR("Event %s: Excluders can only be used with wildcarded events", event_name);
		goto error;
	}

	next_excluder = exclusions;
	while (*next_excluder != 0) {
		event_ptr = event_name;
		excluder_ptr = next_excluder;
		excluder_length = strcspn(next_excluder, ",");

		/* Scan both the excluder and the event letter by letter */
		while (1) {
			char e, x;

			e = *event_ptr;
			x = *excluder_ptr;

			if (x == '*') {
				/* Event is a subset of the excluder */
				ERR("Event %s: %.*s excludes all events from %s",
						event_name,
						excluder_length,
						next_excluder,
						event_name);
				goto error;
			}
			if (e == '*') {
				/* Excluder is a proper subset of event */
				exclusion_count++;
				exclusion_list = realloc(exclusion_list, sizeof(char **) * exclusion_count);
				exclusion_list[exclusion_count - 1] = strndup(next_excluder, excluder_length);

				break;
			}
			if (x != e) {
				/* Excluder and event sets have no common elements */
				WARN("Event %s: %.*s does not exclude any events from %s",
						event_name,
						excluder_length,
						next_excluder,
						event_name);
				break;
			}
			excluder_ptr++;
			event_ptr++;
		}
		/* next excluder */
		next_excluder += excluder_length;
		if (*next_excluder == ',') {
			next_excluder++;
		}
	}
	goto end;
error:
	while (exclusion_count--) {
		free(exclusion_list[exclusion_count]);
	}
	if (exclusion_list != NULL) {
		free(exclusion_list);
	}
	exclusion_list = NULL;
	exclusion_count = 0;
	ret = CMD_ERROR;
end:
	*exclusion_count_ptr = exclusion_count;
	*exclusion_list_ptr = exclusion_list;
	return ret;
}
/*
 * Enabling event using the lttng API.
 */
static int enable_events(char *session_name)
{
	int ret = CMD_SUCCESS, warn = 0;
	char *event_name, *channel_name = NULL;
	struct lttng_event ev;
	struct lttng_domain dom;
	int exclusion_count = 0;
	char **exclusion_list = NULL;

	memset(&ev, 0, sizeof(ev));
	memset(&dom, 0, sizeof(dom));

	if (opt_kernel) {
		if (opt_filter) {
			ERR("Filter not implement for kernel tracing yet");
			ret = CMD_ERROR;
			goto error;
		}
		if (opt_loglevel) {
			WARN("Kernel loglevels are not supported.");
		}
	}

	/* Create lttng domain */
	if (opt_kernel) {
		dom.type = LTTNG_DOMAIN_KERNEL;
		dom.buf_type = LTTNG_BUFFER_GLOBAL;
	} else if (opt_userspace) {
		dom.type = LTTNG_DOMAIN_UST;
		/* Default. */
		dom.buf_type = LTTNG_BUFFER_PER_UID;
	} else if (opt_jul) {
		dom.type = LTTNG_DOMAIN_JUL;
		/* Default. */
		dom.buf_type = LTTNG_BUFFER_PER_UID;
	} else {
		print_missing_domain();
		ret = CMD_ERROR;
		goto error;
	}

	if (opt_kernel && opt_exclude) {
		ERR("Event name exclusions are not yet implemented for kernel events");
		ret = CMD_ERROR;
		goto error;
	}

	channel_name = opt_channel_name;

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
				assert(opt_userspace || opt_jul);
				if (opt_userspace) {
					ev.loglevel = loglevel_str_to_value(opt_loglevel);
				} else if (opt_jul) {
					ev.loglevel = loglevel_jul_str_to_value(opt_loglevel);
				}
				if (ev.loglevel == -1) {
					ERR("Unknown loglevel %s", opt_loglevel);
					ret = -LTTNG_ERR_INVALID;
					goto error;
				}
			} else {
				assert(opt_userspace || opt_jul);
				if (opt_userspace) {
					ev.loglevel = -1;
				} else if (opt_jul) {
					ev.loglevel = LTTNG_LOGLEVEL_JUL_ALL;
				}
			}
		}

		if (opt_exclude) {
			ret = check_exclusion_subsets("*", opt_exclude,
					&exclusion_count, &exclusion_list);
			if (ret == CMD_ERROR) {
				goto error;
			}
		}
		if (!opt_filter) {
			ret = lttng_enable_event_with_exclusions(handle,
					&ev, channel_name,
					NULL,
					exclusion_count, exclusion_list);
			if (ret < 0) {
				switch (-ret) {
				case LTTNG_ERR_KERN_EVENT_EXIST:
					WARN("Kernel events already enabled (channel %s, session %s)",
							print_channel_name(channel_name), session_name);
					break;
				default:
					ERR("Events: %s (channel %s, session %s)",
							lttng_strerror(ret),
							ret == -LTTNG_ERR_NEED_CHANNEL_NAME
								? print_raw_channel_name(channel_name)
								: print_channel_name(channel_name),
							session_name);
					break;
				}
				goto end;
			}

			switch (opt_event_type) {
			case LTTNG_EVENT_TRACEPOINT:
				if (opt_loglevel && dom.type != LTTNG_DOMAIN_KERNEL) {
					char *exclusion_string = print_exclusions(exclusion_count, exclusion_list);
					MSG("All %s tracepoints%s are enabled in channel %s for loglevel %s",
							get_domain_str(dom.type),
							exclusion_string,
							print_channel_name(channel_name),
							opt_loglevel);
					free(exclusion_string);
				} else {
					char *exclusion_string = print_exclusions(exclusion_count, exclusion_list);
					MSG("All %s tracepoints%s are enabled in channel %s",
							get_domain_str(dom.type),
							exclusion_string,
							print_channel_name(channel_name));
					free(exclusion_string);
				}
				break;
			case LTTNG_EVENT_SYSCALL:
				if (opt_kernel) {
					MSG("All kernel system calls are enabled in channel %s",
							print_channel_name(channel_name));
				}
				break;
			case LTTNG_EVENT_ALL:
				if (opt_loglevel && dom.type != LTTNG_DOMAIN_KERNEL) {
					char *exclusion_string = print_exclusions(exclusion_count, exclusion_list);
					MSG("All %s events%s are enabled in channel %s for loglevel %s",
							get_domain_str(dom.type),
							exclusion_string,
							print_channel_name(channel_name),
							opt_loglevel);
					free(exclusion_string);
				} else {
					char *exclusion_string = print_exclusions(exclusion_count, exclusion_list);
					MSG("All %s events%s are enabled in channel %s",
							get_domain_str(dom.type),
							exclusion_string,
							print_channel_name(channel_name));
					free(exclusion_string);
				}
				break;
			default:
				/*
				 * We should not be here since lttng_enable_event should have
				 * failed on the event type.
				 */
				goto error;
			}
		}
		if (opt_filter) {
			ret = lttng_enable_event_with_exclusions(handle, &ev, channel_name,
						opt_filter, exclusion_count, exclusion_list);
			if (ret < 0) {
				switch (-ret) {
				case LTTNG_ERR_FILTER_EXIST:
					WARN("Filter on all events is already enabled"
							" (channel %s, session %s)",
						print_channel_name(channel_name), session_name);
					break;
				default:
					ERR("All events: %s (channel %s, session %s, filter \'%s\')",
							lttng_strerror(ret),
							ret == -LTTNG_ERR_NEED_CHANNEL_NAME
								? print_raw_channel_name(channel_name)
								: print_channel_name(channel_name),
							session_name, opt_filter);
					break;
				}
				goto error;
			} else {
				MSG("Filter '%s' successfully set", opt_filter);
			}
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
					event_name,
					print_channel_name(channel_name));

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
					print_channel_name(channel_name), opt_loglevel ? : "<all>");

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
				ret = CMD_UNSUPPORTED;
				goto error;
			}

			if (opt_exclude) {
				if (opt_event_type != LTTNG_EVENT_ALL && opt_event_type != LTTNG_EVENT_TRACEPOINT) {
					ERR("Exclusion option can only be used with tracepoint events");
					ret = CMD_ERROR;
					goto error;
				}
				/* Free previously allocated items */
				if (exclusion_list != NULL) {
					while (exclusion_count--) {
						free(exclusion_list[exclusion_count]);
					}
					free(exclusion_list);
					exclusion_list = NULL;
				}
				/* Check for proper subsets */
				ret = check_exclusion_subsets(event_name, opt_exclude,
						&exclusion_count, &exclusion_list);
				if (ret == CMD_ERROR) {
					goto error;
				}
			}

			ev.loglevel_type = opt_loglevel_type;
			if (opt_loglevel) {
				ev.loglevel = loglevel_str_to_value(opt_loglevel);
				if (ev.loglevel == -1) {
					ERR("Unknown loglevel %s", opt_loglevel);
					ret = -LTTNG_ERR_INVALID;
					goto error;
				}
			} else {
				ev.loglevel = -1;
			}
		} else if (opt_jul) {
			if (opt_event_type != LTTNG_EVENT_ALL &&
					opt_event_type != LTTNG_EVENT_TRACEPOINT) {
				ERR("Event type not supported for JUL domain.");
				ret = CMD_UNSUPPORTED;
				goto error;
			}

			ev.loglevel_type = opt_loglevel_type;
			if (opt_loglevel) {
				ev.loglevel = loglevel_jul_str_to_value(opt_loglevel);
				if (ev.loglevel == -1) {
					ERR("Unknown loglevel %s", opt_loglevel);
					ret = -LTTNG_ERR_INVALID;
					goto error;
				}
			} else {
				ev.loglevel = LTTNG_LOGLEVEL_JUL_ALL;
			}
			ev.type = LTTNG_EVENT_TRACEPOINT;
			strncpy(ev.name, event_name, LTTNG_SYMBOL_NAME_LEN);
			ev.name[LTTNG_SYMBOL_NAME_LEN - 1] = '\0';
		} else {
			print_missing_domain();
			ret = CMD_ERROR;
			goto error;
		}

		if (!opt_filter) {
			char *exclusion_string;

			ret = lttng_enable_event_with_exclusions(handle,
					&ev, channel_name,
					NULL, exclusion_count, exclusion_list);
			exclusion_string = print_exclusions(exclusion_count, exclusion_list);
			if (ret < 0) {
				/* Turn ret to positive value to handle the positive error code */
				switch (-ret) {
				case LTTNG_ERR_KERN_EVENT_EXIST:
					WARN("Kernel event %s%s already enabled (channel %s, session %s)",
							event_name,
							exclusion_string,
							print_channel_name(channel_name), session_name);
					break;
				default:
					ERR("Event %s%s: %s (channel %s, session %s)", event_name,
							exclusion_string,
							lttng_strerror(ret),
							ret == -LTTNG_ERR_NEED_CHANNEL_NAME
								? print_raw_channel_name(channel_name)
								: print_channel_name(channel_name),
							session_name);
					break;
				}
				warn = 1;
			} else {
				MSG("%s event %s%s created in channel %s",
						get_domain_str(dom.type), event_name,
						exclusion_string,
						print_channel_name(channel_name));
			}
			free(exclusion_string);
		}

		if (opt_filter) {
			char *exclusion_string;

			ret = lttng_enable_event_with_exclusions(handle, &ev, channel_name,
					opt_filter, exclusion_count, exclusion_list);
			exclusion_string = print_exclusions(exclusion_count, exclusion_list);

			if (ret < 0) {
				switch (-ret) {
				case LTTNG_ERR_FILTER_EXIST:
					WARN("Filter on event %s%s is already enabled"
							" (channel %s, session %s)",
						event_name,
						exclusion_string,
						print_channel_name(channel_name), session_name);
					break;
				default:
					ERR("Event %s%s: %s (channel %s, session %s, filter \'%s\')", ev.name,
							exclusion_string,
							lttng_strerror(ret),
							ret == -LTTNG_ERR_NEED_CHANNEL_NAME
								? print_raw_channel_name(channel_name)
								: print_channel_name(channel_name),
							session_name, opt_filter);
					break;
				}
				free(exclusion_string);
				goto error;
			} else {
				MSG("Event %s%s: Filter '%s' successfully set",
						event_name, exclusion_string,
						opt_filter);
			}
			free(exclusion_string);
		}

		/* Next event */
		event_name = strtok(NULL, ",");
	}

end:
error:
	if (warn) {
		ret = CMD_WARNING;
	}
	lttng_destroy_handle(handle);

	if (exclusion_list != NULL) {
		while (exclusion_count--) {
			free(exclusion_list[exclusion_count]);
		}
		free(exclusion_list);
	}

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
	int event_type = -1;

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
		case OPT_EXCLUDE:
			break;
		default:
			usage(stderr);
			ret = CMD_UNDEFINED;
			goto end;
		}

		/* Validate event type. Multiple event type are not supported. */
		if (event_type == -1) {
			event_type = opt_event_type;
		} else {
			if (event_type != opt_event_type) {
				ERR("Multiple event type not supported.");
				ret = CMD_ERROR;
				goto end;
			}
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
