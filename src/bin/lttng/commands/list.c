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

#define _LGPL_SOURCE
#include <inttypes.h>
#include <popt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <common/mi-lttng.h>
#include <lttng/constant.h>

#include "../command.h"

static int opt_userspace;
static int opt_kernel;
static int opt_jul;
static int opt_log4j;
static int opt_python;
static char *opt_channel;
static int opt_domain;
static int opt_fields;
static int opt_syscall;

const char *indent4 = "    ";
const char *indent6 = "      ";
const char *indent8 = "        ";

#ifdef LTTNG_EMBED_HELP
static const char help_msg[] =
#include <lttng-list.1.h>
;
#endif

enum {
	OPT_HELP = 1,
	OPT_USERSPACE,
	OPT_LIST_OPTIONS,
};

static struct lttng_handle *handle;
static struct mi_writer *writer;

/* Only set when listing a single session. */
static struct lttng_session listed_session;

static struct poptOption long_options[] = {
	/* longName, shortName, argInfo, argPtr, value, descrip, argDesc */
	{"help",	'h', POPT_ARG_NONE, 0, OPT_HELP, 0, 0},
	{"kernel",	'k', POPT_ARG_VAL, &opt_kernel, 1, 0, 0},
	{"jul",	'j', POPT_ARG_VAL, &opt_jul, 1, 0, 0},
	{"log4j",	'l', POPT_ARG_VAL, &opt_log4j, 1, 0, 0},
	{"python",	'p', POPT_ARG_VAL, &opt_python, 1, 0, 0},
	{"userspace",	'u', POPT_ARG_NONE, 0, OPT_USERSPACE, 0, 0},
	{"channel",	'c', POPT_ARG_STRING, &opt_channel, 0, 0, 0},
	{"domain",	'd', POPT_ARG_VAL, &opt_domain, 1, 0, 0},
	{"fields",	'f', POPT_ARG_VAL, &opt_fields, 1, 0, 0},
	{"syscall",	'S', POPT_ARG_VAL, &opt_syscall, 1, 0, 0},
	{"list-options", 0, POPT_ARG_NONE, NULL, OPT_LIST_OPTIONS, NULL, NULL},
	{0, 0, 0, 0, 0, 0, 0}
};

/*
 * Get command line from /proc for a specific pid.
 *
 * On success, return an allocated string pointer to the proc cmdline.
 * On error, return NULL.
 */
static char *get_cmdline_by_pid(pid_t pid)
{
	int ret;
	FILE *fp = NULL;
	char *cmdline = NULL;
	/* Can't go bigger than /proc/LTTNG_MAX_PID/cmdline */
	char path[sizeof("/proc//cmdline") + sizeof(LTTNG_MAX_PID_STR) - 1];

	snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
	fp = fopen(path, "r");
	if (fp == NULL) {
		goto end;
	}

	/* Caller must free() *cmdline */
	cmdline = zmalloc(PATH_MAX);
	if (!cmdline) {
		PERROR("malloc cmdline");
		goto end;
	}
	ret = fread(cmdline, 1, PATH_MAX, fp);
	if (ret < 0) {
		PERROR("fread proc list");
	}

end:
	if (fp) {
		fclose(fp);
	}
	return cmdline;
}

static
const char *active_string(int value)
{
	switch (value) {
	case 0:	return "inactive";
	case 1: return "active";
	case -1: return "";
	default: return NULL;
	}
}

static const char *snapshot_string(int value)
{
	switch (value) {
	case 1:
		return " snapshot";
	default:
		return "";
	}
}

static
const char *enabled_string(int value)
{
	switch (value) {
	case 0:	return " [disabled]";
	case 1: return " [enabled]";
	case -1: return "";
	default: return NULL;
	}
}

static
const char *safe_string(const char *str)
{
	return str ? str : "";
}

static const char *logleveltype_string(enum lttng_loglevel_type value)
{
	switch (value) {
	case LTTNG_EVENT_LOGLEVEL_ALL:
		return ":";
	case LTTNG_EVENT_LOGLEVEL_RANGE:
		return " <=";
	case LTTNG_EVENT_LOGLEVEL_SINGLE:
		return " ==";
	default:
		return " <<TYPE UNKN>>";
	}
}

static const char *bitness_event(enum lttng_event_flag flags)
{
	if (flags & LTTNG_EVENT_FLAG_SYSCALL_32) {
		if (flags & LTTNG_EVENT_FLAG_SYSCALL_64) {
			return " [32/64-bit]";
		} else {
			return " [32-bit]";
		}
	} else if (flags & LTTNG_EVENT_FLAG_SYSCALL_64) {
		return " [64-bit]";
	} else {
		return "";
	}
}

/*
 * Get exclusion names message for a single event.
 *
 * Returned pointer must be freed by caller. Returns NULL on error.
 */
static char *get_exclusion_names_msg(struct lttng_event *event)
{
	int ret;
	int exclusion_count;
	char *exclusion_msg = NULL;
	char *at;
	size_t i;
	const char * const exclusion_fmt = " [exclusions: ";
	const size_t exclusion_fmt_len = strlen(exclusion_fmt);

	exclusion_count = lttng_event_get_exclusion_name_count(event);
	if (exclusion_count < 0) {
		goto end;
	} else if (exclusion_count == 0) {
		/*
		 * No exclusions: return copy of empty string so that
		 * it can be freed by caller.
		 */
		exclusion_msg = strdup("");
		goto end;
	}

	/*
	 * exclusion_msg's size is bounded by the exclusion_fmt string,
	 * a comma per entry, the entry count (fixed-size), a closing
	 * bracket, and a trailing \0.
	 */
	exclusion_msg = malloc(exclusion_count +
			exclusion_count * LTTNG_SYMBOL_NAME_LEN +
			exclusion_fmt_len + 1);
	if (!exclusion_msg) {
		goto end;
	}

	at = strcpy(exclusion_msg, exclusion_fmt) + exclusion_fmt_len;
	for (i = 0; i < exclusion_count; ++i) {
		const char *name;

		/* Append comma between exclusion names */
		if (i > 0) {
			*at = ',';
			at++;
		}

		ret = lttng_event_get_exclusion_name(event, i, &name);
		if (ret) {
			/* Prints '?' on local error; should never happen */
			*at = '?';
			at++;
			continue;
		}

		/* Append exclusion name */
		at += sprintf(at, "%s", name);
	}

	/* This also puts a final '\0' at the end of exclusion_msg */
	strcpy(at, "]");

end:
	return exclusion_msg;
}

/*
 * Pretty print single event.
 */
static void print_events(struct lttng_event *event)
{
	int ret;
	const char *filter_str;
	char *filter_msg = NULL;
	char *exclusion_msg = NULL;

	ret = lttng_event_get_filter_expression(event, &filter_str);

	if (ret) {
		filter_msg = strdup(" [failed to retrieve filter]");
	} else if (filter_str) {
		const char * const filter_fmt = " [filter: '%s']";

		filter_msg = malloc(strlen(filter_str) +
				strlen(filter_fmt) + 1);
		if (filter_msg) {
			sprintf(filter_msg, filter_fmt,
					filter_str);
		}
	}

	exclusion_msg = get_exclusion_names_msg(event);
	if (!exclusion_msg) {
		exclusion_msg = strdup(" [failed to retrieve exclusions]");
	}

	switch (event->type) {
	case LTTNG_EVENT_TRACEPOINT:
	{
		if (event->loglevel != -1) {
			MSG("%s%s (loglevel%s %s (%d)) (type: tracepoint)%s%s%s",
				indent6,
				event->name,
				logleveltype_string(event->loglevel_type),
				mi_lttng_loglevel_string(event->loglevel, handle->domain.type),
				event->loglevel,
				enabled_string(event->enabled),
				safe_string(exclusion_msg),
				safe_string(filter_msg));
		} else {
			MSG("%s%s (type: tracepoint)%s%s%s",
				indent6,
				event->name,
				enabled_string(event->enabled),
				safe_string(exclusion_msg),
				safe_string(filter_msg));
		}
		break;
	}
	case LTTNG_EVENT_FUNCTION:
		MSG("%s%s (type: function)%s%s", indent6,
				event->name, enabled_string(event->enabled),
				safe_string(filter_msg));
		if (event->attr.probe.addr != 0) {
			MSG("%saddr: 0x%" PRIx64, indent8, event->attr.probe.addr);
		} else {
			MSG("%soffset: 0x%" PRIx64, indent8, event->attr.probe.offset);
			MSG("%ssymbol: %s", indent8, event->attr.probe.symbol_name);
		}
		break;
	case LTTNG_EVENT_PROBE:
		MSG("%s%s (type: probe)%s%s", indent6,
				event->name, enabled_string(event->enabled),
				safe_string(filter_msg));
		if (event->attr.probe.addr != 0) {
			MSG("%saddr: 0x%" PRIx64, indent8, event->attr.probe.addr);
		} else {
			MSG("%soffset: 0x%" PRIx64, indent8, event->attr.probe.offset);
			MSG("%ssymbol: %s", indent8, event->attr.probe.symbol_name);
		}
		break;
	case LTTNG_EVENT_FUNCTION_ENTRY:
		MSG("%s%s (type: function)%s%s", indent6,
				event->name, enabled_string(event->enabled),
				safe_string(filter_msg));
		MSG("%ssymbol: \"%s\"", indent8, event->attr.ftrace.symbol_name);
		break;
	case LTTNG_EVENT_SYSCALL:
		MSG("%s%s%s%s%s%s", indent6, event->name,
				(opt_syscall ? "" : " (type:syscall)"),
				enabled_string(event->enabled),
				bitness_event(event->flags),
				safe_string(filter_msg));
		break;
	case LTTNG_EVENT_NOOP:
		MSG("%s (type: noop)%s%s", indent6,
				enabled_string(event->enabled),
				safe_string(filter_msg));
		break;
	case LTTNG_EVENT_ALL:
		/* We should never have "all" events in list. */
		assert(0);
		break;
	}

	free(filter_msg);
	free(exclusion_msg);
}

static const char *field_type(struct lttng_event_field *field)
{
	switch(field->type) {
	case LTTNG_EVENT_FIELD_INTEGER:
		return "integer";
	case LTTNG_EVENT_FIELD_ENUM:
		return "enum";
	case LTTNG_EVENT_FIELD_FLOAT:
		return "float";
	case LTTNG_EVENT_FIELD_STRING:
		return "string";
	case LTTNG_EVENT_FIELD_OTHER:
	default:	/* fall-through */
		return "unknown";
	}
}

/*
 * Pretty print single event fields.
 */
static void print_event_field(struct lttng_event_field *field)
{
	if (!field->field_name[0]) {
		return;
	}
	MSG("%sfield: %s (%s)%s", indent8, field->field_name,
		field_type(field), field->nowrite ? " [no write]" : "");
}

/*
 * Machine interface
 * Jul and ust event listing
 */
static int mi_list_agent_ust_events(struct lttng_event *events, int count,
		struct lttng_domain *domain)
{
	int ret, i;
	pid_t cur_pid = 0;
	char *cmdline = NULL;
	int pid_element_open = 0;

	/* Open domains element */
	ret = mi_lttng_domains_open(writer);
	if (ret) {
		goto end;
	}

	/* Write domain */
	ret = mi_lttng_domain(writer, domain, 1);
	if (ret) {
		goto end;
	}

	/* Open pids element element */
	ret = mi_lttng_pids_open(writer);
	if (ret) {
		goto end;
	}

	for (i = 0; i < count; i++) {
		if (cur_pid != events[i].pid) {
			if (pid_element_open) {
				/* Close the previous events and pid element */
				ret = mi_lttng_close_multi_element(writer, 2);
				if (ret) {
					goto end;
				}
				pid_element_open = 0;
			}

			cur_pid = events[i].pid;
			cmdline = get_cmdline_by_pid(cur_pid);
			if (!cmdline) {
				ret = CMD_ERROR;
				goto end;
			}

			if (!pid_element_open) {
				/* Open and write a pid element */
				ret = mi_lttng_pid(writer, cur_pid, cmdline, 1);
				if (ret) {
					goto error;
				}

				/* Open events element */
				ret = mi_lttng_events_open(writer);
				if (ret) {
					goto error;
				}

				pid_element_open = 1;
			}
			free(cmdline);
		}

		/* Write an event */
		ret = mi_lttng_event(writer, &events[i], 0, handle->domain.type);
		if (ret) {
			goto end;
		}
	}

	/* Close pids */
	ret = mi_lttng_writer_close_element(writer);
	if (ret) {
		goto end;
	}

	/* Close domain, domains */
	ret = mi_lttng_close_multi_element(writer, 2);
end:
	return ret;
error:
	free(cmdline);
	return ret;
}

static int list_agent_events(void)
{
	int i, size, ret = CMD_SUCCESS;
	struct lttng_domain domain;
	struct lttng_handle *handle = NULL;
	struct lttng_event *event_list = NULL;
	pid_t cur_pid = 0;
	char *cmdline = NULL;
	const char *agent_domain_str;

	memset(&domain, 0, sizeof(domain));
	if (opt_jul) {
		domain.type = LTTNG_DOMAIN_JUL;
	} else if (opt_log4j) {
		domain.type = LTTNG_DOMAIN_LOG4J;
	} else if (opt_python) {
		domain.type = LTTNG_DOMAIN_PYTHON;
	} else {
		ERR("Invalid agent domain selected.");
		ret = CMD_ERROR;
		goto error;
	}

	agent_domain_str = get_domain_str(domain.type);

	DBG("Getting %s tracing events", agent_domain_str);

	handle = lttng_create_handle(NULL, &domain);
	if (handle == NULL) {
		ret = CMD_ERROR;
		goto end;
	}

	size = lttng_list_tracepoints(handle, &event_list);
	if (size < 0) {
		ERR("Unable to list %s events: %s", agent_domain_str,
				lttng_strerror(size));
		ret = CMD_ERROR;
		goto end;
	}

	if (lttng_opt_mi) {
		/* Mi print */
		ret = mi_list_agent_ust_events(event_list, size, &domain);
		if (ret) {
			ret = CMD_ERROR;
			goto error;
		}
	} else {
		/* Pretty print */
		MSG("%s events (Logger name):\n-------------------------",
				agent_domain_str);

		if (size == 0) {
			MSG("None");
		}

		for (i = 0; i < size; i++) {
			if (cur_pid != event_list[i].pid) {
				cur_pid = event_list[i].pid;
				cmdline = get_cmdline_by_pid(cur_pid);
				if (cmdline == NULL) {
					ret = CMD_ERROR;
					goto error;
				}
				MSG("\nPID: %d - Name: %s", cur_pid, cmdline);
				free(cmdline);
			}
			MSG("%s- %s", indent6, event_list[i].name);
		}

		MSG("");
	}

error:
	free(event_list);
end:
	lttng_destroy_handle(handle);
	return ret;
}

/*
 * Ask session daemon for all user space tracepoints available.
 */
static int list_ust_events(void)
{
	int i, size, ret = CMD_SUCCESS;
	struct lttng_domain domain;
	struct lttng_handle *handle;
	struct lttng_event *event_list = NULL;
	pid_t cur_pid = 0;
	char *cmdline = NULL;

	memset(&domain, 0, sizeof(domain));

	DBG("Getting UST tracing events");

	domain.type = LTTNG_DOMAIN_UST;

	handle = lttng_create_handle(NULL, &domain);
	if (handle == NULL) {
		ret = CMD_ERROR;
		goto end;
	}

	size = lttng_list_tracepoints(handle, &event_list);
	if (size < 0) {
		ERR("Unable to list UST events: %s", lttng_strerror(size));
		ret = CMD_ERROR;
		goto error;
	}

	if (lttng_opt_mi) {
		/* Mi print */
		ret = mi_list_agent_ust_events(event_list, size, &domain);
	} else {
		/* Pretty print */
		MSG("UST events:\n-------------");

		if (size == 0) {
			MSG("None");
		}

		for (i = 0; i < size; i++) {
			if (cur_pid != event_list[i].pid) {
				cur_pid = event_list[i].pid;
				cmdline = get_cmdline_by_pid(cur_pid);
				if (cmdline == NULL) {
					ret = CMD_ERROR;
					goto error;
				}
				MSG("\nPID: %d - Name: %s", cur_pid, cmdline);
				free(cmdline);
			}
			print_events(&event_list[i]);
		}

		MSG("");
	}

error:
	free(event_list);
end:
	lttng_destroy_handle(handle);
	return ret;
}

/*
 * Machine interface
 * List all ust event with their fields
 */
static int mi_list_ust_event_fields(struct lttng_event_field *fields, int count,
		struct lttng_domain *domain)
{
	int ret, i;
	pid_t cur_pid = 0;
	char *cmdline = NULL;
	int pid_element_open = 0;
	int event_element_open = 0;
	struct lttng_event cur_event;

	memset(&cur_event, 0, sizeof(cur_event));

	/* Open domains element */
	ret = mi_lttng_domains_open(writer);
	if (ret) {
		goto end;
	}

	/* Write domain */
	ret = mi_lttng_domain(writer, domain, 1);
	if (ret) {
		goto end;
	}

	/* Open pids element */
	ret = mi_lttng_pids_open(writer);
	if (ret) {
		goto end;
	}

	for (i = 0; i < count; i++) {
		if (cur_pid != fields[i].event.pid) {
			if (pid_element_open) {
				if (event_element_open) {
					/* Close the previous field element and event. */
					ret = mi_lttng_close_multi_element(writer, 2);
					if (ret) {
						goto end;
					}
					event_element_open = 0;
				}
				/* Close the previous events, pid element */
				ret = mi_lttng_close_multi_element(writer, 2);
				if (ret) {
					goto end;
				}
				pid_element_open = 0;
			}

			cur_pid = fields[i].event.pid;
			cmdline = get_cmdline_by_pid(cur_pid);
			if (!pid_element_open) {
				/* Open and write a pid element */
				ret = mi_lttng_pid(writer, cur_pid, cmdline, 1);
				if (ret) {
					goto error;
				}

				/* Open events element */
				ret = mi_lttng_events_open(writer);
				if (ret) {
					goto error;
				}
				pid_element_open = 1;
			}
			free(cmdline);
			/* Wipe current event since we are about to print a new PID. */
			memset(&cur_event, 0, sizeof(cur_event));
		}

		if (strcmp(cur_event.name, fields[i].event.name) != 0) {
			if (event_element_open) {
				/* Close the previous fields element and the previous event */
				ret = mi_lttng_close_multi_element(writer, 2);
				if (ret) {
					goto end;
				}
				event_element_open = 0;
			}

			memcpy(&cur_event, &fields[i].event,
					sizeof(cur_event));

			if (!event_element_open) {
				/* Open and write the event */
				ret = mi_lttng_event(writer, &cur_event, 1,
						handle->domain.type);
				if (ret) {
					goto end;
				}

				/* Open a fields element */
				ret = mi_lttng_event_fields_open(writer);
				if (ret) {
					goto end;
				}
				event_element_open = 1;
			}
		}

		/* Print the event_field */
		ret = mi_lttng_event_field(writer, &fields[i]);
		if (ret) {
			goto end;
		}
	}

	/* Close pid, domain, domains */
	ret = mi_lttng_close_multi_element(writer, 3);
end:
	return ret;
error:
	free(cmdline);
	return ret;
}

/*
 * Ask session daemon for all user space tracepoint fields available.
 */
static int list_ust_event_fields(void)
{
	int i, size, ret = CMD_SUCCESS;
	struct lttng_domain domain;
	struct lttng_handle *handle;
	struct lttng_event_field *event_field_list;
	pid_t cur_pid = 0;
	char *cmdline = NULL;

	struct lttng_event cur_event;

	memset(&domain, 0, sizeof(domain));
	memset(&cur_event, 0, sizeof(cur_event));

	DBG("Getting UST tracing event fields");

	domain.type = LTTNG_DOMAIN_UST;

	handle = lttng_create_handle(NULL, &domain);
	if (handle == NULL) {
		ret = CMD_ERROR;
		goto end;
	}

	size = lttng_list_tracepoint_fields(handle, &event_field_list);
	if (size < 0) {
		ERR("Unable to list UST event fields: %s", lttng_strerror(size));
		ret = CMD_ERROR;
		goto end;
	}

	if (lttng_opt_mi) {
		/* Mi print */
		ret = mi_list_ust_event_fields(event_field_list, size, &domain);
		if (ret) {
			ret = CMD_ERROR;
			goto error;
		}
	} else {
		/* Pretty print */
		MSG("UST events:\n-------------");

		if (size == 0) {
			MSG("None");
		}

		for (i = 0; i < size; i++) {
			if (cur_pid != event_field_list[i].event.pid) {
				cur_pid = event_field_list[i].event.pid;
				cmdline = get_cmdline_by_pid(cur_pid);
				if (cmdline == NULL) {
					ret = CMD_ERROR;
					goto error;
				}
				MSG("\nPID: %d - Name: %s", cur_pid, cmdline);
				free(cmdline);
				/* Wipe current event since we are about to print a new PID. */
				memset(&cur_event, 0, sizeof(cur_event));
			}
			if (strcmp(cur_event.name, event_field_list[i].event.name) != 0) {
				print_events(&event_field_list[i].event);
				memcpy(&cur_event, &event_field_list[i].event,
						sizeof(cur_event));
			}
			print_event_field(&event_field_list[i]);
		}

		MSG("");
	}

error:
	free(event_field_list);
end:
	lttng_destroy_handle(handle);
	return ret;
}

/*
 * Machine interface
 * Print a list of kernel events
 */
static int mi_list_kernel_events(struct lttng_event *events, int count,
		struct lttng_domain *domain)
{
	int ret, i;

	/* Open domains element */
	ret = mi_lttng_domains_open(writer);
	if (ret) {
		goto end;
	}

	/* Write domain */
	ret = mi_lttng_domain(writer, domain, 1);
	if (ret) {
		goto end;
	}

	/* Open events */
	ret = mi_lttng_events_open(writer);
	if (ret) {
		goto end;
	}

	for (i = 0; i < count; i++) {
		ret = mi_lttng_event(writer, &events[i], 0, handle->domain.type);
		if (ret) {
			goto end;
		}
	}

	/* close events, domain and domains */
	ret = mi_lttng_close_multi_element(writer, 3);
	if (ret) {
		goto end;
	}

end:
	return ret;
}

/*
 * Ask for all trace events in the kernel
 */
static int list_kernel_events(void)
{
	int i, size, ret = CMD_SUCCESS;
	struct lttng_domain domain;
	struct lttng_handle *handle;
	struct lttng_event *event_list;

	memset(&domain, 0, sizeof(domain));

	DBG("Getting kernel tracing events");

	domain.type = LTTNG_DOMAIN_KERNEL;

	handle = lttng_create_handle(NULL, &domain);
	if (handle == NULL) {
		ret = CMD_ERROR;
		goto error;
	}

	size = lttng_list_tracepoints(handle, &event_list);
	if (size < 0) {
		ERR("Unable to list kernel events: %s", lttng_strerror(size));
		lttng_destroy_handle(handle);
		return CMD_ERROR;
	}

	if (lttng_opt_mi) {
		/* Mi print */
		ret = mi_list_kernel_events(event_list, size, &domain);
		if (ret) {
			ret = CMD_ERROR;
			goto end;
		}
	} else {
		MSG("Kernel events:\n-------------");

		for (i = 0; i < size; i++) {
			print_events(&event_list[i]);
		}

		MSG("");
	}

end:
	free(event_list);

	lttng_destroy_handle(handle);
	return ret;

error:
	lttng_destroy_handle(handle);
	return ret;
}

/*
 * Machine interface
 * Print a list of system calls.
 */
static int mi_list_syscalls(struct lttng_event *events, int count)
{
	int ret, i;

	/* Open events */
	ret = mi_lttng_events_open(writer);
	if (ret) {
		goto end;
	}

	for (i = 0; i < count; i++) {
		ret = mi_lttng_event(writer, &events[i], 0, handle->domain.type);
		if (ret) {
			goto end;
		}
	}

	/* Close events. */
	ret = mi_lttng_writer_close_element(writer);
	if (ret) {
		goto end;
	}

end:
	return ret;
}

/*
 * Ask for kernel system calls.
 */
static int list_syscalls(void)
{
	int i, size, ret = CMD_SUCCESS;
	struct lttng_event *event_list;

	DBG("Getting kernel system call events");

	size = lttng_list_syscalls(&event_list);
	if (size < 0) {
		ERR("Unable to list system calls: %s", lttng_strerror(size));
		ret = CMD_ERROR;
		goto error;
	}

	if (lttng_opt_mi) {
		/* Mi print */
		ret = mi_list_syscalls(event_list, size);
		if (ret) {
			ret = CMD_ERROR;
			goto end;
		}
	} else {
		MSG("System calls:\n-------------");

		for (i = 0; i < size; i++) {
			print_events(&event_list[i]);
		}

		MSG("");
	}

end:
	free(event_list);
	return ret;

error:
	return ret;
}

/*
 * Machine Interface
 * Print a list of agent events
 */
static int mi_list_session_agent_events(struct lttng_event *events, int count)
{
	int ret, i;

	/* Open events element */
	ret = mi_lttng_events_open(writer);
	if (ret) {
		goto end;
	}

	for (i = 0; i < count; i++) {
		ret = mi_lttng_event(writer, &events[i], 0, handle->domain.type);
		if (ret) {
			goto end;
		}
	}

	/* Close events element */
	ret = mi_lttng_writer_close_element(writer);

end:
	return ret;
}

/*
 * List agent events for a specific session using the handle.
 *
 * Return CMD_SUCCESS on success else a negative value.
 */
static int list_session_agent_events(void)
{
	int ret = CMD_SUCCESS, count, i;
	struct lttng_event *events = NULL;

	count = lttng_list_events(handle, "", &events);
	if (count < 0) {
		ret = CMD_ERROR;
		ERR("%s", lttng_strerror(count));
		goto error;
	}

	if (lttng_opt_mi) {
		/* Mi print */
		ret = mi_list_session_agent_events(events, count);
		if (ret) {
			ret = CMD_ERROR;
			goto end;
		}
	} else {
		/* Pretty print */
		MSG("Events (Logger name):\n---------------------");
		if (count == 0) {
			MSG("%sNone\n", indent6);
			goto end;
		}

		for (i = 0; i < count; i++) {
			const char *filter_str;
			char *filter_msg = NULL;
			struct lttng_event *event = &events[i];

			ret = lttng_event_get_filter_expression(event,
					&filter_str);
			if (ret) {
				filter_msg = strdup(" [failed to retrieve filter]");
			} else if (filter_str) {
				const char * const filter_fmt =
						" [filter: '%s']";

				filter_msg = malloc(strlen(filter_str) +
						strlen(filter_fmt) + 1);
				if (filter_msg) {
					sprintf(filter_msg, filter_fmt,
							filter_str);
				}
			}

			if (event->loglevel_type !=
					LTTNG_EVENT_LOGLEVEL_ALL) {
				MSG("%s- %s%s (loglevel%s %s)%s", indent4,
						event->name,
						enabled_string(event->enabled),
						logleveltype_string(
							event->loglevel_type),
						mi_lttng_loglevel_string(
							event->loglevel,
							handle->domain.type),
						safe_string(filter_msg));
			} else {
				MSG("%s- %s%s%s", indent4, event->name,
						enabled_string(event->enabled),
						safe_string(filter_msg));
			}
			free(filter_msg);
		}

		MSG("");
	}

end:
	free(events);
error:
	return ret;
}

/*
 * Machine interface
 * print a list of event
 */
static int mi_list_events(struct lttng_event *events, int count)
{
	int ret, i;

	/* Open events element */
	ret = mi_lttng_events_open(writer);
	if (ret) {
		goto end;
	}

	for (i = 0; i < count; i++) {
		ret = mi_lttng_event(writer, &events[i], 0, handle->domain.type);
		if (ret) {
			goto end;
		}
	}

	/* Close events element */
	ret = mi_lttng_writer_close_element(writer);

end:
	return ret;
}

/*
 * List events of channel of session and domain.
 */
static int list_events(const char *channel_name)
{
	int ret = CMD_SUCCESS, count, i;
	struct lttng_event *events = NULL;

	count = lttng_list_events(handle, channel_name, &events);
	if (count < 0) {
		ret = CMD_ERROR;
		ERR("%s", lttng_strerror(count));
		goto error;
	}

	if (lttng_opt_mi) {
		/* Mi print */
		ret = mi_list_events(events, count);
		if (ret) {
			ret = CMD_ERROR;
			goto end;
		}
	} else {
		/* Pretty print */
		MSG("\n%sEvent rules:", indent4);
		if (count == 0) {
			MSG("%sNone\n", indent6);
			goto end;
		}

		for (i = 0; i < count; i++) {
			print_events(&events[i]);
		}

		MSG("");
	}
end:
	free(events);
error:
	return ret;
}

static
void print_timer(const char *timer_name, uint32_t space_count, int64_t value)
{
	uint32_t i;

	_MSG("%s%s:", indent6, timer_name);
	for (i = 0; i < space_count; i++) {
		_MSG(" ");
	}

	if (value) {
		MSG("%" PRId64 " µs", value);
	} else {
		MSG("inactive");
	}
}

/*
 * Pretty print channel
 */
static void print_channel(struct lttng_channel *channel)
{
	int ret;
	uint64_t discarded_events, lost_packets, monitor_timer_interval;
	int64_t blocking_timeout;

	ret = lttng_channel_get_discarded_event_count(channel,
			&discarded_events);
	if (ret) {
		ERR("Failed to retrieve discarded event count of channel");
		return;
	}

	ret = lttng_channel_get_lost_packet_count(channel,
			&lost_packets);
	if (ret) {
		ERR("Failed to retrieve lost packet count of channel");
		return;
	}

	ret = lttng_channel_get_monitor_timer_interval(channel,
			&monitor_timer_interval);
	if (ret) {
		ERR("Failed to retrieve monitor interval of channel");
		return;
	}

	ret = lttng_channel_get_blocking_timeout(channel,
			&blocking_timeout);
	if (ret) {
		ERR("Failed to retrieve blocking timeout of channel");
		return;
	}

	MSG("- %s:%s\n", channel->name, enabled_string(channel->enabled));
	MSG("%sAttributes:", indent4);
	MSG("%sEvent-loss mode:  %s", indent6, channel->attr.overwrite ? "overwrite" : "discard");
	MSG("%sSub-buffer size:  %" PRIu64 " bytes", indent6, channel->attr.subbuf_size);
	MSG("%sSub-buffer count: %" PRIu64, indent6, channel->attr.num_subbuf);

	print_timer("Switch timer", 5, channel->attr.switch_timer_interval);
	print_timer("Read timer",  7, channel->attr.read_timer_interval);
	print_timer("Monitor timer", 4, monitor_timer_interval);

	if (!channel->attr.overwrite) {
		if (blocking_timeout == -1) {
			MSG("%sBlocking timeout: infinite", indent6);
		} else {
			MSG("%sBlocking timeout: %" PRId64 " µs", indent6, blocking_timeout);
		}
	}

	MSG("%sTrace file count: %" PRIu64 " per stream", indent6,
			channel->attr.tracefile_count == 0 ?
				1 : channel->attr.tracefile_count);
	if (channel->attr.tracefile_size != 0 ) {
		MSG("%sTrace file size:  %" PRIu64 " bytes", indent6,
				channel->attr.tracefile_size);
	} else {
		MSG("%sTrace file size:  %s", indent6, "unlimited");
	}
	switch (channel->attr.output) {
		case LTTNG_EVENT_SPLICE:
			MSG("%sOutput mode:      splice", indent6);
			break;
		case LTTNG_EVENT_MMAP:
			MSG("%sOutput mode:      mmap", indent6);
			break;
	}

	MSG("\n%sStatistics:", indent4);
	if (listed_session.snapshot_mode) {
		/*
		 * The lost packet count is omitted for sessions in snapshot
		 * mode as it is misleading: it would indicate the number of
		 * packets that the consumer could not extract during the
		 * course of recording the snapshot. It does not have the
		 * same meaning as the "regular" lost packet count that
		 * would result from the consumer not keeping up with
		 * event production in an overwrite-mode channel.
		 *
		 * A more interesting statistic would be the number of
		 * packets lost between the first and last extracted
		 * packets of a given snapshot (which prevents most analyses).
		 */
		MSG("%sNone", indent6);
		goto skip_stats_printing;
	}

	if (!channel->attr.overwrite) {
		MSG("%sDiscarded events: %" PRIu64, indent6, discarded_events);
	} else {
		MSG("%sLost packets:     %" PRIu64, indent6, lost_packets);
	}
skip_stats_printing:
	return;
}

/*
 * Machine interface
 * Print a list of channel
 *
 */
static int mi_list_channels(struct lttng_channel *channels, int count,
		const char *channel_name)
{
	int i, ret;
	unsigned int chan_found = 0;

	/* Open channels element */
	ret = mi_lttng_channels_open(writer);
	if (ret) {
		goto error;
	}

	for (i = 0; i < count; i++) {
		if (channel_name != NULL) {
			if (strncmp(channels[i].name, channel_name, NAME_MAX) == 0) {
				chan_found = 1;
			} else {
				continue;
			}
		}

		/* Write channel element  and leave it open */
		ret = mi_lttng_channel(writer, &channels[i], 1);
		if (ret) {
			goto error;
		}

		/* Listing events per channel */
		ret = list_events(channels[i].name);
		if (ret) {
			goto error;
		}

		/* Closing the channel element we opened earlier */
		ret = mi_lttng_writer_close_element(writer);
		if (ret) {
			goto error;
		}

		if (chan_found) {
			break;
		}
	}

	/* Close channels element */
	ret = mi_lttng_writer_close_element(writer);
	if (ret) {
		goto error;
	}

error:
	return ret;
}

/*
 * List channel(s) of session and domain.
 *
 * If channel_name is NULL, all channels are listed.
 */
static int list_channels(const char *channel_name)
{
	int count, i, ret = CMD_SUCCESS;
	unsigned int chan_found = 0;
	struct lttng_channel *channels = NULL;

	DBG("Listing channel(s) (%s)", channel_name ? : "<all>");

	count = lttng_list_channels(handle, &channels);
	if (count < 0) {
		switch (-count) {
		case LTTNG_ERR_KERN_CHAN_NOT_FOUND:
			if (lttng_opt_mi) {
				/* When printing mi this is not an error
				 * but an empty channels element */
				count = 0;
			} else {
				ret = CMD_SUCCESS;
				WARN("No kernel channel");
				goto error_channels;
			}
			break;
		default:
			/* We had a real error */
			ret = CMD_ERROR;
			ERR("%s", lttng_strerror(count));
			goto error_channels;
			break;
		}
	}

	if (lttng_opt_mi) {
		/* Mi print */
		ret = mi_list_channels(channels, count, channel_name);
		if (ret) {
			ret = CMD_ERROR;
			goto error;
		}
	} else {
		/* Pretty print */
		if (count) {
			MSG("Channels:\n-------------");
		}

		for (i = 0; i < count; i++) {
			if (channel_name != NULL) {
				if (strncmp(channels[i].name, channel_name, NAME_MAX) == 0) {
					chan_found = 1;
				} else {
					continue;
				}
			}
			print_channel(&channels[i]);

			/* Listing events per channel */
			ret = list_events(channels[i].name);
			if (ret) {
				goto error;
			}

			if (chan_found) {
				break;
			}
		}

		if (!chan_found && channel_name != NULL) {
			ret = CMD_ERROR;
			ERR("Channel %s not found", channel_name);
			goto error;
		}
	}
error:
	free(channels);

error_channels:
	return ret;
}

/*
 * List tracker PID(s) of session and domain.
 */
static int list_tracker_pids(void)
{
	int ret = 0;
	int enabled;
	int *pids = NULL;
	size_t nr_pids;

	ret = lttng_list_tracker_pids(handle,
		&enabled, &pids, &nr_pids);
	if (ret) {
		return ret;
	}
	if (enabled) {
		int i;
		_MSG("PID tracker: [");

		/* Mi tracker_pid element*/
		if (writer) {
			/* Open tracker_pid and targets elements */
			ret = mi_lttng_pid_tracker_open(writer);
			if (ret) {
				goto end;
			}
		}

		for (i = 0; i < nr_pids; i++) {
			if (i) {
				_MSG(",");
			}
			_MSG(" %d", pids[i]);

			/* Mi */
			if (writer) {
				ret = mi_lttng_pid_target(writer, pids[i], 0);
				if (ret) {
					goto end;
				}
			}
		}
		_MSG(" ]\n\n");

		/* Mi close tracker_pid and targets */
		if (writer) {
			ret = mi_lttng_close_multi_element(writer,2);
			if (ret) {
				goto end;
			}
		}
	}
end:
	free(pids);
	return ret;

}

/*
 * List all tracker of a domain
 */
static int list_trackers(void)
{
	int ret;

	/* Trackers listing */
	if (lttng_opt_mi) {
		ret = mi_lttng_trackers_open(writer);
		if (ret) {
			goto end;
		}
	}

	/* pid tracker */
	ret = list_tracker_pids();
	if (ret) {
		goto end;
	}

	if (lttng_opt_mi) {
		/* Close trackers element */
		ret = mi_lttng_writer_close_element(writer);
		if (ret) {
			goto end;
		}
	}

end:
	return ret;
}

/*
 * Machine interface
 * Find the session with session_name as name
 * and print his informations.
 */
static int mi_list_session(const char *session_name,
		struct lttng_session *sessions, int count)
{
	int ret, i;
	unsigned int session_found = 0;

	if (session_name == NULL) {
		ret = -LTTNG_ERR_SESS_NOT_FOUND;
		goto end;
	}

	for (i = 0; i < count; i++) {
		if (strncmp(sessions[i].name, session_name, NAME_MAX) == 0) {
			/* We need to leave it open to append other informations
			 * like domain, channel, events etc.*/
			session_found = 1;
			ret = mi_lttng_session(writer, &sessions[i], 1);
			if (ret) {
				goto end;
			}
			break;
		}
	}

	if (!session_found) {
		ERR("Session '%s' not found", session_name);
		ret = -LTTNG_ERR_SESS_NOT_FOUND;
		goto end;
	}

end:
	return ret;
}

/*
 * Machine interface
 * List all availables session
 */
static int mi_list_sessions(struct lttng_session *sessions, int count)
{
	int ret, i;

	/* Opening sessions element */
	ret = mi_lttng_sessions_open(writer);
	if (ret) {
		goto end;
	}

	/* Listing sessions */
	for (i = 0; i < count; i++) {
		ret = mi_lttng_session(writer, &sessions[i], 0);
		if (ret) {
			goto end;
		}
	}

	/* Closing sessions element */
	ret = mi_lttng_writer_close_element(writer);
	if (ret) {
		goto end;
	}

end:
	return ret;
}

/*
 * List available tracing session. List only basic information.
 *
 * If session_name is NULL, all sessions are listed.
 */
static int list_sessions(const char *session_name)
{
	int ret = CMD_SUCCESS;
	int count, i;
	unsigned int session_found = 0;
	struct lttng_session *sessions;

	count = lttng_list_sessions(&sessions);
	DBG("Session count %d", count);
	if (count < 0) {
		ret = CMD_ERROR;
		ERR("%s", lttng_strerror(count));
		goto end;
	}

	if (lttng_opt_mi) {
		/* Mi */
		if (session_name == NULL) {
			/* List all session */
			ret = mi_list_sessions(sessions, count);
		} else {
			/* Note : this return an open session element */
			ret = mi_list_session(session_name, sessions, count);
		}
		if (ret) {
			ret = CMD_ERROR;
			goto error;
		}
	} else {
		/* Pretty print */
		if (count == 0) {
			MSG("Currently no available tracing session");
			goto end;
		}

		if (session_name == NULL) {
			MSG("Available tracing sessions:");
		}


		for (i = 0; i < count; i++) {
			if (session_name != NULL) {
				if (strncmp(sessions[i].name, session_name, NAME_MAX) == 0) {
					session_found = 1;
					MSG("Tracing session %s: [%s%s]", session_name,
							active_string(sessions[i].enabled),
							snapshot_string(sessions[i].snapshot_mode));
					MSG("%sTrace path: %s\n", indent4, sessions[i].path);
					memcpy(&listed_session, &sessions[i],
							sizeof(listed_session));
					break;
				}
			} else {
				MSG("  %d) %s (%s) [%s%s]", i + 1,
						sessions[i].name, sessions[i].path,
						active_string(sessions[i].enabled),
						snapshot_string(sessions[i].snapshot_mode));
				MSG("%sTrace path: %s", indent4, sessions[i].path);
				if (sessions[i].live_timer_interval != 0) {
					MSG("%sLive timer interval: %u µs", indent4,
							sessions[i].live_timer_interval);
				}
				MSG("");
			}
		}

		if (!session_found && session_name != NULL) {
			ERR("Session '%s' not found", session_name);
			ret = CMD_ERROR;
			goto error;
		}

		if (session_name == NULL) {
			MSG("\nUse lttng list <session_name> for more details");
		}
	}

error:
	free(sessions);
end:
	return ret;
}


/*
 * Machine Interface
 * list available domain(s) for a session.
 */
static int mi_list_domains(struct lttng_domain *domains, int count)
{
	int i, ret;
	/* Open domains element */
	ret = mi_lttng_domains_open(writer);
	if (ret) {
		goto end;
	}

	for (i = 0; i < count; i++) {
		ret = mi_lttng_domain(writer, &domains[i] , 0);
		if (ret) {
			goto end;
		}
	}

	/* Closing domains element */
	ret = mi_lttng_writer_close_element(writer);
	if (ret) {
		goto end;
	}
end:
	return ret;
}

/*
 * List available domain(s) for a session.
 */
static int list_domains(const char *session_name)
{
	int i, count, ret = CMD_SUCCESS;
	struct lttng_domain *domains = NULL;


	count = lttng_list_domains(session_name, &domains);
	if (count < 0) {
		ret = CMD_ERROR;
		ERR("%s", lttng_strerror(count));
		goto end;
	}

	if (lttng_opt_mi) {
		/* Mi output */
		ret = mi_list_domains(domains, count);
		if (ret) {
			ret = CMD_ERROR;
			goto error;
		}
	} else {
		/* Pretty print */
		MSG("Domains:\n-------------");
		if (count == 0) {
			MSG("  None");
			goto end;
		}

		for (i = 0; i < count; i++) {
			switch (domains[i].type) {
			case LTTNG_DOMAIN_KERNEL:
				MSG("  - Kernel");
				break;
			case LTTNG_DOMAIN_UST:
				MSG("  - UST global");
				break;
			case LTTNG_DOMAIN_JUL:
				MSG("  - JUL (Java Util Logging)");
				break;
			case LTTNG_DOMAIN_LOG4J:
				MSG("  - LOG4j (Logging for Java)");
				break;
			case LTTNG_DOMAIN_PYTHON:
				MSG("  - Python (logging)");
				break;
			default:
				break;
			}
		}
	}

error:
	free(domains);

end:
	return ret;
}

/*
 * The 'list <options>' first level command
 */
int cmd_list(int argc, const char **argv)
{
	int opt, ret = CMD_SUCCESS;
	const char *session_name;
	static poptContext pc;
	struct lttng_domain domain;
	struct lttng_domain *domains = NULL;

	memset(&domain, 0, sizeof(domain));

	if (argc < 1) {
		ret = CMD_ERROR;
		goto end;
	}

	pc = poptGetContext(NULL, argc, argv, long_options, 0);
	poptReadDefaultConfig(pc, 0);

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case OPT_HELP:
			SHOW_HELP();
			goto end;
		case OPT_USERSPACE:
			opt_userspace = 1;
			break;
		case OPT_LIST_OPTIONS:
			list_cmd_options(stdout, long_options);
			goto end;
		default:
			ret = CMD_UNDEFINED;
			goto end;
		}
	}

	/* Mi check */
	if (lttng_opt_mi) {
		writer = mi_lttng_writer_create(fileno(stdout), lttng_opt_mi);
		if (!writer) {
			ret = CMD_ERROR;
			goto end;
		}

		/* Open command element */
		ret = mi_lttng_writer_command_open(writer,
				mi_lttng_element_command_list);
		if (ret) {
			ret = CMD_ERROR;
			goto end;
		}

		/* Open output element */
		ret = mi_lttng_writer_open_element(writer,
				mi_lttng_element_command_output);
		if (ret) {
			ret = CMD_ERROR;
			goto end;
		}
	}

	/* Get session name (trailing argument) */
	session_name = poptGetArg(pc);
	DBG2("Session name: %s", session_name);

	if (opt_kernel) {
		domain.type = LTTNG_DOMAIN_KERNEL;
	} else if (opt_userspace) {
		DBG2("Listing userspace global domain");
		domain.type = LTTNG_DOMAIN_UST;
	} else if (opt_jul) {
		DBG2("Listing JUL domain");
		domain.type = LTTNG_DOMAIN_JUL;
	} else if (opt_log4j) {
		domain.type = LTTNG_DOMAIN_LOG4J;
	} else if (opt_python) {
		domain.type = LTTNG_DOMAIN_PYTHON;
	}

	if (!opt_kernel && opt_syscall) {
		WARN("--syscall will only work with the Kernel domain (-k)");
		ret = CMD_ERROR;
		goto end;
	}

	if (opt_kernel || opt_userspace || opt_jul || opt_log4j || opt_python) {
		handle = lttng_create_handle(session_name, &domain);
		if (handle == NULL) {
			ret = CMD_FATAL;
			goto end;
		}
	}

	if (session_name == NULL) {
		if (!opt_kernel && !opt_userspace && !opt_jul && !opt_log4j
				&& !opt_python) {
			ret = list_sessions(NULL);
			if (ret) {
				goto end;
			}
		}
		if (opt_kernel) {
			if (opt_syscall) {
				ret = list_syscalls();
				if (ret) {
					goto end;
				}
			} else {
				ret = list_kernel_events();
				if (ret) {
					goto end;
				}
			}
		}
		if (opt_userspace) {
			if (opt_fields) {
				ret = list_ust_event_fields();
			} else {
				ret = list_ust_events();
			}
			if (ret) {
				goto end;
			}
		}
		if (opt_jul || opt_log4j || opt_python) {
			ret = list_agent_events();
			if (ret) {
				goto end;
			}
		}
	} else {
		/* List session attributes */
		if (lttng_opt_mi) {
			/* Open element sessions
			 * Present for xml consistency */
			ret = mi_lttng_sessions_open(writer);
			if (ret) {
				goto end;
			}
		}
		/* MI: the ouptut of list_sessions is an unclosed session element */
		ret = list_sessions(session_name);
		if (ret) {
			goto end;
		}

		/* Domain listing */
		if (opt_domain) {
			ret = list_domains(session_name);
			goto end;
		}

		/* Channel listing */
		if (opt_kernel || opt_userspace) {
			if (lttng_opt_mi) {
				/* Add of domains and domain element for xml
				 * consistency and validation
				 */
				ret = mi_lttng_domains_open(writer);
				if (ret) {
					goto end;
				}

				/* Open domain and leave it open for
				 * nested channels printing */
				ret = mi_lttng_domain(writer, &domain, 1);
				if (ret) {
					goto end;
				}

			}


			/* Trackers */
			ret = list_trackers();
			if (ret) {
				goto end;
			}

			/* Channels */
			ret = list_channels(opt_channel);
			if (ret) {
				goto end;
			}

			if (lttng_opt_mi) {
				/* Close domain and domain element */
				ret = mi_lttng_close_multi_element(writer, 2);
			}
			if (ret) {
				goto end;
			}


		} else {
			int i, nb_domain;

			/* We want all domain(s) */
			nb_domain = lttng_list_domains(session_name, &domains);
			if (nb_domain < 0) {
				ret = CMD_ERROR;
				ERR("%s", lttng_strerror(nb_domain));
				goto end;
			}

			if (lttng_opt_mi) {
				ret = mi_lttng_domains_open(writer);
				if (ret) {
					ret = CMD_ERROR;
					goto end;
				}
			}

			for (i = 0; i < nb_domain; i++) {
				switch (domains[i].type) {
				case LTTNG_DOMAIN_KERNEL:
					MSG("=== Domain: Kernel ===\n");
					break;
				case LTTNG_DOMAIN_UST:
					MSG("=== Domain: UST global ===\n");
					MSG("Buffer type: %s\n",
							domains[i].buf_type ==
							LTTNG_BUFFER_PER_PID ? "per PID" : "per UID");
					break;
				case LTTNG_DOMAIN_JUL:
					MSG("=== Domain: JUL (Java Util Logging) ===\n");
					break;
				case LTTNG_DOMAIN_LOG4J:
					MSG("=== Domain: LOG4j (Logging for Java) ===\n");
					break;
				case LTTNG_DOMAIN_PYTHON:
					MSG("=== Domain: Python (logging) ===\n");
					break;
				default:
					MSG("=== Domain: Unimplemented ===\n");
					break;
				}

				if (lttng_opt_mi) {
					ret = mi_lttng_domain(writer, &domains[i], 1);
					if (ret) {
						ret = CMD_ERROR;
						goto end;
					}
				}

				/* Clean handle before creating a new one */
				if (handle) {
					lttng_destroy_handle(handle);
				}

				handle = lttng_create_handle(session_name, &domains[i]);
				if (handle == NULL) {
					ret = CMD_FATAL;
					goto end;
				}

				if (domains[i].type == LTTNG_DOMAIN_JUL ||
						domains[i].type == LTTNG_DOMAIN_LOG4J ||
						domains[i].type == LTTNG_DOMAIN_PYTHON) {
					ret = list_session_agent_events();
					if (ret) {
						goto end;
					}

					goto next_domain;
				}

				switch (domains[i].type) {
				case LTTNG_DOMAIN_KERNEL:
				case LTTNG_DOMAIN_UST:
					ret = list_trackers();
					if (ret) {
						goto end;
					}
					break;
				default:
					break;
				}

				ret = list_channels(opt_channel);
				if (ret) {
					goto end;
				}

next_domain:
				if (lttng_opt_mi) {
					/* Close domain element */
					ret = mi_lttng_writer_close_element(writer);
					if (ret) {
						ret = CMD_ERROR;
						goto end;
					}
				}

			}
			if (lttng_opt_mi) {
				/* Close the domains, session and sessions element */
				ret = mi_lttng_close_multi_element(writer, 3);
				if (ret) {
					ret = CMD_ERROR;
					goto end;
				}
			}
		}
	}

	/* Mi closing */
	if (lttng_opt_mi) {
		/* Close  output element */
		ret = mi_lttng_writer_close_element(writer);
		if (ret) {
			ret = CMD_ERROR;
			goto end;
		}

		/* Command element close */
		ret = mi_lttng_writer_command_close(writer);
		if (ret) {
			ret = CMD_ERROR;
			goto end;
		}
	}
end:
	/* Mi clean-up */
	if (writer && mi_lttng_writer_destroy(writer)) {
		/* Preserve original error code */
		ret = ret ? ret : -LTTNG_ERR_MI_IO_FAIL;
	}

	free(domains);
	if (handle) {
		lttng_destroy_handle(handle);
	}

	poptFreeContext(pc);
	return ret;
}
