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
#include <inttypes.h>
#include <popt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "../command.h"

static int opt_userspace;
static int opt_kernel;
static int opt_jul;
static char *opt_channel;
static int opt_domain;
static int opt_fields;
#if 0
/* Not implemented yet */
static char *opt_cmd_name;
static pid_t opt_pid;
#endif

const char *indent4 = "    ";
const char *indent6 = "      ";
const char *indent8 = "        ";

enum {
	OPT_HELP = 1,
	OPT_USERSPACE,
	OPT_LIST_OPTIONS,
};

static struct lttng_handle *handle;

static struct poptOption long_options[] = {
	/* longName, shortName, argInfo, argPtr, value, descrip, argDesc */
	{"help",      'h', POPT_ARG_NONE, 0, OPT_HELP, 0, 0},
	{"kernel",    'k', POPT_ARG_VAL, &opt_kernel, 1, 0, 0},
	{"jul",       'j', POPT_ARG_VAL, &opt_jul, 1, 0, 0},
#if 0
	/* Not implemented yet */
	{"userspace",      'u', POPT_ARG_STRING | POPT_ARGFLAG_OPTIONAL, &opt_cmd_name, OPT_USERSPACE, 0, 0},
	{"pid",            'p', POPT_ARG_INT, &opt_pid, 0, 0, 0},
#else
	{"userspace",      'u', POPT_ARG_NONE, 0, OPT_USERSPACE, 0, 0},
#endif
	{"channel",   'c', POPT_ARG_STRING, &opt_channel, 0, 0, 0},
	{"domain",    'd', POPT_ARG_VAL, &opt_domain, 1, 0, 0},
	{"fields",    'f', POPT_ARG_VAL, &opt_fields, 1, 0, 0},
	{"list-options", 0, POPT_ARG_NONE, NULL, OPT_LIST_OPTIONS, NULL, NULL},
	{0, 0, 0, 0, 0, 0, 0}
};

/*
 * usage
 */
static void usage(FILE *ofp)
{
	fprintf(ofp, "usage: lttng list [OPTIONS] [SESSION [SESSION OPTIONS]]\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "With no arguments, list available tracing session(s)\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Without a session, -k lists available kernel events\n");
	fprintf(ofp, "Without a session, -u lists available userspace events\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "  -h, --help              Show this help\n");
	fprintf(ofp, "      --list-options      Simple listing of options\n");
	fprintf(ofp, "  -k, --kernel            Select kernel domain\n");
	fprintf(ofp, "  -u, --userspace         Select user-space domain.\n");
	fprintf(ofp, "  -j, --jul               Apply for Java application using JUL\n");
	fprintf(ofp, "  -f, --fields            List event fields.\n");
#if 0
	fprintf(ofp, "  -p, --pid PID           List user-space events by PID\n");
#endif
	fprintf(ofp, "\n");
	fprintf(ofp, "Session Options:\n");
	fprintf(ofp, "  -c, --channel NAME      List details of a channel\n");
	fprintf(ofp, "  -d, --domain            List available domain(s)\n");
	fprintf(ofp, "\n");
}

/*
 * Get command line from /proc for a specific pid.
 *
 * On success, return an allocated string pointer to the proc cmdline.
 * On error, return NULL.
 */
static char *get_cmdline_by_pid(pid_t pid)
{
	int ret;
	FILE *fp;
	char *cmdline = NULL;
	char path[24];	/* Can't go bigger than /proc/65535/cmdline */

	snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
	fp = fopen(path, "r");
	if (fp == NULL) {
		goto end;
	}

	/* Caller must free() *cmdline */
	cmdline = malloc(PATH_MAX);
	ret = fread(cmdline, 1, PATH_MAX, fp);
	if (ret < 0) {
		perror("fread proc list");
	}
	fclose(fp);

end:
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
const char *filter_string(int value)
{
	switch (value) {
	case 1:	return " [with filter]";
	default: return "";
	}
}

static
const char *exclusion_string(int value)
{
	switch (value) {
	case 1: return " [has exclusions]";
	default: return "";
	}
}

static const char *loglevel_string(int value)
{
	switch (value) {
	case -1:
		return "";
	case LTTNG_LOGLEVEL_EMERG:
		return "TRACE_EMERG";
	case LTTNG_LOGLEVEL_ALERT:
		return "TRACE_ALERT";
	case LTTNG_LOGLEVEL_CRIT:
		return "TRACE_CRIT";
	case LTTNG_LOGLEVEL_ERR:
		return "TRACE_ERR";
	case LTTNG_LOGLEVEL_WARNING:
		return "TRACE_WARNING";
	case LTTNG_LOGLEVEL_NOTICE:
		return "TRACE_NOTICE";
	case LTTNG_LOGLEVEL_INFO:
		return "TRACE_INFO";
	case LTTNG_LOGLEVEL_DEBUG_SYSTEM:
		return "TRACE_DEBUG_SYSTEM";
	case LTTNG_LOGLEVEL_DEBUG_PROGRAM:
		return "TRACE_DEBUG_PROGRAM";
	case LTTNG_LOGLEVEL_DEBUG_PROCESS:
		return "TRACE_DEBUG_PROCESS";
	case LTTNG_LOGLEVEL_DEBUG_MODULE:
		return "TRACE_DEBUG_MODULE";
	case LTTNG_LOGLEVEL_DEBUG_UNIT:
		return "TRACE_DEBUG_UNIT";
	case LTTNG_LOGLEVEL_DEBUG_FUNCTION:
		return "TRACE_DEBUG_FUNCTION";
	case LTTNG_LOGLEVEL_DEBUG_LINE:
		return "TRACE_DEBUG_LINE";
	case LTTNG_LOGLEVEL_DEBUG:
		return "TRACE_DEBUG";
	default:
		return "<<UNKNOWN>>";
	}
}

/*
 * Pretty print single event.
 */
static void print_events(struct lttng_event *event)
{
	switch (event->type) {
	case LTTNG_EVENT_TRACEPOINT:
	{
		if (event->loglevel != -1) {
			MSG("%s%s (loglevel: %s (%d)) (type: tracepoint)%s%s%s",
				indent6,
				event->name,
				loglevel_string(event->loglevel),
				event->loglevel,
				enabled_string(event->enabled),
				exclusion_string(event->exclusion),
				filter_string(event->filter));
		} else {
			MSG("%s%s (type: tracepoint)%s%s%s",
				indent6,
				event->name,
				enabled_string(event->enabled),
				exclusion_string(event->exclusion),
				filter_string(event->filter));
		}
		break;
	}
	case LTTNG_EVENT_FUNCTION:
		MSG("%s%s (type: function)%s%s", indent6,
				event->name, enabled_string(event->enabled),
				filter_string(event->filter));
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
				filter_string(event->filter));
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
				filter_string(event->filter));
		MSG("%ssymbol: \"%s\"", indent8, event->attr.ftrace.symbol_name);
		break;
	case LTTNG_EVENT_SYSCALL:
		MSG("%ssyscalls (type: syscall)%s%s", indent6,
				enabled_string(event->enabled),
				filter_string(event->filter));
		break;
	case LTTNG_EVENT_NOOP:
		MSG("%s (type: noop)%s%s", indent6,
				enabled_string(event->enabled),
				filter_string(event->filter));
		break;
	case LTTNG_EVENT_ALL:
		/* We should never have "all" events in list. */
		assert(0);
		break;
	}
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

static int list_jul_events(void)
{
	int i, size;
	struct lttng_domain domain;
	struct lttng_handle *handle;
	struct lttng_event *event_list;
	pid_t cur_pid = 0;
	char *cmdline = NULL;

	DBG("Getting JUL tracing events");

	memset(&domain, 0, sizeof(domain));
	domain.type = LTTNG_DOMAIN_JUL;

	handle = lttng_create_handle(NULL, &domain);
	if (handle == NULL) {
		goto error;
	}

	size = lttng_list_tracepoints(handle, &event_list);
	if (size < 0) {
		ERR("Unable to list JUL events: %s", lttng_strerror(size));
		lttng_destroy_handle(handle);
		return size;
	}

	MSG("JUL events (Logger name):\n-------------------------");

	if (size == 0) {
		MSG("None");
	}

	for (i = 0; i < size; i++) {
		if (cur_pid != event_list[i].pid) {
			cur_pid = event_list[i].pid;
			cmdline = get_cmdline_by_pid(cur_pid);
			MSG("\nPID: %d - Name: %s", cur_pid, cmdline);
			free(cmdline);
		}
		MSG("%s- %s", indent6, event_list[i].name);
	}

	MSG("");

	free(event_list);
	lttng_destroy_handle(handle);

	return CMD_SUCCESS;

error:
	lttng_destroy_handle(handle);
	return -1;
}

/*
 * Ask session daemon for all user space tracepoints available.
 */
static int list_ust_events(void)
{
	int i, size;
	struct lttng_domain domain;
	struct lttng_handle *handle;
	struct lttng_event *event_list;
	pid_t cur_pid = 0;
	char *cmdline = NULL;

	memset(&domain, 0, sizeof(domain));

	DBG("Getting UST tracing events");

	domain.type = LTTNG_DOMAIN_UST;

	handle = lttng_create_handle(NULL, &domain);
	if (handle == NULL) {
		goto error;
	}

	size = lttng_list_tracepoints(handle, &event_list);
	if (size < 0) {
		ERR("Unable to list UST events: %s", lttng_strerror(size));
		lttng_destroy_handle(handle);
		return size;
	}

	MSG("UST events:\n-------------");

	if (size == 0) {
		MSG("None");
	}

	for (i = 0; i < size; i++) {
		if (cur_pid != event_list[i].pid) {
			cur_pid = event_list[i].pid;
			cmdline = get_cmdline_by_pid(cur_pid);
			MSG("\nPID: %d - Name: %s", cur_pid, cmdline);
			free(cmdline);
		}
		print_events(&event_list[i]);
	}

	MSG("");

	free(event_list);
	lttng_destroy_handle(handle);

	return CMD_SUCCESS;

error:
	lttng_destroy_handle(handle);
	return -1;
}

/*
 * Ask session daemon for all user space tracepoint fields available.
 */
static int list_ust_event_fields(void)
{
	int i, size;
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
		goto error;
	}

	size = lttng_list_tracepoint_fields(handle, &event_field_list);
	if (size < 0) {
		ERR("Unable to list UST event fields: %s", lttng_strerror(size));
		lttng_destroy_handle(handle);
		return size;
	}

	MSG("UST events:\n-------------");

	if (size == 0) {
		MSG("None");
	}

	for (i = 0; i < size; i++) {
		if (cur_pid != event_field_list[i].event.pid) {
			cur_pid = event_field_list[i].event.pid;
			cmdline = get_cmdline_by_pid(cur_pid);
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

	free(event_field_list);
	lttng_destroy_handle(handle);

	return CMD_SUCCESS;

error:
	lttng_destroy_handle(handle);
	return -1;
}

/*
 * Ask for all trace events in the kernel and pretty print them.
 */
static int list_kernel_events(void)
{
	int i, size;
	struct lttng_domain domain;
	struct lttng_handle *handle;
	struct lttng_event *event_list;

	memset(&domain, 0, sizeof(domain));

	DBG("Getting kernel tracing events");

	domain.type = LTTNG_DOMAIN_KERNEL;

	handle = lttng_create_handle(NULL, &domain);
	if (handle == NULL) {
		goto error;
	}

	size = lttng_list_tracepoints(handle, &event_list);
	if (size < 0) {
		ERR("Unable to list kernel events: %s", lttng_strerror(size));
		lttng_destroy_handle(handle);
		return size;
	}

	MSG("Kernel events:\n-------------");

	for (i = 0; i < size; i++) {
		print_events(&event_list[i]);
	}

	MSG("");

	free(event_list);

	lttng_destroy_handle(handle);
	return CMD_SUCCESS;

error:
	lttng_destroy_handle(handle);
	return -1;
}

/*
 * List JUL events for a specific session using the handle.
 *
 * Return CMD_SUCCESS on success else a negative value.
 */
static int list_session_jul_events(void)
{
	int ret, count, i;
	struct lttng_event *events = NULL;

	count = lttng_list_events(handle, "", &events);
	if (count < 0) {
		ret = count;
		ERR("%s", lttng_strerror(ret));
		goto error;
	}

	MSG("Events (Logger name):\n---------------------");
	if (count == 0) {
		MSG("%sNone\n", indent6);
		goto end;
	}

	for (i = 0; i < count; i++) {
		MSG("%s- %s%s", indent4, events[i].name,
				enabled_string(events[i].enabled));
	}

	MSG("");

end:
	free(events);
	ret = CMD_SUCCESS;

error:
	return ret;
}

/*
 * List events of channel of session and domain.
 */
static int list_events(const char *channel_name)
{
	int ret, count, i;
	struct lttng_event *events = NULL;

	count = lttng_list_events(handle, channel_name, &events);
	if (count < 0) {
		ret = count;
		ERR("%s", lttng_strerror(ret));
		goto error;
	}

	MSG("\n%sEvents:", indent4);
	if (count == 0) {
		MSG("%sNone\n", indent6);
		goto end;
	}

	for (i = 0; i < count; i++) {
		print_events(&events[i]);
	}

	MSG("");

end:
	free(events);
	ret = CMD_SUCCESS;

error:
	return ret;
}

/*
 * Pretty print channel
 */
static void print_channel(struct lttng_channel *channel)
{
	MSG("- %s:%s\n", channel->name, enabled_string(channel->enabled));

	MSG("%sAttributes:", indent4);
	MSG("%soverwrite mode: %d", indent6, channel->attr.overwrite);
	MSG("%ssubbufers size: %" PRIu64, indent6, channel->attr.subbuf_size);
	MSG("%snumber of subbufers: %" PRIu64, indent6, channel->attr.num_subbuf);
	MSG("%sswitch timer interval: %u", indent6, channel->attr.switch_timer_interval);
	MSG("%sread timer interval: %u", indent6, channel->attr.read_timer_interval);
	switch (channel->attr.output) {
		case LTTNG_EVENT_SPLICE:
			MSG("%soutput: splice()", indent6);
			break;
		case LTTNG_EVENT_MMAP:
			MSG("%soutput: mmap()", indent6);
			break;
	}
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
			ret = CMD_SUCCESS;
			WARN("No kernel channel");
			break;
		default:
			/* We had a real error */
			ret = count;
			ERR("%s", lttng_strerror(ret));
			break;
		}
		goto error_channels;
	}

	if (channel_name == NULL) {
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
		if (ret < 0) {
			ERR("%s", lttng_strerror(ret));
		}

		if (chan_found) {
			break;
		}
	}

	if (!chan_found && channel_name != NULL) {
		ERR("Channel %s not found", channel_name);
		goto error;
	}

	ret = CMD_SUCCESS;

error:
	free(channels);

error_channels:
	return ret;
}

/*
 * List available tracing session. List only basic information.
 *
 * If session_name is NULL, all sessions are listed.
 */
static int list_sessions(const char *session_name)
{
	int ret, count, i;
	unsigned int session_found = 0;
	struct lttng_session *sessions;

	count = lttng_list_sessions(&sessions);
	DBG("Session count %d", count);
	if (count < 0) {
		ret = count;
		ERR("%s", lttng_strerror(ret));
		goto error;
	} else if (count == 0) {
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
				break;
			}
		} else {
			MSG("  %d) %s (%s) [%s%s]", i + 1, sessions[i].name, sessions[i].path,
					active_string(sessions[i].enabled),
					snapshot_string(sessions[i].snapshot_mode));
		}
	}

	free(sessions);

	if (!session_found && session_name != NULL) {
		ERR("Session '%s' not found", session_name);
		ret = CMD_ERROR;
		goto error;
	}

	if (session_name == NULL) {
		MSG("\nUse lttng list <session_name> for more details");
	}

end:
	return CMD_SUCCESS;

error:
	return ret;
}

/*
 * List available domain(s) for a session.
 */
static int list_domains(const char *session_name)
{
	int i, count, ret = CMD_SUCCESS;
	struct lttng_domain *domains = NULL;

	MSG("Domains:\n-------------");

	count = lttng_list_domains(session_name, &domains);
	if (count < 0) {
		ret = count;
		ERR("%s", lttng_strerror(ret));
		goto error;
	} else if (count == 0) {
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
		default:
			break;
		}
	}

end:
	free(domains);

error:
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
		usage(stderr);
		ret = CMD_ERROR;
		goto end;
	}

	pc = poptGetContext(NULL, argc, argv, long_options, 0);
	poptReadDefaultConfig(pc, 0);

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case OPT_HELP:
			usage(stdout);
			goto end;
		case OPT_USERSPACE:
			opt_userspace = 1;
			break;
		case OPT_LIST_OPTIONS:
			list_cmd_options(stdout, long_options);
			goto end;
		default:
			usage(stderr);
			ret = CMD_UNDEFINED;
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
	}

	if (opt_kernel || opt_userspace || opt_jul) {
		handle = lttng_create_handle(session_name, &domain);
		if (handle == NULL) {
			ret = CMD_FATAL;
			goto end;
		}
	}

	if (session_name == NULL) {
		if (!opt_kernel && !opt_userspace && !opt_jul) {
			ret = list_sessions(NULL);
			if (ret != 0) {
				goto end;
			}
		}
		if (opt_kernel) {
			ret = list_kernel_events();
			if (ret < 0) {
				ret = CMD_ERROR;
				goto end;
			}
		}
		if (opt_userspace) {
			if (opt_fields) {
				ret = list_ust_event_fields();
			} else {
				ret = list_ust_events();
			}
			if (ret < 0) {
				ret = CMD_ERROR;
				goto end;
			}
		}
		if (opt_jul) {
			ret = list_jul_events();
			if (ret < 0) {
				ret = CMD_ERROR;
				goto end;
			}
		}
	} else {
		/* List session attributes */
		ret = list_sessions(session_name);
		if (ret != 0) {
			goto end;
		}

		/* Domain listing */
		if (opt_domain) {
			ret = list_domains(session_name);
			goto end;
		}

		if (opt_kernel) {
			/* Channel listing */
			ret = list_channels(opt_channel);
			if (ret < 0) {
				goto end;
			}
		} else {
			int i, nb_domain;

			/* We want all domain(s) */
			nb_domain = lttng_list_domains(session_name, &domains);
			if (nb_domain < 0) {
				ret = nb_domain;
				ERR("%s", lttng_strerror(ret));
				goto end;
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
				default:
					MSG("=== Domain: Unimplemented ===\n");
					break;
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

				if (domains[i].type == LTTNG_DOMAIN_JUL) {
					ret = list_session_jul_events();
					if (ret < 0) {
						goto end;
					}
					continue;
				}

				ret = list_channels(opt_channel);
				if (ret < 0) {
					goto end;
				}
			}
		}
	}

end:
	free(domains);
	if (handle) {
		lttng_destroy_handle(handle);
	}

	poptFreeContext(pc);
	return ret;
}
