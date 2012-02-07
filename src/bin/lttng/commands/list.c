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
#include <inttypes.h>
#include <popt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "../command.h"

static int opt_userspace;
static int opt_kernel;
static char *opt_channel;
static int opt_domain;
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
#if 0
	/* Not implemented yet */
	{"userspace",      'u', POPT_ARG_STRING | POPT_ARGFLAG_OPTIONAL, &opt_cmd_name, OPT_USERSPACE, 0, 0},
	{"pid",            'p', POPT_ARG_INT, &opt_pid, 0, 0, 0},
#else
	{"userspace",      'u', POPT_ARG_NONE, 0, OPT_USERSPACE, 0, 0},
#endif
	{"channel",   'c', POPT_ARG_STRING, &opt_channel, 0, 0, 0},
	{"domain",    'd', POPT_ARG_VAL, &opt_domain, 1, 0, 0},
	{"list-options", 0, POPT_ARG_NONE, NULL, OPT_LIST_OPTIONS, NULL, NULL},
	{0, 0, 0, 0, 0, 0, 0}
};

/*
 * usage
 */
static void usage(FILE *ofp)
{
	fprintf(ofp, "usage: lttng list [OPTIONS] [SESSION [<OPTIONS>]]\n");
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
	case 0:	return " [inactive]";
	case 1: return " [active]";
	case -1: return "";
	default: return NULL;
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
const char *loglevel_string_pre(int loglevel)
{
	if (loglevel == -1) {
		return "";
	} else {
		return " (loglevel: ";
	}
}

static
const char *loglevel_string_post(int loglevel)
{
	if (loglevel == -1) {
		return "";
	} else {
		return ")";
	}
}

static const char *loglevel_string(int value)
{
	switch (value) {
	case -1: return "";
	case 0: return "TRACE_EMERG";
	case 1: return "TRACE_ALERT";
	case 2: return "TRACE_CRIT";
	case 3: return "TRACE_ERR";
	case 4: return "TRACE_WARNING";
	case 5: return "TRACE_NOTICE";
	case 6: return "TRACE_INFO";
	case 7: return "TRACE_SYSTEM";
	case 8: return "TRACE_PROGRAM";
	case 9: return "TRACE_PROCESS";
	case 10: return "TRACE_MODULE";
	case 11: return "TRACE_UNIT";
	case 12: return "TRACE_FUNCTION";
	case 13: return "TRACE_DEFAULT";
	case 14: return "TRACE_VERBOSE";
	case 15: return "TRACE_DEBUG";
	default: return "<<UNKNOWN>>";
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
		MSG("%s%s%s%s%s (type: tracepoint)%s", indent6,
				event->name,
				loglevel_string_pre(event->loglevel),
				loglevel_string(event->loglevel),
				loglevel_string_post(event->loglevel),
				enabled_string(event->enabled));
		break;
	}
	case LTTNG_EVENT_PROBE:
		MSG("%s%s (type: probe)%s", indent6,
				event->name, enabled_string(event->enabled));
		if (event->attr.probe.addr != 0) {
			MSG("%saddr: 0x%" PRIx64, indent8, event->attr.probe.addr);
		} else {
			MSG("%soffset: 0x%" PRIx64, indent8, event->attr.probe.offset);
			MSG("%ssymbol: %s", indent8, event->attr.probe.symbol_name);
		}
		break;
	case LTTNG_EVENT_FUNCTION:
	case LTTNG_EVENT_FUNCTION_ENTRY:
		MSG("%s%s (type: function)%s", indent6,
				event->name, enabled_string(event->enabled));
		MSG("%ssymbol: \"%s\"", indent8, event->attr.ftrace.symbol_name);
		break;
	case LTTNG_EVENT_SYSCALL:
		MSG("%s (type: syscall)%s", indent6,
				enabled_string(event->enabled));
		break;
	case LTTNG_EVENT_NOOP:
		MSG("%s (type: noop)%s", indent6,
				enabled_string(event->enabled));
		break;
	case LTTNG_EVENT_ALL:
		/* We should never have "all" events in list. */
		assert(0);
		break;
	}
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

	memset(&domain, 0, sizeof(domain));

	DBG("Getting UST tracing events");

	domain.type = LTTNG_DOMAIN_UST;

	handle = lttng_create_handle(NULL, &domain);
	if (handle == NULL) {
		goto error;
	}

	size = lttng_list_tracepoints(handle, &event_list);
	if (size < 0) {
		ERR("Unable to list UST events");
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
			MSG("\nPID: %d - Name: %s", cur_pid, get_cmdline_by_pid(cur_pid));
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
		ERR("Unable to list kernel events");
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
 * List events of channel of session and domain.
 */
static int list_events(const char *channel_name)
{
	int ret, count, i;
	struct lttng_event *events = NULL;

	count = lttng_list_events(handle, channel_name, &events);
	if (count < 0) {
		ret = count;
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
	if (events) {
		free(events);
	}
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
		ret = count;
		goto error_channels;
	} else if (count == 0) {
		ERR("Channel %s not found", channel_name);
		goto error;
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
			MSG("%s", lttng_strerror(ret));
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
		goto error;
	}

	if (session_name == NULL) {
		MSG("Available tracing sessions:");
	}

	for (i = 0; i < count; i++) {
		if (session_name != NULL) {
			if (strncmp(sessions[i].name, session_name, NAME_MAX) == 0) {
				session_found = 1;
				MSG("Tracing session %s:%s", session_name, active_string(sessions[i].enabled));
				MSG("%sTrace path: %s\n", indent4, sessions[i].path);
				break;
			}
			continue;
		}

		MSG("  %d) %s (%s)%s", i + 1, sessions[i].name, sessions[i].path,
				active_string(sessions[i].enabled));

		if (session_found) {
			break;
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
	int opt, i, ret = CMD_SUCCESS;
	int nb_domain;
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
	} else {
		usage(stderr);
		ret = CMD_UNDEFINED;
		goto end;
	}

	handle = lttng_create_handle(session_name, &domain);
	if (handle == NULL) {
		ret = CMD_FATAL;
		goto end;
	}

	if (session_name == NULL) {
		if (!opt_kernel && !opt_userspace) {
			ret = list_sessions(NULL);
			if (ret != 0) {
				goto end;
			}
		}
		if (opt_kernel) {
			ret = list_kernel_events();
			if (ret < 0) {
				goto end;
			}
		}
		if (opt_userspace) {
			ret = list_ust_events();
			if (ret < 0) {
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
			/* We want all domain(s) */
			nb_domain = lttng_list_domains(session_name, &domains);
			if (nb_domain < 0) {
				ret = nb_domain;
				goto end;
			}

			for (i = 0; i < nb_domain; i++) {
				switch (domains[i].type) {
				case LTTNG_DOMAIN_KERNEL:
					MSG("=== Domain: Kernel ===\n");
					break;
				case LTTNG_DOMAIN_UST:
					MSG("=== Domain: UST global ===\n");
					break;
				default:
					MSG("=== Domain: Unimplemented ===\n");
					break;
				}

				/* Clean handle before creating a new one */
				lttng_destroy_handle(handle);

				handle = lttng_create_handle(session_name, &domains[i]);
				if (handle == NULL) {
					ret = CMD_FATAL;
					goto end;
				}

				ret = list_channels(opt_channel);
				if (ret < 0) {
					goto end;
				}
			}
		}
	}

end:
	if (domains) {
		free(domains);
	}
	lttng_destroy_handle(handle);

	poptFreeContext(pc);
	return ret;
}
