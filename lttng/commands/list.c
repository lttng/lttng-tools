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

#include "../cmd.h"

static int opt_pid;
static int opt_userspace;
static int opt_kernel;
static char *opt_channel;
static int opt_domain;

const char *indent4 = "    ";
const char *indent6 = "      ";
const char *indent8 = "        ";

enum {
	OPT_HELP = 1,
};

static struct poptOption long_options[] = {
	/* longName, shortName, argInfo, argPtr, value, descrip, argDesc */
	{"help",      'h', POPT_ARG_NONE, 0, OPT_HELP, 0, 0},
	{"kernel",    'k', POPT_ARG_VAL, &opt_kernel, 1, 0, 0},
	{"userspace", 'u', POPT_ARG_VAL, &opt_userspace, 1, 0, 0},
	{"pid",       'p', POPT_ARG_INT, &opt_pid, 0, 0, 0},
	{"channel",   'c', POPT_ARG_STRING, &opt_channel, 0, 0, 0},
	{"domain",    'd', POPT_ARG_VAL, &opt_domain, 1, 0, 0},
	{0, 0, 0, 0, 0, 0, 0}
};

/*
 * usage
 */
static void usage(FILE *ofp)
{
	fprintf(ofp, "usage: lttng list [[-k] [-u] [-p PID] [SESSION [<options>]]]\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "With no arguments, list available tracing session(s)\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "With -k alone, list available kernel events\n");
	fprintf(ofp, "With -u alone, list available userspace events\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "  -h, --help              Show this help\n");
	fprintf(ofp, "  -k, --kernel            Select kernel domain\n");
	fprintf(ofp, "  -u, --userspace         Select user-space domain.\n");
	fprintf(ofp, "  -p, --pid PID           List user-space events by PID\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Options:\n");
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
#ifdef DISABLE
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
#endif /* DISABLE */

/*
 * Ask for all trace events in the kernel and pretty print them.
 */
static int list_kernel_events(void)
{
	int i, size;
	struct lttng_event *event_list;

	DBG("Getting all tracing events");

	size = lttng_list_kernel_events(&event_list);
	if (size < 0) {
		ERR("Unable to list kernel events");
		return size;
	}

	MSG("Kernel events:\n-------------");

	for (i = 0; i < size; i++) {
		MSG("  %s", event_list[i].name);
	}

	free(event_list);

	return CMD_SUCCESS;
}

/*
 * List events of channel of session and domain.
 */
static int list_events(struct lttng_domain *dom,
		const char *session_name, const char *channel_name)
{
	int ret, count, i;
	struct lttng_event *events = NULL;

	count = lttng_list_events(dom, session_name, channel_name, &events);
	if (count < 0) {
		ret = count;
		goto error;
	}

	MSG("\n%sEvents:", indent4);
	if (count == 0) {
		MSG("%sNone", indent6);
		goto end;
	}

	for (i = 0; i < count; i++) {
		switch (events[i].type) {
			case LTTNG_EVENT_TRACEPOINT:
				MSG("%s%s (type: tracepoint) [enabled: %d]", indent6,
						events[i].name, events[i].enabled);
				break;
			case LTTNG_EVENT_PROBE:
				MSG("%s%s (type: probe) [enabled: %d]", indent6,
						events[i].name, events[i].enabled);
				if (events[i].attr.probe.addr != 0) {
					MSG("%saddr: 0x%" PRIx64, indent8, events[i].attr.probe.addr);
				} else {
					MSG("%soffset: 0x%" PRIx64, indent8, events[i].attr.probe.offset);
					MSG("%ssymbol: %s", indent8, events[i].attr.probe.symbol_name);
				}
				break;
			case LTTNG_EVENT_FUNCTION:
			case LTTNG_EVENT_FUNCTION_ENTRY:
				MSG("%s%s (type: function) [enabled: %d]", indent6,
						events[i].name, events[i].enabled);
				MSG("%ssymbol: \"%s\"", indent8, events[i].attr.ftrace.symbol_name);
				break;
		}
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
	MSG("- %s (enabled: %d):\n", channel->name, channel->enabled);

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
static int list_channels(struct lttng_domain *dom,
		const char *session_name, const char *channel_name)
{
	int count, i, ret = CMD_SUCCESS;
	unsigned int chan_found = 0;
	struct lttng_channel *channels = NULL;

	DBG("Listing channel(s) (%s)", channel_name);

	count = lttng_list_channels(dom, session_name, &channels);
	if (count < 0) {
		ret = count;
		goto error;
	} else if (count == 0) {
		MSG("No channel found");
		goto end;
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
		ret = list_events(dom, session_name, channels[i].name);
		if (ret < 0) {
			MSG("%s", lttng_get_readable_code(ret));
		}

		if (chan_found) {
			break;
		}
	}

	if (!chan_found && channel_name != NULL) {
		MSG("Channel %s not found", channel_name);
	}

end:
	free(channels);
	ret = CMD_SUCCESS;

error:
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
				MSG("Tracing session %s:", session_name);
				MSG("%sTrace path: %s\n", indent4, sessions[i].path);
				break;
			}
		}

		MSG("  %d) %s (%s)", i + 1, sessions[i].name, sessions[i].path);

		if (session_found) {
			break;
		}
	}

	free(sessions);

	if (!session_found && session_name != NULL) {
		MSG("Session %s not found", session_name);
	}

	if (session_name == NULL) {
		MSG("\nUse lttng list -s <session_name> for a detail listing");
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
	const char *session_name;
	static poptContext pc;
	struct lttng_domain domain;
	struct lttng_domain *domains = NULL;

	if (argc < 1) {
		usage(stderr);
		goto end;
	}

	pc = poptGetContext(NULL, argc, argv, long_options, 0);
	poptReadDefaultConfig(pc, 0);

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case OPT_HELP:
			usage(stderr);
			goto end;
		default:
			usage(stderr);
			ret = CMD_UNDEFINED;
			goto end;
		}
	}

	if (opt_userspace || opt_pid != 0) {
		MSG("*** Userspace tracing not implemented ***\n");
	}

	/* Get session name (trailing argument) */
	session_name = poptGetArg(pc);
	DBG("Session name: %s", session_name);

	if (session_name == NULL) {
		if (opt_kernel) {
			ret = list_kernel_events();
			if (ret < 0) {
				goto end;
			}
		} else {
			ret = list_sessions(NULL);
			if (ret < 0) {
				goto end;
			}
		}
	} else {
		/* List session attributes */
		ret = list_sessions(session_name);
		if (ret < 0) {
			goto end;
		}

		/* Domain listing */
		if (opt_domain) {
			ret = list_domains(session_name);
			goto end;
		}

		if (opt_kernel) {
			domain.type = LTTNG_DOMAIN_KERNEL;
			/* Channel listing */
			ret = list_channels(&domain, session_name, opt_channel);
			if (ret < 0) {
				goto end;
			}
		} else if (opt_userspace) {
			/* TODO: Userspace domain */
		} else {
			/* We want all domain(s) */
			ret = lttng_list_domains(session_name, &domains);
			if (ret < 0) {
				goto end;
			}

			for (i = 0; i < ret; i++) {
				switch (domains[i].type) {
				case LTTNG_DOMAIN_KERNEL:
					MSG("=== Domain: Kernel ===\n");
					break;
				default:
					MSG("=== Domain: Unimplemented ===\n");
					break;
				}

				ret = list_channels(&domains[i], session_name, opt_channel);
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
	return ret;
}
