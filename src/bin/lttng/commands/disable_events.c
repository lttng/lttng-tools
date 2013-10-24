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

#include "../command.h"

static char *opt_event_list;
static int opt_kernel;
static char *opt_channel_name;
static char *opt_session_name;
static int opt_userspace;
static int opt_disable_all;
static int opt_jul;
#if 0
/* Not implemented yet */
static char *opt_cmd_name;
static pid_t opt_pid;
#endif

enum {
	OPT_HELP = 1,
	OPT_USERSPACE,
	OPT_LIST_OPTIONS,
};

static struct lttng_handle *handle;

static struct poptOption long_options[] = {
	/* longName, shortName, argInfo, argPtr, value, descrip, argDesc */
	{"help",           'h', POPT_ARG_NONE, 0, OPT_HELP, 0, 0},
	{"session",        's', POPT_ARG_STRING, &opt_session_name, 0, 0, 0},
	{"all-events",     'a', POPT_ARG_VAL, &opt_disable_all, 1, 0, 0},
	{"channel",        'c', POPT_ARG_STRING, &opt_channel_name, 0, 0, 0},
	{"jul",            'j', POPT_ARG_VAL, &opt_jul, 1, 0, 0},
	{"kernel",         'k', POPT_ARG_VAL, &opt_kernel, 1, 0, 0},
#if 0
	/* Not implemented yet */
	{"userspace",      'u', POPT_ARG_STRING | POPT_ARGFLAG_OPTIONAL, &opt_cmd_name, OPT_USERSPACE, 0, 0},
	{"pid",            'p', POPT_ARG_INT, &opt_pid, 0, 0, 0},
#else
	{"userspace",      'u', POPT_ARG_NONE, 0, OPT_USERSPACE, 0, 0},
#endif
	{"list-options", 0, POPT_ARG_NONE, NULL, OPT_LIST_OPTIONS, NULL, NULL},
	{0, 0, 0, 0, 0, 0, 0}
};

/*
 * usage
 */
static void usage(FILE *ofp)
{
	fprintf(ofp, "usage: lttng disable-event NAME[,NAME2,...] (-k | -u) [OPTIONS]\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Options:\n");
	fprintf(ofp, "  -h, --help               Show this help\n");
	fprintf(ofp, "      --list-options       Simple listing of options\n");
	fprintf(ofp, "  -s, --session NAME       Apply to session name\n");
	fprintf(ofp, "  -c, --channel NAME       Apply to this channel\n");
	fprintf(ofp, "  -a, --all-events         Disable all tracepoints\n");
	fprintf(ofp, "  -k, --kernel             Apply for the kernel tracer\n");
	fprintf(ofp, "  -u, --userspace          Apply to the user-space tracer\n");
	fprintf(ofp, "  -j, --jul                Apply for Java application using JUL\n");
	fprintf(ofp, "\n");
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
 *  disable_events
 *
 *  Disabling event using the lttng API.
 */
static int disable_events(char *session_name)
{
	int ret = CMD_SUCCESS, warn = 0;
	char *event_name, *channel_name = NULL;
	struct lttng_domain dom;

	memset(&dom, 0, sizeof(dom));

	/* Create lttng domain */
	if (opt_kernel) {
		dom.type = LTTNG_DOMAIN_KERNEL;
	} else if (opt_userspace) {
		dom.type = LTTNG_DOMAIN_UST;
	} else if (opt_jul) {
		dom.type = LTTNG_DOMAIN_JUL;
	} else {
		print_missing_domain();
		ret = CMD_ERROR;
		goto error;
	}

	channel_name = opt_channel_name;

	handle = lttng_create_handle(session_name, &dom);
	if (handle == NULL) {
		ret = -1;
		goto error;
	}

	if (opt_disable_all) {
		ret = lttng_disable_event(handle, NULL, channel_name);
		if (ret < 0) {
			ERR("%s", lttng_strerror(ret));
			goto error;
		}

		MSG("All %s events are disabled in channel %s",
				get_domain_str(dom.type), print_channel_name(channel_name));
		goto end;
	}

	/* Strip event list */
	event_name = strtok(opt_event_list, ",");
	while (event_name != NULL) {
		DBG("Disabling event %s", event_name);

		ret = lttng_disable_event(handle, event_name, channel_name);
		if (ret < 0) {
			ERR("Event %s: %s (channel %s, session %s)", event_name,
					lttng_strerror(ret),
					ret == -LTTNG_ERR_NEED_CHANNEL_NAME
						? print_raw_channel_name(channel_name)
						: print_channel_name(channel_name),
					session_name);
			warn = 1;
		} else {
			MSG("%s event %s disabled in channel %s for session %s",
					get_domain_str(dom.type), event_name,
					print_channel_name(channel_name),
					session_name);
		}

		/* Next event */
		event_name = strtok(NULL, ",");
	}

	ret = CMD_SUCCESS;

end:
error:
	if (warn) {
		ret = CMD_WARNING;
	}
	lttng_destroy_handle(handle);

	return ret;
}

/*
 *  cmd_disable_events
 *
 *  Disable event to trace session
 */
int cmd_disable_events(int argc, const char **argv)
{
	int opt, ret = CMD_SUCCESS;
	static poptContext pc;
	char *session_name = NULL;

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

	opt_event_list = (char*) poptGetArg(pc);
	if (opt_event_list == NULL && opt_disable_all == 0) {
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

	ret = disable_events(session_name);

end:
	if (!opt_session_name && session_name) {
		free(session_name);
	}
	poptFreeContext(pc);
	return ret;
}
