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
#define _LGPL_SOURCE
#include <popt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <assert.h>

#include <common/mi-lttng.h>

#include "../command.h"

static char *opt_event_list;
static int opt_kernel;
static char *opt_channel_name;
static char *opt_session_name;
static int opt_userspace;
static int opt_disable_all;
static int opt_jul;
static int opt_log4j;
static int opt_python;
static int opt_event_type;
#if 0
/* Not implemented yet */
static char *opt_cmd_name;
static pid_t opt_pid;
#endif

enum {
	OPT_HELP = 1,
	OPT_USERSPACE,
	OPT_SYSCALL,
	OPT_LIST_OPTIONS,
};

static struct lttng_handle *handle;
static struct mi_writer *writer;

static struct poptOption long_options[] = {
	/* longName, shortName, argInfo, argPtr, value, descrip, argDesc */
	{"help",           'h', POPT_ARG_NONE, 0, OPT_HELP, 0, 0},
	{"session",        's', POPT_ARG_STRING, &opt_session_name, 0, 0, 0},
	{"all-events",     'a', POPT_ARG_VAL, &opt_disable_all, 1, 0, 0},
	{"channel",        'c', POPT_ARG_STRING, &opt_channel_name, 0, 0, 0},
	{"jul",            'j', POPT_ARG_VAL, &opt_jul, 1, 0, 0},
	{"log4j",          'l', POPT_ARG_VAL, &opt_log4j, 1, 0, 0},
	{"python",         'p', POPT_ARG_VAL, &opt_python, 1, 0, 0},
	{"kernel",         'k', POPT_ARG_VAL, &opt_kernel, 1, 0, 0},
	{"syscall",        0,   POPT_ARG_NONE, 0, OPT_SYSCALL, 0, 0},
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
	fprintf(ofp, "Usage: lttng disable-event <name>[,<name2>,...] (-k | -u | -j | -l | -p) [opts]\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Domain options:\n");
	fprintf(ofp, "  -j, --jul              Apply to Java applications using JUL\n");
	fprintf(ofp, "  -k, --kernel           Apply to the kernel tracer\n");
	fprintf(ofp, "  -l, --log4j            Apply to Java applications using log4j\n");
	fprintf(ofp, "  -p, --python           Apply to Python applications using logging\n");
	fprintf(ofp, "  -u, --userspace        Apply to the user space tracer\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Target options:\n");
	fprintf(ofp, "  -c, --channel CHANNEL  Apply to channel CHANNEL\n");
	fprintf(ofp, "  -s, --session SESSION  Apply to session SESSION\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Event options:\n");
	fprintf(ofp, "  -a, --all-events       Disable all tracepoints\n");
	fprintf(ofp, "      --syscall          Disable system call events\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Help options:\n");
	fprintf(ofp, "  -h, --help             Show this help\n");
	fprintf(ofp, "      --list-options     List options\n");
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

/* Mi print a partial event.
 * enabled is 0 or 1
 * success is 0 or 1
 */
static int mi_print_event(char *event_name, int enabled, int success)
{
	int ret;

	assert(writer);
	assert(event_name);

	/* Open event element */
	ret = mi_lttng_writer_open_element(writer, config_element_event);
	if (ret) {
		goto end;
	}

	/* Print the name of event */
	ret = mi_lttng_writer_write_element_string(writer,
			config_element_name, event_name);
	if (ret) {
		goto end;
	}

	/* Print enabled ? */
	ret = mi_lttng_writer_write_element_bool(writer,
			config_element_enabled, enabled);
	if (ret) {
		goto end;
	}

	/* Success ? */
	ret = mi_lttng_writer_write_element_bool(writer,
			mi_lttng_element_command_success, success);
	if (ret) {
		goto end;
	}

	/* Close event element */
	ret = mi_lttng_writer_close_element(writer);
end:
	return ret;
}

/*
 *  disable_events
 *
 *  Disabling event using the lttng API.
 */
static int disable_events(char *session_name)
{
	int ret = CMD_SUCCESS, warn = 0, command_ret = CMD_SUCCESS;
	int enabled = 1, success = 1;
	char *event_name, *channel_name = NULL;
	struct lttng_domain dom;
	struct lttng_event event;

	memset(&dom, 0, sizeof(dom));

	/* Create lttng domain */
	if (opt_kernel) {
		dom.type = LTTNG_DOMAIN_KERNEL;
	} else if (opt_userspace) {
		dom.type = LTTNG_DOMAIN_UST;
	} else if (opt_jul) {
		dom.type = LTTNG_DOMAIN_JUL;
	} else if (opt_log4j) {
		dom.type = LTTNG_DOMAIN_LOG4J;
	} else if (opt_python) {
		dom.type = LTTNG_DOMAIN_PYTHON;
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

	/* Mi print the channel and open the events element */
	if (lttng_opt_mi) {
		ret = mi_lttng_writer_open_element(writer, config_element_channel);
		if (ret) {
			ret = CMD_ERROR;
			goto end;
		}

		ret = mi_lttng_writer_write_element_string(writer,
				config_element_name, print_channel_name(channel_name));
		if (ret) {
			ret = CMD_ERROR;
			goto end;
		}

		/* Open events element */
		ret = mi_lttng_writer_open_element(writer, config_element_events);
		if (ret) {
			ret = CMD_ERROR;
			goto end;
		}
	}

	memset(&event, 0, sizeof(event));
	/* Set default loglevel to any/unknown */
	event.loglevel = -1;

	switch (opt_event_type) {
	case LTTNG_EVENT_SYSCALL:
		event.type = LTTNG_EVENT_SYSCALL;
		break;
	default:
		event.type = LTTNG_EVENT_ALL;
		break;
	}

	if (opt_disable_all) {
		command_ret = lttng_disable_event_ext(handle, &event, channel_name, NULL);
		if (command_ret < 0) {
			ERR("%s", lttng_strerror(command_ret));
			enabled = 1;
			success = 0;

		} else {
			enabled = 0;
			success = 1;
			MSG("All %s %s are disabled in channel %s",
					get_domain_str(dom.type),
					opt_event_type == LTTNG_EVENT_SYSCALL ? "system calls" : "events",
					print_channel_name(channel_name));
		}

		if (lttng_opt_mi) {
			ret = mi_print_event("*", enabled, success);
			if (ret) {
				ret = CMD_ERROR;
				goto error;
			}
		}
	} else {
		/* Strip event list */
		event_name = strtok(opt_event_list, ",");
		while (event_name != NULL) {
			DBG("Disabling event %s", event_name);

			strncpy(event.name, event_name, sizeof(event.name));
			event.name[sizeof(event.name) - 1] = '\0';
			command_ret = lttng_disable_event_ext(handle, &event, channel_name, NULL);
			if (command_ret < 0) {
				ERR("%s %s: %s (channel %s, session %s)",
						opt_event_type == LTTNG_EVENT_SYSCALL ? "System call" : "Event",
						event_name,
						lttng_strerror(command_ret),
						command_ret == -LTTNG_ERR_NEED_CHANNEL_NAME
							? print_raw_channel_name(channel_name)
							: print_channel_name(channel_name),
						session_name);
				warn = 1;
				success = 0;
				/*
				 * If an error occurred we assume that the event is still
				 * enabled.
				 */
				enabled = 1;
			} else {
				MSG("%s %s %s disabled in channel %s for session %s",
						get_domain_str(dom.type),
						opt_event_type == LTTNG_EVENT_SYSCALL ? "system call" : "event",
						event_name,
						print_channel_name(channel_name),
						session_name);
				success = 1;
				enabled = 0;
			}

			if (lttng_opt_mi) {
				ret = mi_print_event(event_name, enabled, success);
				if (ret) {
					ret = CMD_ERROR;
					goto error;
				}
			}

			/* Next event */
			event_name = strtok(NULL, ",");
		}
	}

end:
	if (lttng_opt_mi) {
		/* Close events element and channel element */
		ret = mi_lttng_close_multi_element(writer, 2);
		if (ret) {
			ret = CMD_ERROR;
		}
	}
error:
	/* if there is already an error preserve it */
	if (warn && !ret) {
		ret = CMD_WARNING;
	}

	/* Overwrite ret if an error occurred */
	ret = command_ret ? command_ret : ret;

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
	int opt, ret = CMD_SUCCESS, command_ret = CMD_SUCCESS, success = 1;
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
		case OPT_USERSPACE:
			opt_userspace = 1;
			break;
		case OPT_SYSCALL:
			opt_event_type = LTTNG_EVENT_SYSCALL;
			break;
		case OPT_LIST_OPTIONS:
			list_cmd_options(stdout, long_options);
			goto end;
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

	/* Mi check */
	if (lttng_opt_mi) {
		writer = mi_lttng_writer_create(fileno(stdout), lttng_opt_mi);
		if (!writer) {
			ret = -LTTNG_ERR_NOMEM;
			goto end;
		}

		/* Open command element */
		ret = mi_lttng_writer_command_open(writer,
				mi_lttng_element_command_disable_event);
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

	command_ret = disable_events(session_name);
	if (command_ret) {
		success = 0;
	}

	/* Mi closing */
	if (lttng_opt_mi) {
		/* Close  output element */
		ret = mi_lttng_writer_close_element(writer);
		if (ret) {
			ret = CMD_ERROR;
			goto end;
		}

		ret = mi_lttng_writer_write_element_bool(writer,
				mi_lttng_element_command_success, success);
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
	if (!opt_session_name && session_name) {
		free(session_name);
	}

	/* Mi clean-up */
	if (writer && mi_lttng_writer_destroy(writer)) {
		/* Preserve original error code */
		ret = ret ? ret : LTTNG_ERR_MI_IO_FAIL;
	}

	/* Overwrite ret if an error occured in disable_events */
	ret = command_ret ? command_ret : ret;

	poptFreeContext(pc);
	return ret;
}
