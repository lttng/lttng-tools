/*
 * Copyright (C) 2011 EfficiOS Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include "../command.hpp"

#include <common/mi-lttng.hpp>

#include <lttng/domain-internal.hpp>

#include <popt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static int opt_kernel;
static char *opt_channel_name;
static char *opt_session_name;
static int opt_userspace;
static int opt_disable_all;
static int opt_jul;
static int opt_log4j;
static int opt_python;
static int opt_event_type;

#ifdef LTTNG_EMBED_HELP
static const char help_msg[] =
#include <lttng-disable-event.1.h>
	;
#endif

enum {
	OPT_HELP = 1,
	OPT_TYPE_SYSCALL,
	OPT_TYPE_TRACEPOINT,
	OPT_TYPE_PROBE,
	OPT_TYPE_FUNCTION,
	OPT_TYPE_ALL,
	OPT_LIST_OPTIONS,
};

static struct lttng_handle *handle;
static struct mi_writer *writer;

static struct poptOption long_options[] = {
	/* longName, shortName, argInfo, argPtr, value, descrip, argDesc */
	{ "help", 'h', POPT_ARG_NONE, nullptr, OPT_HELP, nullptr, nullptr },
	{ "session", 's', POPT_ARG_STRING, &opt_session_name, 0, nullptr, nullptr },
	{ "all-events", 'a', POPT_ARG_VAL, &opt_disable_all, 1, nullptr, nullptr },
	{ "channel", 'c', POPT_ARG_STRING, &opt_channel_name, 0, nullptr, nullptr },
	{ "jul", 'j', POPT_ARG_VAL, &opt_jul, 1, nullptr, nullptr },
	{ "log4j", 'l', POPT_ARG_VAL, &opt_log4j, 1, nullptr, nullptr },
	{ "python", 'p', POPT_ARG_VAL, &opt_python, 1, nullptr, nullptr },
	{ "kernel", 'k', POPT_ARG_VAL, &opt_kernel, 1, nullptr, nullptr },
	{ "userspace", 'u', POPT_ARG_VAL, &opt_userspace, 1, nullptr, nullptr },
	{ "syscall", 0, POPT_ARG_NONE, nullptr, OPT_TYPE_SYSCALL, nullptr, nullptr },
	{ "probe", 0, POPT_ARG_NONE, nullptr, OPT_TYPE_PROBE, nullptr, nullptr },
	{ "tracepoint", 0, POPT_ARG_NONE, nullptr, OPT_TYPE_TRACEPOINT, nullptr, nullptr },
	{ "function", 0, POPT_ARG_NONE, nullptr, OPT_TYPE_FUNCTION, nullptr, nullptr },
	{ "all", 0, POPT_ARG_NONE, nullptr, OPT_TYPE_ALL, nullptr, nullptr },
	{ "list-options", 0, POPT_ARG_NONE, nullptr, OPT_LIST_OPTIONS, nullptr, nullptr },
	{ nullptr, 0, 0, nullptr, 0, nullptr, nullptr }
};

static const char *print_channel_name(const char *name)
{
	return name ?: DEFAULT_CHANNEL_NAME;
}

static const char *print_raw_channel_name(const char *name)
{
	return name ?: "<default>";
}

static const char *print_event_type(const enum lttng_event_type ev_type)
{
	switch (ev_type) {
	case LTTNG_EVENT_ALL:
		return "any";
	case LTTNG_EVENT_TRACEPOINT:
		return "tracepoint";
	case LTTNG_EVENT_PROBE:
		return "probe";
	case LTTNG_EVENT_FUNCTION:
		return "function";
	case LTTNG_EVENT_FUNCTION_ENTRY:
		return "function entry";
	case LTTNG_EVENT_SYSCALL:
		return "syscall";
	default:
		return "";
	}
}

/* Mi print a partial event.
 * enabled is 0 or 1
 * success is 0 or 1
 */
static int mi_print_event(const char *event_name, int enabled, int success)
{
	int ret;

	LTTNG_ASSERT(writer);
	LTTNG_ASSERT(event_name);

	/* Open event element */
	ret = mi_lttng_writer_open_element(writer, config_element_event);
	if (ret) {
		goto end;
	}

	/* Print the name of event */
	ret = mi_lttng_writer_write_element_string(writer, config_element_name, event_name);
	if (ret) {
		goto end;
	}

	/* Print enabled ? */
	ret = mi_lttng_writer_write_element_bool(writer, config_element_enabled, enabled);
	if (ret) {
		goto end;
	}

	/* Success ? */
	ret = mi_lttng_writer_write_element_bool(writer, mi_lttng_element_command_success, success);
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
static int disable_events(char *session_name, char *event_list)
{
	enum cmd_error_code ret = CMD_SUCCESS, command_ret = CMD_SUCCESS;
	bool enabled = true, success = true, warn = false;
	char *event_name, *channel_name = nullptr;
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
		/* Checked by the caller. */
		abort();
	}

	channel_name = opt_channel_name;

	handle = lttng_create_handle(session_name, &dom);
	if (handle == nullptr) {
		ret = CMD_ERROR;
		goto error;
	}

	/* Mi print the channel and open the events element */
	if (lttng_opt_mi) {
		int mi_ret = mi_lttng_writer_open_element(writer, config_element_channel);
		if (mi_ret) {
			ret = CMD_ERROR;
			goto end;
		}

		mi_ret = mi_lttng_writer_write_element_string(
			writer, config_element_name, print_channel_name(channel_name));
		if (mi_ret) {
			ret = CMD_ERROR;
			goto end;
		}

		/* Open events element */
		mi_ret = mi_lttng_writer_open_element(writer, config_element_events);
		if (mi_ret) {
			ret = CMD_ERROR;
			goto end;
		}
	}

	memset(&event, 0, sizeof(event));
	/* Set default loglevel to any/unknown */
	event.loglevel = -1;

	/* opt_event_type contain the event type to disable at this point */
	event.type = (lttng_event_type) opt_event_type;

	if (opt_disable_all) {
		const int disable_ret =
			lttng_disable_event_ext(handle, &event, channel_name, nullptr);

		if (disable_ret < 0) {
			ERR("%s", lttng_strerror(command_ret));
			command_ret = CMD_ERROR;
			enabled = true;
			success = false;
		} else {
			enabled = false;
			success = true;
			MSG("All %s events of type %s are disabled in channel %s",
			    lttng_domain_type_str(dom.type),
			    print_event_type((lttng_event_type) opt_event_type),
			    print_channel_name(channel_name));
		}

		if (lttng_opt_mi) {
			const int mi_ret = mi_print_event("*", enabled, success);

			if (mi_ret) {
				ret = CMD_ERROR;
				goto error;
			}
		}
	} else {
		/* Strip event list */
		event_name = strtok(event_list, ",");
		while (event_name != nullptr) {
			DBG("Disabling event %s", event_name);

			strncpy(event.name, event_name, sizeof(event.name));
			event.name[sizeof(event.name) - 1] = '\0';
			const int disable_ret =
				lttng_disable_event_ext(handle, &event, channel_name, nullptr);
			if (disable_ret < 0) {
				ERR("%s of type %s : %s (channel %s, session %s)",
				    event_name,
				    print_event_type((lttng_event_type) opt_event_type),
				    lttng_strerror(disable_ret),
				    disable_ret == -LTTNG_ERR_NEED_CHANNEL_NAME ?
					    print_raw_channel_name(channel_name) :
					    print_channel_name(channel_name),
				    session_name);
				warn = true;
				success = false;
				/*
				 * If an error occurred we assume that the event is still
				 * enabled.
				 */
				enabled = true;
				command_ret = CMD_ERROR;
			} else {
				MSG("%s %s of type %s disabled in channel %s for session %s",
				    lttng_domain_type_str(dom.type),
				    event_name,
				    print_event_type((lttng_event_type) opt_event_type),
				    print_channel_name(channel_name),
				    session_name);
				success = true;
				enabled = false;
			}

			if (lttng_opt_mi) {
				const int mi_ret = mi_print_event(event_name, enabled, success);

				if (mi_ret) {
					ret = CMD_ERROR;
					goto error;
				}
			}

			/* Next event */
			event_name = strtok(nullptr, ",");
		}
	}

end:
	if (lttng_opt_mi) {
		/* Close events element and channel element */
		const int mi_ret = mi_lttng_close_multi_element(writer, 2);

		if (mi_ret) {
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
	char *session_name = nullptr;
	char *event_list = nullptr;
	const char *arg_event_list = nullptr;
	const char *leftover = nullptr;
	int event_type = -1;

	pc = poptGetContext(nullptr, argc, argv, long_options, 0);
	poptReadDefaultConfig(pc, 0);

	/* Default event type */
	opt_event_type = LTTNG_EVENT_ALL;

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case OPT_HELP:
			SHOW_HELP();
			goto end;
		case OPT_TYPE_SYSCALL:
			opt_event_type = LTTNG_EVENT_SYSCALL;
			break;
		case OPT_TYPE_TRACEPOINT:
			opt_event_type = LTTNG_EVENT_TRACEPOINT;
			break;
		case OPT_TYPE_PROBE:
			opt_event_type = LTTNG_EVENT_PROBE;
			break;
		case OPT_TYPE_FUNCTION:
			opt_event_type = LTTNG_EVENT_FUNCTION;
			break;
		case OPT_TYPE_ALL:
			opt_event_type = LTTNG_EVENT_ALL;
			break;
		case OPT_LIST_OPTIONS:
			list_cmd_options(stdout, long_options);
			goto end;
		default:
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

	ret = print_missing_or_multiple_domains(
		opt_kernel + opt_userspace + opt_jul + opt_log4j + opt_python, true);
	if (ret) {
		ret = CMD_ERROR;
		goto end;
	}

	/* Ust and agent only support ALL event type */
	if ((opt_userspace || opt_jul || opt_log4j || opt_python) &&
	    opt_event_type != LTTNG_EVENT_ALL) {
		ERR("Disabling userspace and agent (-j | -l | -p) event(s) based on instrumentation type is not supported.\n");
		ret = CMD_ERROR;
		goto end;
	}

	arg_event_list = poptGetArg(pc);
	if (arg_event_list == nullptr && opt_disable_all == 0) {
		ERR("Missing event name(s).\n");
		ret = CMD_ERROR;
		goto end;
	}

	if (opt_disable_all == 0) {
		event_list = strdup(arg_event_list);
		if (event_list == nullptr) {
			PERROR("Failed to copy event name(s)");
			ret = CMD_ERROR;
			goto end;
		}
	}

	leftover = poptGetArg(pc);
	if (leftover) {
		ERR("Unknown argument: %s", leftover);
		ret = CMD_ERROR;
		goto end;
	}

	if (!opt_session_name) {
		session_name = get_session_name();
		if (session_name == nullptr) {
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
		ret = mi_lttng_writer_command_open(writer, mi_lttng_element_command_disable_event);
		if (ret) {
			ret = CMD_ERROR;
			goto end;
		}

		/* Open output element */
		ret = mi_lttng_writer_open_element(writer, mi_lttng_element_command_output);
		if (ret) {
			ret = CMD_ERROR;
			goto end;
		}
	}

	command_ret = disable_events(session_name, event_list);
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

		ret = mi_lttng_writer_write_element_bool(
			writer, mi_lttng_element_command_success, success);
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

	free(event_list);

	/* Mi clean-up */
	if (writer && mi_lttng_writer_destroy(writer)) {
		/* Preserve original error code */
		ret = ret ? ret : LTTNG_ERR_MI_IO_FAIL;
	}

	/* Overwrite ret if an error occurred in disable_events */
	ret = command_ret ? command_ret : ret;

	poptFreeContext(pc);
	return ret;
}
