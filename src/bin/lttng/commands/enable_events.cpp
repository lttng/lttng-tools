/*
 * Copyright (C) 2011 EfficiOS Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include <common/compat/getenv.hpp>
#include <common/compat/string.hpp>
#include <common/make-unique-wrapper.hpp>
#include <common/scope-exit.hpp>
#include <common/sessiond-comm/sessiond-comm.hpp>
#include <common/string-utils/string-utils.hpp>
#include <common/utils.hpp>

#include <ctype.h>
#include <inttypes.h>
#include <popt.h>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

/* Mi dependancy */
#include "../command.hpp"
#include "../loglevel.hpp"
#include "../uprobe.hpp"

#include <common/mi-lttng.hpp>

#include <lttng/domain-internal.hpp>
#include <lttng/event-internal.hpp>

#if (LTTNG_SYMBOL_NAME_LEN == 256)
#define LTTNG_SYMBOL_NAME_LEN_SCANF_IS_A_BROKEN_API "255"
#endif

namespace {
void _mi_lttng_writer_deleter_func(mi_writer *writer)
{
	if (writer && mi_lttng_writer_destroy(writer)) {
		LTTNG_THROW_ERROR("Failed to destroy mi_writer instance");
	}
}

using mi_writer_uptr = std::unique_ptr<
	mi_writer,
	lttng::memory::create_deleter_class<mi_writer, _mi_lttng_writer_deleter_func>::deleter>;
using event_rule_patterns = std::vector<std::string>;

int opt_event_type;
const char *opt_loglevel;
int opt_loglevel_type;
int opt_kernel;
char *opt_session_name;
int opt_userspace;
int opt_jul;
int opt_log4j;
int opt_python;
int opt_enable_all;
char *opt_probe;
char *opt_userspace_probe;
char *opt_function;
char *opt_channel_name;
char *opt_filter;
char *opt_exclude;

struct lttng_handle *handle;
mi_writer_uptr writer;

#ifdef LTTNG_EMBED_HELP
static const char help_msg[] =
#include <lttng-enable-event.1.h>
	;
#endif

enum {
	OPT_HELP = 1,
	OPT_TRACEPOINT,
	OPT_PROBE,
	OPT_USERSPACE_PROBE,
	OPT_FUNCTION,
	OPT_SYSCALL,
	OPT_USERSPACE,
	OPT_LOGLEVEL,
	OPT_LOGLEVEL_ONLY,
	OPT_LIST_OPTIONS,
	OPT_FILTER,
	OPT_EXCLUDE,
};

struct poptOption long_options[] = {
	/* longName, shortName, argInfo, argPtr, value, descrip, argDesc */
	{ "help", 'h', POPT_ARG_NONE, nullptr, OPT_HELP, nullptr, nullptr },
	{ "session", 's', POPT_ARG_STRING, &opt_session_name, 0, nullptr, nullptr },
	{ "all", 'a', POPT_ARG_VAL, &opt_enable_all, 1, nullptr, nullptr },
	{ "channel", 'c', POPT_ARG_STRING, &opt_channel_name, 0, nullptr, nullptr },
	{ "kernel", 'k', POPT_ARG_VAL, &opt_kernel, 1, nullptr, nullptr },
	{ "userspace", 'u', POPT_ARG_NONE, nullptr, OPT_USERSPACE, nullptr, nullptr },
	{ "jul", 'j', POPT_ARG_VAL, &opt_jul, 1, nullptr, nullptr },
	{ "log4j", 'l', POPT_ARG_VAL, &opt_log4j, 1, nullptr, nullptr },
	{ "python", 'p', POPT_ARG_VAL, &opt_python, 1, nullptr, nullptr },
	{ "tracepoint", 0, POPT_ARG_NONE, nullptr, OPT_TRACEPOINT, nullptr, nullptr },
	{ "probe", 0, POPT_ARG_STRING, &opt_probe, OPT_PROBE, nullptr, nullptr },
	{ "userspace-probe",
	  0,
	  POPT_ARG_STRING,
	  &opt_userspace_probe,
	  OPT_USERSPACE_PROBE,
	  nullptr,
	  nullptr },
	{ "function", 0, POPT_ARG_STRING, &opt_function, OPT_FUNCTION, nullptr, nullptr },
	{ "syscall", 0, POPT_ARG_NONE, nullptr, OPT_SYSCALL, nullptr, nullptr },
	{ "loglevel", 0, POPT_ARG_STRING, nullptr, OPT_LOGLEVEL, nullptr, nullptr },
	{ "loglevel-only", 0, POPT_ARG_STRING, nullptr, OPT_LOGLEVEL_ONLY, nullptr, nullptr },
	{ "list-options", 0, POPT_ARG_NONE, nullptr, OPT_LIST_OPTIONS, nullptr, nullptr },
	{ "filter", 'f', POPT_ARG_STRING, &opt_filter, OPT_FILTER, nullptr, nullptr },
	{ "exclude", 'x', POPT_ARG_STRING, &opt_exclude, OPT_EXCLUDE, nullptr, nullptr },
	{ nullptr, 0, 0, nullptr, 0, nullptr, nullptr }
};

/*
 * Parse probe options.
 */
int parse_probe_opts(struct lttng_event *ev, char *opt)
{
	int ret = CMD_SUCCESS;
	int match;
	char s_hex[19];
#define S_HEX_LEN_SCANF_IS_A_BROKEN_API "18" /* 18 is (19 - 1) (\0 is extra) */
	char name[LTTNG_SYMBOL_NAME_LEN];

	if (opt == nullptr) {
		ret = CMD_ERROR;
		goto end;
	}

	/* Check for symbol+offset */
	match = sscanf(opt,
		       "%" LTTNG_SYMBOL_NAME_LEN_SCANF_IS_A_BROKEN_API
		       "[^'+']+%" S_HEX_LEN_SCANF_IS_A_BROKEN_API "s",
		       name,
		       s_hex);
	if (match == 2) {
		strncpy(ev->attr.probe.symbol_name, name, LTTNG_SYMBOL_NAME_LEN);
		ev->attr.probe.symbol_name[LTTNG_SYMBOL_NAME_LEN - 1] = '\0';
		DBG("probe symbol %s", ev->attr.probe.symbol_name);
		if (*s_hex == '\0') {
			ERR("Invalid probe offset %s", s_hex);
			ret = CMD_ERROR;
			goto end;
		}
		ev->attr.probe.offset = strtoull(s_hex, nullptr, 0);
		DBG("probe offset %" PRIu64, ev->attr.probe.offset);
		ev->attr.probe.addr = 0;
		goto end;
	}

	/* Check for symbol */
	if (isalpha(name[0]) || name[0] == '_') {
		match = sscanf(opt, "%" LTTNG_SYMBOL_NAME_LEN_SCANF_IS_A_BROKEN_API "s", name);
		if (match == 1) {
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
	match = sscanf(opt, "%" S_HEX_LEN_SCANF_IS_A_BROKEN_API "s", s_hex);
	if (match > 0) {
		/*
		 * Return an error if the first character of the tentative
		 * address is NULL or not a digit. It can be "0" if the address
		 * is in hexadecimal and can be 1 to 9 if it's in decimal.
		 */
		if (*s_hex == '\0' || !isdigit(*s_hex)) {
			ERR("Invalid probe description %s", s_hex);
			ret = CMD_ERROR;
			goto end;
		}
		ev->attr.probe.addr = strtoull(s_hex, nullptr, 0);
		DBG("probe addr %" PRIu64, ev->attr.probe.addr);
		ev->attr.probe.offset = 0;
		memset(ev->attr.probe.symbol_name, 0, LTTNG_SYMBOL_NAME_LEN);
		goto end;
	}

	/* No match */
	ret = CMD_ERROR;

end:
	return ret;
}

const char *print_channel_name(const char *name)
{
	return name ?: DEFAULT_CHANNEL_NAME;
}

const char *print_raw_channel_name(const char *name)
{
	return name ?: "<default>";
}

/*
 * Mi print exlcusion list
 */
int mi_print_exclusion(const struct lttng_dynamic_pointer_array *exclusions)
{
	int ret;
	size_t i;
	const size_t count = lttng_dynamic_pointer_array_get_count(exclusions);

	LTTNG_ASSERT(writer);

	if (count == 0) {
		ret = 0;
		goto end;
	}

	ret = mi_lttng_writer_open_element(writer.get(), config_element_exclusions);
	if (ret) {
		goto end;
	}

	for (i = 0; i < count; i++) {
		const char *exclusion =
			(const char *) lttng_dynamic_pointer_array_get_pointer(exclusions, i);

		ret = mi_lttng_writer_write_element_string(
			writer.get(), config_element_exclusion, exclusion);
		if (ret) {
			goto end;
		}
	}

	/* Close exclusions element */
	ret = mi_lttng_writer_close_element(writer.get());

end:
	return ret;
}

/*
 * Return allocated string for pretty-printing exclusion names.
 */
char *print_exclusions(const struct lttng_dynamic_pointer_array *exclusions)
{
	int length = 0;
	size_t i;
	const char preamble[] = " excluding ";
	char *ret;
	const size_t count = lttng_dynamic_pointer_array_get_count(exclusions);

	if (count == 0) {
		return strdup("");
	}

	/* Calculate total required length. */
	for (i = 0; i < count; i++) {
		const char *exclusion =
			(const char *) lttng_dynamic_pointer_array_get_pointer(exclusions, i);

		length += strlen(exclusion) + 4;
	}

	length += sizeof(preamble);
	ret = calloc<char>(length);
	if (!ret) {
		return nullptr;
	}

	strncpy(ret, preamble, length);
	for (i = 0; i < count; i++) {
		const char *exclusion =
			(const char *) lttng_dynamic_pointer_array_get_pointer(exclusions, i);

		strcat(ret, "\"");
		strcat(ret, exclusion);
		strcat(ret, "\"");
		if (i != count - 1) {
			strcat(ret, ", ");
		}
	}

	return ret;
}

int check_exclusion_subsets(const char *pattern, const char *exclusion)
{
	bool warn = false;
	int ret = 0;
	const char *e = pattern;
	const char *x = exclusion;

	/* Scan both the excluder and the event letter by letter */
	while (true) {
		if (*e == '\\') {
			if (*x != *e) {
				warn = true;
				goto end;
			}

			e++;
			x++;
			goto cmp_chars;
		}

		if (*x == '*') {
			/* Event is a subset of the excluder */
			ERR("Event %s: %s excludes all events from %s", pattern, exclusion, pattern);
			goto error;
		}

		if (*e == '*') {
			/*
			 * Reached the end of the event name before the
			 * end of the exclusion: this is valid.
			 */
			goto end;
		}

	cmp_chars:
		if (*x != *e) {
			warn = true;
			break;
		}

		x++;
		e++;
	}

	goto end;

error:
	ret = -1;

end:
	if (warn) {
		WARN("Event %s: %s does not exclude any events from %s",
		     pattern,
		     exclusion,
		     pattern);
	}

	return ret;
}

int create_exclusion_list_and_validate(const char *pattern,
				       const char *exclusions_arg,
				       struct lttng_dynamic_pointer_array *exclusions)
{
	int ret = 0;

	/* Split exclusions. */
	ret = strutils_split(exclusions_arg, ',', true, exclusions);
	if (ret < 0) {
		goto error;
	}

	if (validate_exclusion_list(pattern, exclusions) != 0) {
		goto error;
	}

	goto end;

error:
	ret = -1;
	lttng_dynamic_pointer_array_reset(exclusions);

end:
	return ret;
}

void warn_on_truncated_exclusion_names(const struct lttng_dynamic_pointer_array *exclusions,
				       int *warn)
{
	size_t i;
	const size_t num_exclusions = lttng_dynamic_pointer_array_get_count(exclusions);

	for (i = 0; i < num_exclusions; i++) {
		const char *const exclusion =
			(const char *) lttng_dynamic_pointer_array_get_pointer(exclusions, i);

		if (strlen(exclusion) >= LTTNG_SYMBOL_NAME_LEN) {
			WARN("Event exclusion \"%s\" will be truncated", exclusion);
			*warn = 1;
		}
	}
}

/*
 * Enabling event using the lttng API.
 * Note: in case of error only the last error code will be return.
 */
int enable_events(const std::string& session_name, const event_rule_patterns& patterns)
{
	int ret = CMD_SUCCESS, command_ret = CMD_SUCCESS;
	int error_holder = CMD_SUCCESS, warn = 0, error = 0, success = 1;
	char *channel_name = nullptr;
	struct lttng_event *ev;
	struct lttng_domain dom = {};
	struct lttng_dynamic_pointer_array exclusions;
	struct lttng_userspace_probe_location *uprobe_loc = nullptr;

	lttng_dynamic_pointer_array_init(&exclusions, nullptr);

	ev = lttng_event_create();
	if (!ev) {
		ret = CMD_ERROR;
		goto error;
	}

	if (opt_kernel) {
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
	} else if (opt_log4j) {
		dom.type = LTTNG_DOMAIN_LOG4J;
		/* Default. */
		dom.buf_type = LTTNG_BUFFER_PER_UID;
	} else if (opt_python) {
		dom.type = LTTNG_DOMAIN_PYTHON;
		/* Default. */
		dom.buf_type = LTTNG_BUFFER_PER_UID;
	} else {
		/* Checked by the caller. */
		abort();
	}

	if (opt_exclude) {
		switch (dom.type) {
		case LTTNG_DOMAIN_KERNEL:
		case LTTNG_DOMAIN_JUL:
		case LTTNG_DOMAIN_LOG4J:
		case LTTNG_DOMAIN_PYTHON:
			ERR("Event name exclusions are not yet implemented for %s events",
			    lttng_domain_type_str(dom.type));
			ret = CMD_ERROR;
			goto error;
		case LTTNG_DOMAIN_UST:
			/* Exclusions supported */
			break;
		default:
			abort();
		}
	}

	/*
	 * Adding a filter to a probe, function or userspace-probe would be
	 * denied by the kernel tracer as it's not supported at the moment. We
	 * do an early check here to warn the user.
	 */
	if (opt_filter && opt_kernel) {
		switch (opt_event_type) {
		case LTTNG_EVENT_ALL:
		case LTTNG_EVENT_TRACEPOINT:
		case LTTNG_EVENT_SYSCALL:
			break;
		case LTTNG_EVENT_PROBE:
		case LTTNG_EVENT_USERSPACE_PROBE:
		case LTTNG_EVENT_FUNCTION:
			ERR("Filter expressions are not supported for %s events",
			    get_event_type_str((lttng_event_type) opt_event_type));
			ret = CMD_ERROR;
			goto error;
		default:
			ret = CMD_UNDEFINED;
			goto error;
		}
	}

	channel_name = opt_channel_name;

	handle = lttng_create_handle(session_name.c_str(), &dom);
	if (handle == nullptr) {
		ret = -1;
		goto error;
	}

	/* Prepare Mi */
	if (lttng_opt_mi) {
		/* Open a events element */
		ret = mi_lttng_writer_open_element(writer.get(), config_element_events);
		if (ret) {
			ret = CMD_ERROR;
			goto error;
		}
	}

	for (const auto& pattern : patterns) {
		/* Copy name and type of the event */
		strncpy(ev->name, pattern.c_str(), LTTNG_SYMBOL_NAME_LEN);
		ev->name[LTTNG_SYMBOL_NAME_LEN - 1] = '\0';
		ev->type = (lttng_event_type) opt_event_type;

		/* Kernel tracer action */
		if (opt_kernel) {
			DBG_FMT("Enabling kernel event: pattern=`{}`, channel_name=`{}`",
				pattern,
				print_channel_name(channel_name));

			switch (opt_event_type) {
			case LTTNG_EVENT_ALL: /* Enable tracepoints and syscalls */
				/* If event name differs from *, select tracepoint. */
				if (strcmp(ev->name, "*") != 0) {
					ev->type = LTTNG_EVENT_TRACEPOINT;
				}
				break;
			case LTTNG_EVENT_TRACEPOINT:
				break;
			case LTTNG_EVENT_PROBE:
				ret = parse_probe_opts(ev, opt_probe);
				if (ret) {
					ERR("Unable to parse probe options");
					ret = CMD_ERROR;
					goto error;
				}
				break;
			case LTTNG_EVENT_USERSPACE_PROBE:
				LTTNG_ASSERT(ev->type == LTTNG_EVENT_USERSPACE_PROBE);

				ret = parse_userspace_probe_opts(opt_userspace_probe, &uprobe_loc);
				if (ret) {
					switch (ret) {
					case CMD_UNSUPPORTED:
						/*
						 * Error message describing
						 * what is not supported was
						 * printed in the function.
						 */
						break;
					case CMD_ERROR:
					default:
						ERR("Unable to parse userspace probe options");
						break;
					}
					goto error;
				}

				ret = lttng_event_set_userspace_probe_location(ev, uprobe_loc);
				if (ret) {
					WARN("Failed to set probe location on event");
					ret = CMD_ERROR;
					goto error;
				}

				/* Ownership of the uprobe location was transferred to the event. */
				uprobe_loc = nullptr;
				break;
			case LTTNG_EVENT_FUNCTION:
				ret = parse_probe_opts(ev, opt_function);
				if (ret) {
					ERR("Unable to parse function probe options");
					ret = CMD_ERROR;
					goto error;
				}
				break;
			case LTTNG_EVENT_SYSCALL:
				ev->type = LTTNG_EVENT_SYSCALL;
				break;
			default:
				ret = CMD_UNDEFINED;
				goto error;
			}

			/* kernel loglevels not implemented */
			ev->loglevel_type = LTTNG_EVENT_LOGLEVEL_ALL;
		} else if (opt_userspace) { /* User-space tracer action */
			DBG("Enabling UST event %s for channel %s, loglevel %s",
			    pattern.c_str(),
			    print_channel_name(channel_name),
			    opt_loglevel ?: "<all>");

			switch (opt_event_type) {
			case LTTNG_EVENT_ALL: /* Default behavior is tracepoint */
				/* Fall-through */
			case LTTNG_EVENT_TRACEPOINT:
				/* Copy name and type of the event */
				ev->type = LTTNG_EVENT_TRACEPOINT;
				strncpy(ev->name, pattern.c_str(), LTTNG_SYMBOL_NAME_LEN);
				ev->name[LTTNG_SYMBOL_NAME_LEN - 1] = '\0';
				break;
			case LTTNG_EVENT_PROBE:
			case LTTNG_EVENT_FUNCTION:
			case LTTNG_EVENT_SYSCALL:
			case LTTNG_EVENT_USERSPACE_PROBE:
			default:
				ERR("Event type not available for user-space tracing");
				ret = CMD_UNSUPPORTED;
				goto error;
			}

			if (opt_exclude) {
				ev->exclusion = 1;
				if (opt_event_type != LTTNG_EVENT_ALL &&
				    opt_event_type != LTTNG_EVENT_TRACEPOINT) {
					ERR("Exclusion option can only be used with tracepoint events");
					ret = CMD_ERROR;
					goto error;
				}
				/* Free previously allocated items. */
				lttng_dynamic_pointer_array_reset(&exclusions);
				ret = create_exclusion_list_and_validate(
					pattern.c_str(), opt_exclude, &exclusions);
				if (ret) {
					ret = CMD_ERROR;
					goto error;
				}

				warn_on_truncated_exclusion_names(&exclusions, &warn);
			}

			ev->loglevel_type = (lttng_loglevel_type) opt_loglevel_type;
			if (opt_loglevel) {
				enum lttng_loglevel loglevel;
				const int name_search_ret =
					loglevel_name_to_value(opt_loglevel, &loglevel);

				if (name_search_ret == -1) {
					ERR("Unknown loglevel %s", opt_loglevel);
					ret = -LTTNG_ERR_INVALID;
					goto error;
				}

				ev->loglevel = (int) loglevel;
			} else {
				ev->loglevel = -1;
			}
		} else if (opt_jul || opt_log4j || opt_python) {
			if (opt_event_type != LTTNG_EVENT_ALL &&
			    opt_event_type != LTTNG_EVENT_TRACEPOINT) {
				ERR("Event type not supported for domain.");
				ret = CMD_UNSUPPORTED;
				goto error;
			}

			ev->loglevel_type = (lttng_loglevel_type) opt_loglevel_type;
			if (opt_loglevel) {
				int name_search_ret;

				if (opt_jul) {
					enum lttng_loglevel_jul loglevel;

					name_search_ret =
						loglevel_jul_name_to_value(opt_loglevel, &loglevel);
					ev->loglevel = (int) loglevel;
				} else if (opt_log4j) {
					enum lttng_loglevel_log4j loglevel;

					name_search_ret = loglevel_log4j_name_to_value(opt_loglevel,
										       &loglevel);
					ev->loglevel = (int) loglevel;
				} else {
					/* python domain. */
					enum lttng_loglevel_python loglevel;

					name_search_ret = loglevel_python_name_to_value(
						opt_loglevel, &loglevel);
					ev->loglevel = (int) loglevel;
				}

				if (name_search_ret) {
					ERR("Unknown loglevel %s", opt_loglevel);
					ret = -LTTNG_ERR_INVALID;
					goto error;
				}
			} else {
				if (opt_jul) {
					ev->loglevel = LTTNG_LOGLEVEL_JUL_ALL;
				} else if (opt_log4j) {
					ev->loglevel = LTTNG_LOGLEVEL_LOG4J_ALL;
				} else if (opt_python) {
					ev->loglevel = LTTNG_LOGLEVEL_PYTHON_DEBUG;
				}
			}
			ev->type = LTTNG_EVENT_TRACEPOINT;
			strncpy(ev->name, pattern.c_str(), LTTNG_SYMBOL_NAME_LEN);
			ev->name[LTTNG_SYMBOL_NAME_LEN - 1] = '\0';
		} else {
			abort();
		}

		if (!opt_filter) {
			char *exclusion_string;

			command_ret = lttng_enable_event_with_exclusions(
				handle,
				ev,
				channel_name,
				nullptr,
				lttng_dynamic_pointer_array_get_count(&exclusions),
				(char **) exclusions.array.buffer.data);
			exclusion_string = print_exclusions(&exclusions);
			if (!exclusion_string) {
				PERROR("Cannot allocate exclusion_string");
				error = 1;
				goto end;
			}
			if (command_ret < 0) {
				/* Turn ret to positive value to handle the positive error code */
				switch (-command_ret) {
				case LTTNG_ERR_KERN_EVENT_EXIST:
					WARN("Kernel event %s%s already enabled (channel %s, session %s)",
					     pattern.c_str(),
					     exclusion_string,
					     print_channel_name(channel_name),
					     session_name.c_str());
					warn = 1;
					break;
				case LTTNG_ERR_TRACE_ALREADY_STARTED:
				{
					const char *msg =
						"The command tried to enable an event in a new domain for a session that has already been started once.";
					ERR("Event %s%s: %s (channel %s, session %s)",
					    pattern.c_str(),
					    exclusion_string,
					    msg,
					    print_channel_name(channel_name),
					    session_name.c_str());
					error = 1;
					break;
				}
				case LTTNG_ERR_SDT_PROBE_SEMAPHORE:
					ERR("SDT probes %s guarded by semaphores are not supported (channel %s, session %s)",
					    pattern.c_str(),
					    print_channel_name(channel_name),
					    session_name.c_str());
					error = 1;
					break;
				default:
					ERR("Event %s%s: %s (channel %s, session %s)",
					    pattern.c_str(),
					    exclusion_string,
					    lttng_strerror(command_ret),
					    command_ret == -LTTNG_ERR_NEED_CHANNEL_NAME ?
						    print_raw_channel_name(channel_name) :
						    print_channel_name(channel_name),
					    session_name.c_str());
					error = 1;
					break;
				}
				error_holder = command_ret;
			} else {
				switch (dom.type) {
				case LTTNG_DOMAIN_KERNEL:
				case LTTNG_DOMAIN_UST:
					MSG("%s event %s%s created in channel %s",
					    lttng_domain_type_str(dom.type),
					    pattern.c_str(),
					    exclusion_string,
					    print_channel_name(channel_name));
					break;
				case LTTNG_DOMAIN_JUL:
				case LTTNG_DOMAIN_LOG4J:
				case LTTNG_DOMAIN_PYTHON:
					/*
					 * Don't print the default channel
					 * name for agent domains.
					 */
					MSG("%s event %s%s enabled",
					    lttng_domain_type_str(dom.type),
					    pattern.c_str(),
					    exclusion_string);
					break;
				default:
					abort();
				}
			}
			free(exclusion_string);
		}

		if (opt_filter) {
			char *exclusion_string;

			/* Filter present */
			ev->filter = 1;

			command_ret = lttng_enable_event_with_exclusions(
				handle,
				ev,
				channel_name,
				opt_filter,
				lttng_dynamic_pointer_array_get_count(&exclusions),
				(char **) exclusions.array.buffer.data);
			exclusion_string = print_exclusions(&exclusions);
			if (!exclusion_string) {
				PERROR("Cannot allocate exclusion_string");
				error = 1;
				goto end;
			}
			if (command_ret < 0) {
				switch (-command_ret) {
				case LTTNG_ERR_FILTER_EXIST:
					WARN("Filter on event %s%s is already enabled"
					     " (channel %s, session %s)",
					     pattern.c_str(),
					     exclusion_string,
					     print_channel_name(channel_name),
					     session_name.c_str());
					warn = 1;
					break;
				case LTTNG_ERR_TRACE_ALREADY_STARTED:
				{
					const char *msg =
						"The command tried to enable an event in a new domain for a session that has already been started once.";
					ERR("Event %s%s: %s (channel %s, session %s, filter \'%s\')",
					    ev->name,
					    exclusion_string,
					    msg,
					    print_channel_name(channel_name),
					    session_name.c_str(),
					    opt_filter);
					error = 1;
					break;
				}
				default:
					ERR("Event %s%s: %s (channel %s, session %s, filter \'%s\')",
					    ev->name,
					    exclusion_string,
					    lttng_strerror(command_ret),
					    command_ret == -LTTNG_ERR_NEED_CHANNEL_NAME ?
						    print_raw_channel_name(channel_name) :
						    print_channel_name(channel_name),
					    session_name.c_str(),
					    opt_filter);
					error = 1;
					break;
				}
				error_holder = command_ret;

			} else {
				MSG("Event %s%s: Filter '%s' successfully set",
				    pattern.c_str(),
				    exclusion_string,
				    opt_filter);
			}
			free(exclusion_string);
		}

		if (lttng_opt_mi) {
			if (command_ret) {
				success = 0;
				ev->enabled = 0;
			} else {
				ev->enabled = 1;
			}

			ret = mi_lttng_event(writer.get(), ev, 1, handle->domain.type);
			if (ret) {
				ret = CMD_ERROR;
				goto error;
			}

			/* print exclusion */
			ret = mi_print_exclusion(&exclusions);
			if (ret) {
				ret = CMD_ERROR;
				goto error;
			}

			/* Success ? */
			ret = mi_lttng_writer_write_element_bool(
				writer.get(), mi_lttng_element_command_success, success);
			if (ret) {
				ret = CMD_ERROR;
				goto end;
			}

			/* Close event element */
			ret = mi_lttng_writer_close_element(writer.get());
			if (ret) {
				ret = CMD_ERROR;
				goto end;
			}
		}

		/* Reset warn, error and success */
		success = 1;
	}

end:
	/* Close Mi */
	if (lttng_opt_mi) {
		/* Close events element */
		ret = mi_lttng_writer_close_element(writer.get());
		if (ret) {
			ret = CMD_ERROR;
			goto error;
		}
	}
error:
	if (warn) {
		ret = CMD_WARNING;
	}
	if (error) {
		ret = CMD_ERROR;
	}
	lttng_destroy_handle(handle);
	lttng_dynamic_pointer_array_reset(&exclusions);
	lttng_userspace_probe_location_destroy(uprobe_loc);

	/* Overwrite ret with error_holder if there was an actual error with
	 * enabling an event.
	 */
	ret = error_holder ? error_holder : ret;

	lttng_event_destroy(ev);
	return ret;
}

void _poptContextFree_deleter_func(poptContext ctx)
{
	poptFreeContext(ctx);
}

} /* namespace */

int validate_exclusion_list(const char *pattern,
			    const struct lttng_dynamic_pointer_array *exclusions)
{
	int ret;

	/* Event name must be a valid globbing pattern to allow exclusions. */
	if (!strutils_is_star_glob_pattern(pattern)) {
		ERR("Event %s: Exclusions can only be used with a globbing pattern", pattern);
		goto error;
	}

	/*
	 * If the event name is a star-at-end only globbing pattern,
	 * then we can validate the individual exclusions. Otherwise
	 * all exclusions are passed to the session daemon.
	 */
	if (strutils_is_star_at_the_end_only_glob_pattern(pattern)) {
		size_t i, num_exclusions;

		num_exclusions = lttng_dynamic_pointer_array_get_count(exclusions);

		for (i = 0; i < num_exclusions; i++) {
			const char *exclusion =
				(const char *) lttng_dynamic_pointer_array_get_pointer(exclusions,
										       i);

			if (!strutils_is_star_glob_pattern(exclusion) ||
			    strutils_is_star_at_the_end_only_glob_pattern(exclusion)) {
				ret = check_exclusion_subsets(pattern, exclusion);
				if (ret) {
					goto error;
				}
			}
		}
	}

	ret = 0;
	goto end;

error:
	ret = -1;

end:
	return ret;
}

/*
 * Add event to trace session
 */
int cmd_enable_events(int argc, const char **argv)
{
	int opt, ret = CMD_SUCCESS, command_ret = CMD_SUCCESS, success = 1;
	std::string session_name;
	const char *arg_event_list = nullptr;
	const char *leftover = nullptr;
	int event_type = -1;
	event_rule_patterns patterns;

	auto pc = lttng::make_unique_wrapper<poptContext_s, _poptContextFree_deleter_func>(
		poptGetContext(nullptr, argc, argv, long_options, 0));
	poptReadDefaultConfig(pc.get(), 0);

	/* Default event type */
	opt_event_type = LTTNG_EVENT_ALL;

	while ((opt = poptGetNextOpt(pc.get())) != -1) {
		switch (opt) {
		case OPT_HELP:
			SHOW_HELP();
			return CMD_SUCCESS;
		case OPT_TRACEPOINT:
			opt_event_type = LTTNG_EVENT_TRACEPOINT;
			break;
		case OPT_PROBE:
			opt_event_type = LTTNG_EVENT_PROBE;
			break;
		case OPT_USERSPACE_PROBE:
			opt_event_type = LTTNG_EVENT_USERSPACE_PROBE;
			break;
		case OPT_FUNCTION:
			opt_event_type = LTTNG_EVENT_FUNCTION;
			break;
		case OPT_SYSCALL:
			opt_event_type = LTTNG_EVENT_SYSCALL;
			break;
		case OPT_USERSPACE:
			opt_userspace = 1;
			break;
		case OPT_LOGLEVEL:
			opt_loglevel_type = LTTNG_EVENT_LOGLEVEL_RANGE;
			opt_loglevel = poptGetOptArg(pc.get());
			break;
		case OPT_LOGLEVEL_ONLY:
			opt_loglevel_type = LTTNG_EVENT_LOGLEVEL_SINGLE;
			opt_loglevel = poptGetOptArg(pc.get());
			break;
		case OPT_LIST_OPTIONS:
			list_cmd_options(stdout, long_options);
			return CMD_SUCCESS;
		case OPT_FILTER:
			break;
		case OPT_EXCLUDE:
			break;
		default:
			return CMD_UNDEFINED;
		}

		/* Validate event type. Multiple event type are not supported. */
		if (event_type == -1) {
			event_type = opt_event_type;
		} else {
			if (event_type != opt_event_type) {
				ERR("Multiple event type not supported.");
				return CMD_ERROR;
			}
		}
	}

	ret = print_missing_or_multiple_domains(
		opt_kernel + opt_userspace + opt_jul + opt_log4j + opt_python, true);
	if (ret) {
		return CMD_ERROR;
	}

	/* Mi check */
	if (lttng_opt_mi) {
		writer = mi_writer_uptr(mi_lttng_writer_create(fileno(stdout), lttng_opt_mi));
		if (!writer) {
			LTTNG_THROW_ERROR(lttng::format(
				"Failed to create MI writer: format_code={}", lttng_opt_mi));
		}

		/* Open command element */
		ret = mi_lttng_writer_command_open(writer.get(),
						   mi_lttng_element_command_enable_event);
		if (ret) {
			LTTNG_THROW_ERROR(lttng::format(
				"Failed to open MI command element: command_name=`{}`",
				mi_lttng_element_command_enable_event));
		}

		/* Open output element */
		ret = mi_lttng_writer_open_element(writer.get(), mi_lttng_element_command_output);
		if (ret) {
			LTTNG_THROW_ERROR(
				lttng::format("Failed to open MI element: element_name=`{}`",
					      mi_lttng_element_command_output));
		}
	}

	/* Close the MI command context when leaving the function, no matter the result. */
	const auto close_mi_on_exit = lttng::make_scope_exit([&success]() noexcept {
		if (!lttng_opt_mi) {
			return;
		}

		/* Close output element. */
		if (mi_lttng_writer_close_element(writer.get())) {
			ERR_FMT("Failed to close MI output element");
			return;
		}

		if (mi_lttng_writer_write_element_bool(
			    writer.get(), mi_lttng_element_command_success, success)) {
			ERR_FMT("Failed to write MI element: element_name=`{}`, value={}",
				mi_lttng_element_command_success,
				success);
			return;
		}

		/* Command element close. */
		if (mi_lttng_writer_command_close(writer.get())) {
			ERR_FMT("Failed to close MI command element");
			return;
		}
	});

	arg_event_list = poptGetArg(pc.get());
	if (arg_event_list == nullptr && opt_enable_all == 0) {
		ERR("Missing event name(s).");
		return CMD_ERROR;
	}

	if (opt_enable_all) {
		patterns.emplace_back("*");
	} else {
		std::stringstream event_list_arg_stream(arg_event_list);

		for (std::string line; std::getline(event_list_arg_stream, line, ',');) {
			patterns.emplace_back(std::move(line));
		}
	}

	leftover = poptGetArg(pc.get());
	if (leftover) {
		ERR("Unknown argument: %s", leftover);
		return CMD_ERROR;
	}

	if (!opt_session_name) {
		const auto rc_file_session_name =
			lttng::make_unique_wrapper<char, lttng::free>(get_session_name());

		if (!rc_file_session_name) {
			return CMD_ERROR;
		}

		session_name = rc_file_session_name.get();
	} else {
		session_name = opt_session_name;
	}

	command_ret = enable_events(session_name, patterns);
	if (command_ret) {
		return CMD_ERROR;
	}

	return CMD_SUCCESS;
}
