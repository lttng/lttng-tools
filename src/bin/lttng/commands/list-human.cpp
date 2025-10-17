/*
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 * SPDX-FileCopyrightText: 2020 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "../command.hpp"
#include "list-common.hpp"
#include "list-human.hpp"
#include "list-memory-usage.hpp"

#include <common/mi-lttng.hpp>

#include <lttng/domain-internal.hpp>
#include <lttng/lttng.h>

namespace lcm = lttng::cli::memory_usage;

const char *indent4 = "    ";
const char *indent6 = "      ";
const char *indent8 = "        ";

static struct lttng_handle *the_handle;

/* Only set when listing a single session. */
static struct lttng_session the_listed_session;

/* Configuration for the list command */
static const list_cmd_config *the_config;

/*
 * Get command line from /proc for a specific pid.
 *
 * On success, return an allocated string pointer to the proc cmdline.
 * On error, return NULL.
 */

static const char *active_string(int value)
{
	switch (value) {
	case 0:
		return "inactive";
	case 1:
		return "active";
	case -1:
		return "";
	default:
		return nullptr;
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

static const char *enabled_string(int value)
{
	switch (value) {
	case 0:
		return " [disabled]";
	case 1:
		return " [enabled]";
	case -1:
		return "";
	default:
		return nullptr;
	}
}

static const char *safe_string(const char *str)
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
	char *exclusion_msg = nullptr;
	char *at;
	size_t i;
	const char *const exclusion_fmt = " [exclusions: ";
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
	exclusion_msg = (char *) malloc(exclusion_count + exclusion_count * LTTNG_SYMBOL_NAME_LEN +
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

static void print_userspace_probe_location(struct lttng_event *event)
{
	const struct lttng_userspace_probe_location *location;
	const struct lttng_userspace_probe_location_lookup_method *lookup_method;
	enum lttng_userspace_probe_location_lookup_method_type lookup_type;

	location = lttng_event_get_userspace_probe_location(event);
	if (!location) {
		MSG("Event has no userspace probe location");
		return;
	}

	lookup_method = lttng_userspace_probe_location_get_lookup_method(location);
	if (!lookup_method) {
		MSG("Event has no userspace probe location lookup method");
		return;
	}

	MSG("%s%s (type: userspace-probe)%s", indent6, event->name, enabled_string(event->enabled));

	lookup_type = lttng_userspace_probe_location_lookup_method_get_type(lookup_method);

	switch (lttng_userspace_probe_location_get_type(location)) {
	case LTTNG_USERSPACE_PROBE_LOCATION_TYPE_UNKNOWN:
		MSG("%sType: Unknown", indent8);
		break;
	case LTTNG_USERSPACE_PROBE_LOCATION_TYPE_FUNCTION:
	{
		const char *function_name;
		char *binary_path;

		MSG("%sType: Function", indent8);
		function_name = lttng_userspace_probe_location_function_get_function_name(location);
		binary_path = realpath(
			lttng_userspace_probe_location_function_get_binary_path(location), nullptr);

		MSG("%sBinary path:   %s", indent8, binary_path ? binary_path : "NULL");
		MSG("%sFunction:      %s()", indent8, function_name ? function_name : "NULL");
		switch (lookup_type) {
		case LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_FUNCTION_ELF:
			MSG("%sLookup method: ELF", indent8);
			break;
		case LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_FUNCTION_DEFAULT:
			MSG("%sLookup method: default", indent8);
			break;
		default:
			MSG("%sLookup method: INVALID LOOKUP TYPE ENCOUNTERED", indent8);
			break;
		}

		free(binary_path);
		break;
	}
	case LTTNG_USERSPACE_PROBE_LOCATION_TYPE_TRACEPOINT:
	{
		const char *probe_name, *provider_name;
		char *binary_path;

		MSG("%sType: Tracepoint", indent8);
		probe_name = lttng_userspace_probe_location_tracepoint_get_probe_name(location);
		provider_name =
			lttng_userspace_probe_location_tracepoint_get_provider_name(location);
		binary_path = realpath(
			lttng_userspace_probe_location_tracepoint_get_binary_path(location),
			nullptr);
		MSG("%sBinary path:   %s", indent8, binary_path ? binary_path : "NULL");
		MSG("%sTracepoint:    %s:%s",
		    indent8,
		    provider_name ? provider_name : "NULL",
		    probe_name ? probe_name : "NULL");
		switch (lookup_type) {
		case LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_TRACEPOINT_SDT:
			MSG("%sLookup method: SDT", indent8);
			break;
		default:
			MSG("%sLookup method: INVALID LOOKUP TYPE ENCOUNTERED", indent8);
			break;
		}

		free(binary_path);
		break;
	}
	default:
		ERR("Invalid probe type encountered");
	}
}

/*
 * Pretty print single event.
 */
static void print_events(struct lttng_event *event)
{
	int ret;
	const char *filter_str;
	char *filter_msg = nullptr;
	char *exclusion_msg = nullptr;

	ret = lttng_event_get_filter_expression(event, &filter_str);

	if (ret) {
		filter_msg = strdup(" [failed to retrieve filter]");
	} else if (filter_str) {
		if (asprintf(&filter_msg, " [filter: '%s']", filter_str) == -1) {
			filter_msg = nullptr;
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
			    mi_lttng_loglevel_string(event->loglevel, the_handle->domain.type),
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
		MSG("%s%s (type: function)%s%s",
		    indent6,
		    event->name,
		    enabled_string(event->enabled),
		    safe_string(filter_msg));
		if (event->attr.probe.addr != 0) {
			MSG("%saddr: 0x%" PRIx64, indent8, event->attr.probe.addr);
		} else {
			MSG("%soffset: 0x%" PRIx64, indent8, event->attr.probe.offset);
			MSG("%ssymbol: %s", indent8, event->attr.probe.symbol_name);
		}
		break;
	case LTTNG_EVENT_PROBE:
		MSG("%s%s (type: probe)%s%s",
		    indent6,
		    event->name,
		    enabled_string(event->enabled),
		    safe_string(filter_msg));
		if (event->attr.probe.addr != 0) {
			MSG("%saddr: 0x%" PRIx64, indent8, event->attr.probe.addr);
		} else {
			MSG("%soffset: 0x%" PRIx64, indent8, event->attr.probe.offset);
			MSG("%ssymbol: %s", indent8, event->attr.probe.symbol_name);
		}
		break;
	case LTTNG_EVENT_USERSPACE_PROBE:
		print_userspace_probe_location(event);
		break;
	case LTTNG_EVENT_FUNCTION_ENTRY:
		MSG("%s%s (type: function)%s%s",
		    indent6,
		    event->name,
		    enabled_string(event->enabled),
		    safe_string(filter_msg));
		MSG("%ssymbol: \"%s\"", indent8, event->attr.ftrace.symbol_name);
		break;
	case LTTNG_EVENT_SYSCALL:
		MSG("%s%s%s%s%s%s",
		    indent6,
		    event->name,
		    (the_config->syscall ? "" : " (type:syscall)"),
		    enabled_string(event->enabled),
		    bitness_event(event->flags),
		    safe_string(filter_msg));
		break;
	case LTTNG_EVENT_NOOP:
		MSG("%s (type: noop)%s%s",
		    indent6,
		    enabled_string(event->enabled),
		    safe_string(filter_msg));
		break;
	case LTTNG_EVENT_ALL:
		/* Fall-through. */
	default:
		/* We should never have "all" events in list. */
		abort();
		break;
	}

	free(filter_msg);
	free(exclusion_msg);
}

static const char *field_type(struct lttng_event_field *field)
{
	switch (field->type) {
	case LTTNG_EVENT_FIELD_INTEGER:
		return "integer";
	case LTTNG_EVENT_FIELD_ENUM:
		return "enum";
	case LTTNG_EVENT_FIELD_FLOAT:
		return "float";
	case LTTNG_EVENT_FIELD_STRING:
		return "string";
	case LTTNG_EVENT_FIELD_OTHER:
	default: /* fall-through */
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
	MSG("%sfield: %s (%s)%s",
	    indent8,
	    field->field_name,
	    field_type(field),
	    field->nowrite ? " [no write]" : "");
}

static int list_agent_events()
{
	int i, size, ret = CMD_SUCCESS;
	struct lttng_domain domain;
	struct lttng_handle *handle = nullptr;
	struct lttng_event *event_list = nullptr;
	pid_t cur_pid = 0;
	char *cmdline = nullptr;
	const char *agent_domain_str;

	memset(&domain, 0, sizeof(domain));
	if (the_config->jul) {
		domain.type = LTTNG_DOMAIN_JUL;
	} else if (the_config->log4j) {
		domain.type = LTTNG_DOMAIN_LOG4J;
	} else if (the_config->log4j2) {
		domain.type = LTTNG_DOMAIN_LOG4J2;
	} else if (the_config->python) {
		domain.type = LTTNG_DOMAIN_PYTHON;
	} else {
		ERR("Invalid agent domain selected.");
		ret = CMD_ERROR;
		goto error;
	}

	agent_domain_str = lttng_domain_type_str(domain.type);

	DBG("Getting %s tracing events", agent_domain_str);

	handle = lttng_create_handle(nullptr, &domain);
	if (handle == nullptr) {
		ret = CMD_ERROR;
		goto end;
	}

	size = lttng_list_tracepoints(handle, &event_list);
	if (size < 0) {
		ERR("Unable to list %s events: %s", agent_domain_str, lttng_strerror(size));
		ret = CMD_ERROR;
		goto end;
	}

	/* Pretty print */
	MSG("%s events (Logger name):\n-------------------------", agent_domain_str);

	if (size == 0) {
		MSG("None");
	}

	for (i = 0; i < size; i++) {
		if (cur_pid != event_list[i].pid) {
			cur_pid = event_list[i].pid;
			cmdline = get_cmdline_by_pid(cur_pid);
			if (cmdline == nullptr) {
				ret = CMD_ERROR;
				goto error;
			}
			MSG("\nPID: %d - Name: %s", cur_pid, cmdline);
			free(cmdline);
		}
		MSG("%s- %s", indent6, event_list[i].name);
	}

	MSG("");

error:
	free(event_list);
end:
	lttng_destroy_handle(handle);
	return ret;
}

/*
 * Ask session daemon for all user space tracepoints available.
 */
static int list_ust_events()
{
	int i, size, ret = CMD_SUCCESS;
	struct lttng_domain domain;
	struct lttng_handle *handle;
	struct lttng_event *event_list = nullptr;
	pid_t cur_pid = 0;
	char *cmdline = nullptr;

	memset(&domain, 0, sizeof(domain));

	DBG("Getting UST tracing events");

	domain.type = LTTNG_DOMAIN_UST;

	handle = lttng_create_handle(nullptr, &domain);
	if (handle == nullptr) {
		ret = CMD_ERROR;
		goto end;
	}

	size = lttng_list_tracepoints(handle, &event_list);
	if (size < 0) {
		ERR("Unable to list UST events: %s", lttng_strerror(size));
		ret = CMD_ERROR;
		goto error;
	}

	/* Pretty print */
	MSG("UST events:\n-------------");

	if (size == 0) {
		MSG("None");
	}

	for (i = 0; i < size; i++) {
		if (cur_pid != event_list[i].pid) {
			cur_pid = event_list[i].pid;
			cmdline = get_cmdline_by_pid(cur_pid);
			if (cmdline == nullptr) {
				ret = CMD_ERROR;
				goto error;
			}
			MSG("\nPID: %d - Name: %s", cur_pid, cmdline);
			free(cmdline);
		}
		print_events(&event_list[i]);
	}

	MSG("");

error:
	free(event_list);
end:
	lttng_destroy_handle(handle);
	return ret;
}

/*
 * Ask session daemon for all user space tracepoint fields available.
 */
static int list_ust_event_fields()
{
	int i, size, ret = CMD_SUCCESS;
	struct lttng_domain domain;
	struct lttng_handle *handle;
	struct lttng_event_field *event_field_list;
	pid_t cur_pid = 0;
	char *cmdline = nullptr;

	struct lttng_event cur_event;

	memset(&domain, 0, sizeof(domain));
	memset(&cur_event, 0, sizeof(cur_event));

	DBG("Getting UST tracing event fields");

	domain.type = LTTNG_DOMAIN_UST;

	handle = lttng_create_handle(nullptr, &domain);
	if (handle == nullptr) {
		ret = CMD_ERROR;
		goto end;
	}

	size = lttng_list_tracepoint_fields(handle, &event_field_list);
	if (size < 0) {
		ERR("Unable to list UST event fields: %s", lttng_strerror(size));
		ret = CMD_ERROR;
		goto end;
	}

	/* Pretty print */
	MSG("UST events:\n-------------");

	if (size == 0) {
		MSG("None");
	}

	for (i = 0; i < size; i++) {
		if (cur_pid != event_field_list[i].event.pid) {
			cur_pid = event_field_list[i].event.pid;
			cmdline = get_cmdline_by_pid(cur_pid);
			if (cmdline == nullptr) {
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
			memcpy(&cur_event, &event_field_list[i].event, sizeof(cur_event));
		}
		print_event_field(&event_field_list[i]);
	}

	MSG("");

error:
	free(event_field_list);
end:
	lttng_destroy_handle(handle);
	return ret;
}

/*
 * Ask for all trace events in the kernel
 */
static int list_kernel_events()
{
	int i, size, ret = CMD_SUCCESS;
	struct lttng_domain domain;
	struct lttng_handle *handle;
	struct lttng_event *event_list;

	memset(&domain, 0, sizeof(domain));

	DBG("Getting kernel tracing events");

	domain.type = LTTNG_DOMAIN_KERNEL;

	handle = lttng_create_handle(nullptr, &domain);
	if (handle == nullptr) {
		ret = CMD_ERROR;
		goto end;
	}

	size = lttng_list_tracepoints(handle, &event_list);
	if (size < 0) {
		ERR("Unable to list kernel events: %s", lttng_strerror(size));
		lttng_destroy_handle(handle);
		return CMD_ERROR;
	}

	MSG("Kernel events:\n-------------");

	for (i = 0; i < size; i++) {
		print_events(&event_list[i]);
	}

	MSG("");
	free(event_list);

end:
	lttng_destroy_handle(handle);
	return ret;
}

/*
 * Ask for kernel system calls.
 */
static int list_syscalls()
{
	int i, size, ret = CMD_SUCCESS;
	struct lttng_event *event_list;

	DBG("Getting kernel system call events");

	size = lttng_list_syscalls(&event_list);
	if (size < 0) {
		ERR("Unable to list system calls: %s", lttng_strerror(size));
		ret = CMD_ERROR;
		goto end;
	}

	MSG("System calls:\n-------------");

	for (i = 0; i < size; i++) {
		print_events(&event_list[i]);
	}

	MSG("");
	free(event_list);

end:
	return ret;
}

/*
 * List agent events for a specific session using the handle.
 *
 * Return CMD_SUCCESS on success else a negative value.
 */
static int list_session_agent_events()
{
	int ret = CMD_SUCCESS, count, i;
	struct lttng_event *events = nullptr;

	count = lttng_list_events(the_handle, "", &events);
	if (count < 0) {
		ret = CMD_ERROR;
		ERR("%s", lttng_strerror(count));
		goto error;
	}

	/* Pretty print */
	MSG("Event rules:\n---------------------");
	if (count == 0) {
		MSG("%sNone\n", indent6);
		goto end;
	}

	for (i = 0; i < count; i++) {
		const char *filter_str;
		char *filter_msg = nullptr;
		struct lttng_event *event = &events[i];

		ret = lttng_event_get_filter_expression(event, &filter_str);
		if (ret) {
			filter_msg = strdup(" [failed to retrieve filter]");
		} else if (filter_str) {
			if (asprintf(&filter_msg, " [filter: '%s']", filter_str) == -1) {
				filter_msg = nullptr;
			}
		}

		if (event->loglevel_type != LTTNG_EVENT_LOGLEVEL_ALL) {
			MSG("%s- %s%s (loglevel%s %s)%s",
			    indent4,
			    event->name,
			    enabled_string(event->enabled),
			    logleveltype_string(event->loglevel_type),
			    mi_lttng_loglevel_string(event->loglevel, the_handle->domain.type),
			    safe_string(filter_msg));
		} else {
			MSG("%s- %s%s%s",
			    indent4,
			    event->name,
			    enabled_string(event->enabled),
			    safe_string(filter_msg));
		}
		free(filter_msg);
	}

	MSG("");

end:
	free(events);
error:
	return ret;
}

/*
 * List events of channel of session and domain.
 */
static int list_events(const char *channel_name)
{
	int ret = CMD_SUCCESS, count, i;
	struct lttng_event *events = nullptr;

	count = lttng_list_events(the_handle, channel_name, &events);
	if (count < 0) {
		ret = CMD_ERROR;
		ERR("%s", lttng_strerror(count));
		goto error;
	}

	/* Pretty print */
	MSG("\n%sRecording event rules:", indent4);
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
error:
	return ret;
}

static void print_timer(const char *timer_name, uint32_t space_count, int64_t value)
{
	uint32_t i;

	_MSG("%s%s:", indent6, timer_name);
	for (i = 0; i < space_count; i++) {
		_MSG(" ");
	}

	if (value) {
		MSG("%" PRId64 " %s", value, USEC_UNIT);
	} else {
		MSG("inactive");
	}
}

static const char *allocation_policy_to_pretty_string(enum lttng_channel_allocation_policy policy)
{
	switch (policy) {
	case LTTNG_CHANNEL_ALLOCATION_POLICY_PER_CPU:
		return "per-cpu";
	case LTTNG_CHANNEL_ALLOCATION_POLICY_PER_CHANNEL:
		return "per-channel";
	default:
		return "unknown";
	}
}

static const char *
preallocation_policy_to_pretty_string(enum lttng_channel_preallocation_policy policy)
{
	switch (policy) {
	case LTTNG_CHANNEL_PREALLOCATION_POLICY_PREALLOCATE:
		return "preallocate";
	case LTTNG_CHANNEL_PREALLOCATION_POLICY_ON_DEMAND:
		return "on-demand";
	default:
		return "unknown";
	}
}

static void print_detailed_mem_usage(struct lttng_channel *channel,
				     const struct lttng_data_stream_info_sets *ds_info_sets,
				     unsigned int ds_info_sets_count)
{
	enum lttng_data_stream_info_status status;

	for (unsigned int ds_info_set_i = 0; ds_info_set_i < ds_info_sets_count; ds_info_set_i++) {
		const struct lttng_data_stream_info_set *ds_info_set;
		nonstd::optional<uid_t> uid;
		nonstd::optional<pid_t> pid;
		nonstd::optional<enum lttng_app_bitness> app_bitness;
		unsigned int ds_info_count;

		status = lttng_data_stream_info_sets_get_at_index(
			ds_info_sets, ds_info_set_i, &ds_info_set);
		if (status != LTTNG_DATA_STREAM_INFO_STATUS_OK) {
			ERR_FMT("Failed to retrieve data stream info set #{} of channel `{}`",
				ds_info_set_i,
				channel->name);
			continue;
		}

		{
			uid_t tmp_uid;

			status = lttng_data_stream_info_set_get_uid(ds_info_set, &tmp_uid);
			if (status == LTTNG_DATA_STREAM_INFO_STATUS_OK) {
				uid = tmp_uid;
			} else if (status != LTTNG_DATA_STREAM_INFO_STATUS_NONE) {
				ERR_FMT("Failed to retrieve UID of data stream info set #{} of channel `{}`",
					ds_info_set_i,
					channel->name);
				continue;
			}
		}

		{
			pid_t tmp_pid;

			status = lttng_data_stream_info_set_get_pid(ds_info_set, &tmp_pid);
			if (status == LTTNG_DATA_STREAM_INFO_STATUS_OK) {
				pid = tmp_pid;
			} else if (status != LTTNG_DATA_STREAM_INFO_STATUS_NONE) {
				ERR_FMT("Failed to retrieve PID of data stream info set #{} of channel `{}`",
					ds_info_set_i,
					channel->name);
				continue;
			}
		}

		{
			enum lttng_app_bitness tmp_app_bitness;

			status = lttng_data_stream_info_set_get_app_bitness(ds_info_set,
									    &tmp_app_bitness);
			if (status == LTTNG_DATA_STREAM_INFO_STATUS_OK) {
				app_bitness = tmp_app_bitness;
			} else if (status != LTTNG_DATA_STREAM_INFO_STATUS_NONE) {
				ERR_FMT("Failed to retrieve ABI of data stream info set #{} of channel `{}`",
					ds_info_set_i,
					channel->name);
				continue;
			}
		}

		status = lttng_data_stream_info_set_get_count(ds_info_set, &ds_info_count);
		if (status != LTTNG_DATA_STREAM_INFO_STATUS_OK) {
			ERR_FMT("Failed to retrieve data stream info count of set #{} of channel `{}`",
				ds_info_set_i,
				channel->name);
			continue;
		}

		{
			std::string msg = fmt::format("Data streams for ", indent6);

			if (uid) {
				msg += fmt::format("UID {}", *uid);
			}

			if (pid) {
				msg += fmt::format("PID {}", *pid);
			}

			if (app_bitness) {
				msg += fmt::format(" ({}-bit)",
						   *app_bitness == LTTNG_APP_BITNESS_32 ? 32 : 64);
			}

			msg += fmt::format(": {}:",
					   utils_string_from_size(lcm::compute_set_memory_usage(
						   channel, ds_info_set, ds_info_set_i)));
			MSG("%s%s", indent6, msg.c_str());
		}

		for (unsigned int ds_info_i = 0; ds_info_i < ds_info_count; ds_info_i++) {
			const struct lttng_data_stream_info *ds_info;
			nonstd::optional<unsigned int> cpu_id;
			uint64_t mem_bytes;

			status = lttng_data_stream_info_set_get_at_index(
				ds_info_set, ds_info_i, &ds_info);
			if (status != LTTNG_DATA_STREAM_INFO_STATUS_OK) {
				ERR_FMT("Failed to retrieve data stream info #{} of set #{} of channel `{}`",
					ds_info_i,
					ds_info_set_i,
					channel->name);
				continue;
			}

			{
				unsigned int tmp_cpu_id;

				status = lttng_data_stream_info_get_cpu_id(ds_info, &tmp_cpu_id);
				if (status == LTTNG_DATA_STREAM_INFO_STATUS_OK) {
					cpu_id = tmp_cpu_id;
				} else if (status != LTTNG_DATA_STREAM_INFO_STATUS_NONE) {
					ERR_FMT("Failed to retrieve CPU ID of data stream info #{} of set {} of channel `{}`",
						ds_info_set_i,
						ds_info_set_i,
						channel->name);
					continue;
				}
			}

			status = lttng_data_stream_info_get_memory_usage(ds_info, &mem_bytes);
			if (status != LTTNG_DATA_STREAM_INFO_STATUS_OK) {
				ERR_FMT("Failed to retrieve memory usage of data stream info #{} of set {} of channel `{}`",
					ds_info_i,
					ds_info_set_i,
					channel->name);
				continue;
			}

			std::string msg = fmt::format("[{}] ", ds_info_i);

			if (cpu_id) {
				msg += fmt::format("CPU {}: ", *cpu_id);
			}

			msg += utils_string_from_size(mem_bytes);
			MSG("%s%s", indent8, msg.c_str());
		}
	}
}

static void print_mem_usage(struct lttng_channel *channel)
{
	try {
		const auto channel_mem_usage = lcm::get_channel_memory_usage(
			the_handle->session_name, channel, the_handle->domain.type);
		const auto msg =
			fmt::format("Buffer memory usage: {}",
				    utils_string_from_size(channel_mem_usage.total_memory_usage));

		if (the_config->stream_info_details &&
		    channel_mem_usage.data_stream_info_sets_count > 0) {
			MSG("\n%s%s:", indent4, msg.c_str());
			print_detailed_mem_usage(channel,
						 channel_mem_usage.data_stream_info_sets(),
						 channel_mem_usage.data_stream_info_sets_count);
		} else {
			MSG("\n%s%s", indent4, msg.c_str());
		}
	} catch (const lttng::unsupported_error& e) {
		/* This information is not available for all domains. */
		return;
	} catch (const std::exception& e) {
		ERR_FMT("Failed to retrieve memory usage of channel `{}`: {}",
			channel->name,
			e.what());
	}
}

/*
 * Pretty print channel
 */
static void print_channel(struct lttng_channel *channel)
{
	int ret;
	uint64_t discarded_events, lost_packets, monitor_timer_interval, watchdog_timer_interval;
	int64_t blocking_timeout;
	enum lttng_channel_allocation_policy allocation_policy;
	enum lttng_channel_get_watchdog_timer_interval_status watchdog_timer_status;
	bool print_watchdog_timer = false;

	ret = lttng_channel_get_discarded_event_count(channel, &discarded_events);
	if (ret) {
		ERR("Failed to retrieve discarded event count of channel");
		return;
	}

	ret = lttng_channel_get_lost_packet_count(channel, &lost_packets);
	if (ret) {
		ERR("Failed to retrieve lost packet count of channel");
		return;
	}

	ret = lttng_channel_get_monitor_timer_interval(channel, &monitor_timer_interval);
	if (ret) {
		ERR("Failed to retrieve monitor interval of channel");
		return;
	}

	watchdog_timer_status =
		lttng_channel_get_watchdog_timer_interval(channel, &watchdog_timer_interval);
	switch (watchdog_timer_status) {
	case LTTNG_CHANNEL_GET_WATCHDOG_TIMER_INTERVAL_STATUS_INVALID:
		ERR("Failed to retrieve watchdog interval of channel");
		return;
	case LTTNG_CHANNEL_GET_WATCHDOG_TIMER_INTERVAL_STATUS_UNSET:
		break;
	case LTTNG_CHANNEL_GET_WATCHDOG_TIMER_INTERVAL_STATUS_OK:
		print_watchdog_timer = true;
		break;
	}

	ret = lttng_channel_get_blocking_timeout(channel, &blocking_timeout);
	if (ret) {
		ERR("Failed to retrieve blocking timeout of channel");
		return;
	}

	ret = lttng_channel_get_allocation_policy(channel, &allocation_policy);
	if (ret != LTTNG_OK) {
		ERR("Failed to retrieve allocation policy of channel");
		return;
	}

	const auto allocation_policy_str = allocation_policy_to_pretty_string(allocation_policy);

	MSG("- %s:%s\n", channel->name, enabled_string(channel->enabled));
	MSG("%sAttributes:", indent4);
	MSG("%sAllocation policy: %s", indent6, allocation_policy_str);

	{
		enum lttng_channel_preallocation_policy preallocation_policy;
		const auto preallocation_ret =
			lttng_channel_get_preallocation_policy(channel, &preallocation_policy);
		if (preallocation_ret != LTTNG_OK) {
			ERR("Failed to retrieve preallocation policy of channel");
			return;
		}

		MSG("%sPreallocation policy: %s",
		    indent6,
		    preallocation_policy_to_pretty_string(preallocation_policy));
	}

	MSG("%sEvent-loss mode:   %s", indent6, channel->attr.overwrite ? "overwrite" : "discard");
	MSG("%sSub-buffer size:   %" PRIu64 " bytes", indent6, channel->attr.subbuf_size);
	MSG("%sSub-buffer count:  %" PRIu64, indent6, channel->attr.num_subbuf);

	{
		uint64_t maximal_age_us = 0;
		static const char *const prop_name = "Automatic memory reclamation policy";
		const auto reclamation_status =
			lttng_channel_get_automatic_memory_reclamation_policy(channel,
									      &maximal_age_us);
		if (reclamation_status == LTTNG_CHANNEL_STATUS_OK) {
			if (maximal_age_us == 0) {
				MSG("%s%s: consumed", indent6, prop_name);

			} else {
				MSG("%s%s: when older than %" PRIu64 " %s",
				    indent6,
				    prop_name,
				    maximal_age_us,
				    USEC_UNIT);
			}
		} else if (reclamation_status == LTTNG_CHANNEL_STATUS_UNSET) {
			MSG("%s%s: none", indent6, prop_name);
		} else {
			ERR("Failed to retrieve automatic memory reclamation policy of channel");
			return;
		}
	}

	print_timer("Switch timer", 6, channel->attr.switch_timer_interval);
	print_timer("Read timer", 8, channel->attr.read_timer_interval);
	print_timer("Monitor timer", 5, monitor_timer_interval);

	if (print_watchdog_timer) {
		print_timer("Watchdog timer", 4, watchdog_timer_interval);
	}

	if (!channel->attr.overwrite) {
		if (blocking_timeout == -1) {
			MSG("%sBlocking timeout:  infinite", indent6);
		} else {
			MSG("%sBlocking timeout:  %" PRId64 " %s",
			    indent6,
			    blocking_timeout,
			    USEC_UNIT);
		}
	}

	MSG("%sTrace file count:  %" PRIu64 " per stream",
	    indent6,
	    channel->attr.tracefile_count == 0 ? 1 : channel->attr.tracefile_count);
	if (channel->attr.tracefile_size != 0) {
		MSG("%sTrace file size:   %" PRIu64 " bytes",
		    indent6,
		    channel->attr.tracefile_size);
	} else {
		MSG("%sTrace file size:   %s", indent6, "unlimited");
	}
	switch (channel->attr.output) {
	case LTTNG_EVENT_SPLICE:
		MSG("%sOutput mode:       splice", indent6);
		break;
	case LTTNG_EVENT_MMAP:
		MSG("%sOutput mode:       mmap", indent6);
		break;
	}

	MSG("\n%sStatistics:", indent4);
	if (the_listed_session.snapshot_mode) {
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
	print_mem_usage(channel);
	return;
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
	struct lttng_channel *channels = nullptr;

	DBG("Listing channel(s) (%s)", channel_name ?: "<all>");

	count = lttng_list_channels(the_handle, &channels);
	if (count < 0) {
		switch (-count) {
		case LTTNG_ERR_KERN_CHAN_NOT_FOUND:
			/* In pretty-print mode, treat as no channels. */
			ret = CMD_SUCCESS;
			goto error_channels;
		default:
			/* We had a real error */
			ret = CMD_ERROR;
			ERR("%s", lttng_strerror(count));
			goto error_channels;
		}
	}

	/* Pretty print */
	if (count) {
		MSG("Channels:\n-------------");
	}

	for (i = 0; i < count; i++) {
		if (channel_name != nullptr) {
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

	if (!chan_found && channel_name != nullptr) {
		ret = CMD_ERROR;
		ERR("Channel %s not found", channel_name);
		goto error;
	}
error:
	free(channels);

error_channels:
	return ret;
}

static const char *get_capitalized_process_attr_str(enum lttng_process_attr process_attr)
{
	switch (process_attr) {
	case LTTNG_PROCESS_ATTR_PROCESS_ID:
		return "Process ID";
	case LTTNG_PROCESS_ATTR_VIRTUAL_PROCESS_ID:
		return "Virtual process ID";
	case LTTNG_PROCESS_ATTR_USER_ID:
		return "User ID";
	case LTTNG_PROCESS_ATTR_VIRTUAL_USER_ID:
		return "Virtual user ID";
	case LTTNG_PROCESS_ATTR_GROUP_ID:
		return "Group ID";
	case LTTNG_PROCESS_ATTR_VIRTUAL_GROUP_ID:
		return "Virtual group ID";
	default:
		return "Unknown";
	}
	return nullptr;
}

static inline bool is_value_type_name(enum lttng_process_attr_value_type value_type)
{
	return value_type == LTTNG_PROCESS_ATTR_VALUE_TYPE_USER_NAME ||
		value_type == LTTNG_PROCESS_ATTR_VALUE_TYPE_GROUP_NAME;
}

/*
 * List a process attribute tracker for a session and domain tuple.
 */
static int list_process_attr_tracker(enum lttng_process_attr process_attr)
{
	int ret = 0;
	unsigned int count, i;
	enum lttng_tracking_policy policy;
	enum lttng_error_code ret_code;
	enum lttng_process_attr_tracker_handle_status handle_status;
	enum lttng_process_attr_values_status values_status;
	const struct lttng_process_attr_values *values;
	struct lttng_process_attr_tracker_handle *tracker_handle = nullptr;

	ret_code = lttng_session_get_tracker_handle(
		the_handle->session_name, the_handle->domain.type, process_attr, &tracker_handle);
	if (ret_code != LTTNG_OK) {
		ERR("Failed to get process attribute tracker handle: %s", lttng_strerror(ret_code));
		ret = CMD_ERROR;
		goto end;
	}

	handle_status =
		lttng_process_attr_tracker_handle_get_inclusion_set(tracker_handle, &values);
	ret = handle_process_attr_status(process_attr, handle_status, the_handle->session_name);
	if (ret != CMD_SUCCESS) {
		goto end;
	}

	handle_status =
		lttng_process_attr_tracker_handle_get_tracking_policy(tracker_handle, &policy);
	ret = handle_process_attr_status(process_attr, handle_status, the_handle->session_name);
	if (ret != CMD_SUCCESS) {
		goto end;
	}

	{
		char *process_attr_name;
		const int print_ret = asprintf(
			&process_attr_name, "%ss:", get_capitalized_process_attr_str(process_attr));

		if (print_ret == -1) {
			ret = CMD_FATAL;
			goto end;
		}
		_MSG("  %-22s", process_attr_name);
		free(process_attr_name);
	}
	switch (policy) {
	case LTTNG_TRACKING_POLICY_INCLUDE_SET:
		break;
	case LTTNG_TRACKING_POLICY_EXCLUDE_ALL:
		MSG("none");
		ret = CMD_SUCCESS;
		goto end;
	case LTTNG_TRACKING_POLICY_INCLUDE_ALL:
		MSG("all");
		ret = CMD_SUCCESS;
		goto end;
	default:
		ERR("Unknown tracking policy encountered while listing the %s process attribute tracker of session `%s`",
		    lttng_process_attr_to_string(process_attr),
		    the_handle->session_name);
		ret = CMD_FATAL;
		goto end;
	}

	values_status = lttng_process_attr_values_get_count(values, &count);
	if (values_status != LTTNG_PROCESS_ATTR_VALUES_STATUS_OK) {
		ERR("Failed to get the count of values in the inclusion set of the %s process attribute tracker of session `%s`",
		    lttng_process_attr_to_string(process_attr),
		    the_handle->session_name);
		ret = CMD_FATAL;
		goto end;
	}

	if (count == 0) {
		/* Functionally equivalent to the 'exclude all' policy. */
		MSG("none");
		ret = CMD_SUCCESS;
		goto end;
	}

	for (i = 0; i < count; i++) {
		const enum lttng_process_attr_value_type value_type =
			lttng_process_attr_values_get_type_at_index(values, i);
		int64_t integral_value = INT64_MAX;
		const char *name = "error";

		if (i >= 1) {
			_MSG(", ");
		}
		switch (value_type) {
		case LTTNG_PROCESS_ATTR_VALUE_TYPE_PID:
		{
			pid_t pid;

			values_status = lttng_process_attr_values_get_pid_at_index(values, i, &pid);
			integral_value = (int64_t) pid;
			break;
		}
		case LTTNG_PROCESS_ATTR_VALUE_TYPE_UID:
		{
			uid_t uid;

			values_status = lttng_process_attr_values_get_uid_at_index(values, i, &uid);
			integral_value = (int64_t) uid;
			break;
		}
		case LTTNG_PROCESS_ATTR_VALUE_TYPE_GID:
		{
			gid_t gid;

			values_status = lttng_process_attr_values_get_gid_at_index(values, i, &gid);
			integral_value = (int64_t) gid;
			break;
		}
		case LTTNG_PROCESS_ATTR_VALUE_TYPE_USER_NAME:
			values_status =
				lttng_process_attr_values_get_user_name_at_index(values, i, &name);
			break;
		case LTTNG_PROCESS_ATTR_VALUE_TYPE_GROUP_NAME:
			values_status =
				lttng_process_attr_values_get_group_name_at_index(values, i, &name);
			break;
		default:
			ret = CMD_ERROR;
			goto end;
		}

		if (values_status != LTTNG_PROCESS_ATTR_VALUES_STATUS_OK) {
			/*
			 * Not possible given the current liblttng-ctl
			 * implementation.
			 */
			ERR("Unknown error occurred while fetching process attribute value in inclusion list");
			ret = CMD_FATAL;
			goto end;
		}

		if (is_value_type_name(value_type)) {
			_MSG("`%s`", name);
		} else {
			_MSG("%" PRIi64, integral_value);
		}
	}
	MSG("");

end:
	lttng_process_attr_tracker_handle_destroy(tracker_handle);
	return ret;
}

/*
 * List all trackers of a domain
 */
static int list_trackers(const struct lttng_domain *domain)
{
	int ret = 0;

	MSG("Tracked process attributes");

	switch (domain->type) {
	case LTTNG_DOMAIN_KERNEL:
		/* pid tracker */
		ret = list_process_attr_tracker(LTTNG_PROCESS_ATTR_PROCESS_ID);
		if (ret) {
			goto end;
		}
		/* vpid tracker */
		ret = list_process_attr_tracker(LTTNG_PROCESS_ATTR_VIRTUAL_PROCESS_ID);
		if (ret) {
			goto end;
		}
		/* uid tracker */
		ret = list_process_attr_tracker(LTTNG_PROCESS_ATTR_USER_ID);
		if (ret) {
			goto end;
		}
		/* vuid tracker */
		ret = list_process_attr_tracker(LTTNG_PROCESS_ATTR_VIRTUAL_USER_ID);
		if (ret) {
			goto end;
		}
		/* gid tracker */
		ret = list_process_attr_tracker(LTTNG_PROCESS_ATTR_GROUP_ID);
		if (ret) {
			goto end;
		}
		/* vgid tracker */
		ret = list_process_attr_tracker(LTTNG_PROCESS_ATTR_VIRTUAL_GROUP_ID);
		if (ret) {
			goto end;
		}
		break;
	case LTTNG_DOMAIN_UST:
		/* vpid tracker */
		ret = list_process_attr_tracker(LTTNG_PROCESS_ATTR_VIRTUAL_PROCESS_ID);
		if (ret) {
			goto end;
		}
		/* vuid tracker */
		ret = list_process_attr_tracker(LTTNG_PROCESS_ATTR_VIRTUAL_USER_ID);
		if (ret) {
			goto end;
		}
		/* vgid tracker */
		ret = list_process_attr_tracker(LTTNG_PROCESS_ATTR_VIRTUAL_GROUP_ID);
		if (ret) {
			goto end;
		}
		break;
	default:
		break;
	}
	MSG();

end:
	return ret;
}

static enum cmd_error_code
print_periodic_rotation_schedule(const struct lttng_rotation_schedule *schedule)
{
	enum cmd_error_code ret;
	enum lttng_rotation_status status;
	uint64_t value;

	status = lttng_rotation_schedule_periodic_get_period(schedule, &value);
	if (status != LTTNG_ROTATION_STATUS_OK) {
		ERR("Failed to retrieve period parameter from periodic rotation schedule.");
		ret = CMD_ERROR;
		goto end;
	}

	MSG("    timer period: %" PRIu64 " %s", value, USEC_UNIT);
	ret = CMD_SUCCESS;
end:
	return ret;
}

static enum cmd_error_code
print_size_threshold_rotation_schedule(const struct lttng_rotation_schedule *schedule)
{
	enum cmd_error_code ret;
	enum lttng_rotation_status status;
	uint64_t value;

	status = lttng_rotation_schedule_size_threshold_get_threshold(schedule, &value);
	if (status != LTTNG_ROTATION_STATUS_OK) {
		ERR("Failed to retrieve size parameter from size-based rotation schedule.");
		ret = CMD_ERROR;
		goto end;
	}

	MSG("    size threshold: %" PRIu64 " bytes", value);
	ret = CMD_SUCCESS;
end:
	return ret;
}

static enum cmd_error_code print_rotation_schedule(const struct lttng_rotation_schedule *schedule)
{
	enum cmd_error_code ret;

	switch (lttng_rotation_schedule_get_type(schedule)) {
	case LTTNG_ROTATION_SCHEDULE_TYPE_SIZE_THRESHOLD:
		ret = print_size_threshold_rotation_schedule(schedule);
		break;
	case LTTNG_ROTATION_SCHEDULE_TYPE_PERIODIC:
		ret = print_periodic_rotation_schedule(schedule);
		break;
	default:
		ret = CMD_ERROR;
	}
	return ret;
}

/*
 * List the automatic rotation settings.
 */
static enum cmd_error_code list_rotate_settings(const char *session_name)
{
	int ret;
	enum cmd_error_code cmd_ret = CMD_SUCCESS;
	unsigned int count, i;
	struct lttng_rotation_schedules *schedules = nullptr;
	enum lttng_rotation_status status;

	ret = lttng_session_list_rotation_schedules(session_name, &schedules);
	if (ret != LTTNG_OK) {
		ERR("Failed to list session rotation schedules: %s", lttng_strerror(ret));
		cmd_ret = CMD_ERROR;
		goto end;
	}

	status = lttng_rotation_schedules_get_count(schedules, &count);
	if (status != LTTNG_ROTATION_STATUS_OK) {
		ERR("Failed to retrieve the number of session rotation schedules.");
		cmd_ret = CMD_ERROR;
		goto end;
	}

	if (count == 0) {
		cmd_ret = CMD_SUCCESS;
		goto end;
	}

	MSG("Automatic rotation schedules:");

	for (i = 0; i < count; i++) {
		enum cmd_error_code tmp_ret = CMD_SUCCESS;
		const struct lttng_rotation_schedule *schedule;

		schedule = lttng_rotation_schedules_get_at_index(schedules, i);
		if (!schedule) {
			ERR("Failed to retrieve session rotation schedule.");
			cmd_ret = CMD_ERROR;
			goto end;
		}

		tmp_ret = print_rotation_schedule(schedule);

		/*
		 * Report an error if the serialization of any of the
		 * descriptors failed.
		 */
		cmd_ret = cmd_ret ? cmd_ret : tmp_ret;
	}

	_MSG("\n");
end:
	lttng_rotation_schedules_destroy(schedules);
	return cmd_ret;
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
	struct lttng_session *sessions = nullptr;

	count = lttng_list_sessions(&sessions);
	DBG("Session count %d", count);
	if (count < 0) {
		ret = CMD_ERROR;
		ERR("%s", lttng_strerror(count));
		goto end;
	}

	/* Pretty print */
	if (count == 0) {
		MSG("Currently no available recording session");
		goto end;
	}

	if (session_name == nullptr) {
		MSG("Available recording sessions:");
	}

	for (i = 0; i < count; i++) {
		if (session_name != nullptr) {
			if (strncmp(sessions[i].name, session_name, NAME_MAX) == 0) {
				session_found = 1;
				MSG("Recording session %s: [%s%s]",
				    session_name,
				    active_string(sessions[i].enabled),
				    snapshot_string(sessions[i].snapshot_mode));
				if (*sessions[i].path) {
					MSG("%sTrace output: %s\n", indent4, sessions[i].path);
				}
				memcpy(&the_listed_session,
				       &sessions[i],
				       sizeof(the_listed_session));
				break;
			}
		} else {
			MSG("  %d) %s [%s%s]",
			    i + 1,
			    sessions[i].name,
			    active_string(sessions[i].enabled),
			    snapshot_string(sessions[i].snapshot_mode));
			if (*sessions[i].path) {
				MSG("%sTrace output: %s", indent4, sessions[i].path);
			}
			if (sessions[i].live_timer_interval != 0) {
				MSG("%sLive timer interval: %u %s",
				    indent4,
				    sessions[i].live_timer_interval,
				    USEC_UNIT);
			}
			MSG("");
		}
	}

	if (!session_found && session_name != nullptr) {
		ERR("Session '%s' not found", session_name);
		ret = CMD_ERROR;
		goto end;
	}

	if (session_name == nullptr) {
		MSG("\nUse lttng list <session_name> for more details");
	}

end:
	free(sessions);
	return ret;
}

/*
 * List available domain(s) for a session.
 */
static int list_domains(const char *session_name)
{
	int i, count, ret = CMD_SUCCESS;
	struct lttng_domain *domains = nullptr;

	count = lttng_list_domains(session_name, &domains);
	if (count < 0) {
		ret = CMD_ERROR;
		ERR("%s", lttng_strerror(count));
		goto end;
	}

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
			MSG("  - JUL (java.util.logging)");
			break;
		case LTTNG_DOMAIN_LOG4J:
			MSG("  - Log4j");
			break;
		case LTTNG_DOMAIN_LOG4J2:
			MSG("  - Log4j2");
			break;
		case LTTNG_DOMAIN_PYTHON:
			MSG("  - Python (logging)");
			break;
		default:
			break;
		}
	}

end:
	free(domains);
	return ret;
}

/*
 * Pretty-print (human-readable) output for the list command.
 *
 * This function implements the non-MI output format for listing sessions,
 * domains, channels, events, and trackers.
 */
int list_human(const list_cmd_config& config)
{
	int ret = CMD_SUCCESS;
	struct lttng_domain domain;
	struct lttng_domain *domains = nullptr;

	/* Cache configuration for use by helpers */
	the_config = &config;

	/* Initialize domain based on config */
	memset(&domain, 0, sizeof(domain));
	if (config.domain_type) {
		domain.type = *config.domain_type;
	}

	if (config.kernel || config.userspace || config.jul || config.log4j || config.log4j2 ||
	    config.python) {
		the_handle = lttng_create_handle(
			config.session_name ? config.session_name->c_str() : nullptr, &domain);
		if (the_handle == nullptr) {
			ret = CMD_FATAL;
			goto end;
		}
	}

	if (!config.session_name) {
		if (!config.kernel && !config.userspace && !config.jul && !config.log4j &&
		    !config.log4j2 && !config.python) {
			ret = list_sessions(nullptr);
			if (ret) {
				goto end;
			}
		}
		if (config.kernel) {
			if (config.syscall) {
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
		if (config.userspace) {
			if (config.fields) {
				ret = list_ust_event_fields();
			} else {
				ret = list_ust_events();
			}
			if (ret) {
				goto end;
			}
		}
		if (config.jul || config.log4j || config.log4j2 || config.python) {
			ret = list_agent_events();
			if (ret) {
				goto end;
			}
		}
	} else {
		/* List session attributes */
		ret = list_sessions(config.session_name->c_str());
		if (ret) {
			goto end;
		}

		ret = list_rotate_settings(config.session_name->c_str());
		if (ret) {
			goto end;
		}

		/* Domain listing */
		if (config.domain) {
			ret = list_domains(config.session_name->c_str());
			goto end;
		}

		/* Channel listing */
		if (config.kernel || config.userspace) {
			/* Trackers */
			ret = list_trackers(&domain);
			if (ret) {
				goto end;
			}

			/* Channels */
			ret = list_channels(config.channel_name ? config.channel_name->c_str() :
								  nullptr);
			if (ret) {
				goto end;
			}
		} else {
			int i, nb_domain;

			/* We want all domain(s) */
			nb_domain = lttng_list_domains(config.session_name->c_str(), &domains);
			if (nb_domain < 0) {
				ret = CMD_ERROR;
				ERR("%s", lttng_strerror(nb_domain));
				goto end;
			}

			for (i = 0; i < nb_domain; i++) {
				switch (domains[i].type) {
				case LTTNG_DOMAIN_KERNEL:
					MSG("=== Domain: Linux kernel ===\n");
					break;
				case LTTNG_DOMAIN_UST:
					MSG("=== Domain: User space ===\n");
					MSG("Buffering scheme: %s\n",
					    domains[i].buf_type == LTTNG_BUFFER_PER_PID ?
						    "per-process" :
						    "per-user");
					break;
				case LTTNG_DOMAIN_JUL:
					MSG("=== Domain: JUL (java.util.logging) ===\n");
					break;
				case LTTNG_DOMAIN_LOG4J:
					MSG("=== Domain: Log4j ===\n");
					break;
				case LTTNG_DOMAIN_LOG4J2:
					MSG("=== Domain: Log4j2 ===\n");
					break;
				case LTTNG_DOMAIN_PYTHON:
					MSG("=== Domain: Python logging ===\n");
					break;
				default:
					MSG("=== Domain: Unimplemented ===\n");
					break;
				}

				/* Clean handle before creating a new one */
				if (the_handle) {
					lttng_destroy_handle(the_handle);
				}

				the_handle = lttng_create_handle(config.session_name->c_str(),
								 &domains[i]);
				if (the_handle == nullptr) {
					ret = CMD_FATAL;
					goto end;
				}

				if (domains[i].type == LTTNG_DOMAIN_JUL ||
				    domains[i].type == LTTNG_DOMAIN_LOG4J ||
				    domains[i].type == LTTNG_DOMAIN_LOG4J2 ||
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
					ret = list_trackers(&domains[i]);
					if (ret) {
						goto end;
					}
					break;
				default:
					break;
				}

				ret = list_channels(config.channel_name ?
							    config.channel_name->c_str() :
							    nullptr);
				if (ret) {
					goto end;
				}

			next_domain:;
			}
		}
	}

end:
	free(domains);
	if (the_handle) {
		lttng_destroy_handle(the_handle);
	}

	return ret;
}
