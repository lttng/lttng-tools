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
#include "list-wrappers.hpp"

#include <common/mi-lttng.hpp>

#include <lttng/domain-internal.hpp>
#include <lttng/lttng.h>

const char *indent4 = "    ";
const char *indent6 = "      ";
const char *indent8 = "        ";

/* Configuration for the list command */
static const list_cmd_config *the_config;

static bool is_agent_domain(lttng_domain_type domain_type)
{
	return domain_type == LTTNG_DOMAIN_JUL || domain_type == LTTNG_DOMAIN_LOG4J ||
		domain_type == LTTNG_DOMAIN_LOG4J2 || domain_type == LTTNG_DOMAIN_PYTHON;
}

static bool is_ust_or_agent_domain(lttng_domain_type domain_type)
{
	return domain_type == LTTNG_DOMAIN_UST || is_agent_domain(domain_type);
}

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
 * Get exclusion names message for a UST tracepoint event rule.
 *
 * Returned pointer must be freed by caller. Returns NULL on error.
 */
static char *get_exclusion_names_msg(const lttng::cli::ust_tracepoint_event_rule& event_rule)
{
	char *exclusion_msg = nullptr;
	const char *const exclusion_fmt = " [exclusions: ";
	const size_t exclusion_fmt_len = strlen(exclusion_fmt);
	const auto exclusions = event_rule.exclusions();

	if (exclusions.empty()) {
		/*
		 * No exclusions: return copy of empty string so that
		 * it can be freed by caller.
		 */
		exclusion_msg = strdup("");
		return exclusion_msg;
	}

	/*
	 * exclusion_msg's size is bounded by the exclusion_fmt string,
	 * a comma per entry, the entry count (fixed-size), a closing
	 * bracket, and a trailing \0.
	 */
	const auto exclusion_count = exclusions.size();

	exclusion_msg = (char *) malloc(exclusion_count + exclusion_count * LTTNG_SYMBOL_NAME_LEN +
					exclusion_fmt_len + 1);
	if (!exclusion_msg) {
		return nullptr;
	}

	char *at = strcpy(exclusion_msg, exclusion_fmt) + exclusion_fmt_len;
	bool first = true;

	for (const auto& exclusion : exclusions) {
		/* Append comma between exclusion names */
		if (!first) {
			*at = ',';
			at++;
		}

		first = false;

		/* Append exclusion name */
		at += sprintf(at, "%s", exclusion.data());
	}

	/* This also puts a final '\0' at the end of exclusion_msg */
	strcpy(at, "]");

	return exclusion_msg;
}

static void print_userspace_probe_location(const lttng::cli::linux_uprobe_event_rule& uprobe_event)
{
	const auto location = uprobe_event.location();

	if (!location) {
		MSG("Event has no userspace probe location");
		return;
	}

	MSG("%s%s (type: userspace-probe)%s",
	    indent6,
	    uprobe_event.name().data(),
	    enabled_string(uprobe_event.is_enabled()));

	switch (location->type()) {
	case LTTNG_USERSPACE_PROBE_LOCATION_TYPE_UNKNOWN:
		MSG("%sType: Unknown", indent8);
		break;
	case LTTNG_USERSPACE_PROBE_LOCATION_TYPE_FUNCTION:
	{
		const auto func_location = location->as_function();
		char *binary_path = realpath(func_location.binary_path().data(), nullptr);

		MSG("%sType: Function", indent8);
		MSG("%sBinary path:   %s", indent8, binary_path ? binary_path : "NULL");
		MSG("%sFunction:      %s()", indent8, func_location.function_name().data());

		switch (location->lookup_method_type()) {
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
		const auto tp_location = location->as_tracepoint();
		char *binary_path = realpath(tp_location.binary_path().data(), nullptr);

		MSG("%sType: Tracepoint", indent8);
		MSG("%sBinary path:   %s", indent8, binary_path ? binary_path : "NULL");
		MSG("%sTracepoint:    %s:%s",
		    indent8,
		    tp_location.provider_name().data(),
		    tp_location.probe_name().data());

		switch (location->lookup_method_type()) {
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
 * Pretty print instrumentation point (kernel tracepoint, UST tracepoint, syscall, agent logger).
 */
static void print_instrumentation_point(const lttng::cli::instrumentation_point& instr_point,
					enum lttng_domain_type domain_type)
{
	switch (instr_point.lib().type) {
	case LTTNG_EVENT_TRACEPOINT:
	{
		if (domain_type == LTTNG_DOMAIN_KERNEL) {
			/* Kernel tracepoint - no loglevel */
			MSG("%s%s (type: tracepoint)", indent6, instr_point.name().data());
		} else {
			/* UST/agent instrumentation point - has loglevel */
			int loglevel = -1;

			if (domain_type == LTTNG_DOMAIN_UST) {
				loglevel =
					static_cast<const lttng::cli::ust_tracepoint&>(instr_point)
						.log_level();
			}

			if (loglevel != -1) {
				MSG("%s%s (loglevel: %s (%d)) (type: tracepoint)",
				    indent6,
				    instr_point.name().data(),
				    mi_lttng_loglevel_string(loglevel, domain_type),
				    loglevel);
			} else {
				MSG("%s%s (type: tracepoint)", indent6, instr_point.name().data());
			}
		}
		break;
	}
	case LTTNG_EVENT_SYSCALL:
		MSG("%s%s%s%s",
		    indent6,
		    instr_point.name().data(),
		    (the_config->syscall ? "" : " (type:syscall)"),
		    bitness_event(instr_point.lib().flags));
		break;
	default:
		/* Should not happen for instrumentation points */
		abort();
		break;
	}
}

/*
 * Pretty print single event rule (from a channel).
 */
static void print_events(const lttng::cli::event_rule& event_rule,
			 enum lttng_domain_type domain_type)
{
	char *filter_msg = nullptr;
	char *exclusion_msg = nullptr;

	const auto filter_expr = event_rule.filter_expression();
	if (filter_expr) {
		if (asprintf(&filter_msg, " [filter: '%s']", filter_expr.data()) == -1) {
			filter_msg = nullptr;
		}
	}

	/* Exclusions are only supported for UST tracepoint event rules */
	if (domain_type == LTTNG_DOMAIN_UST && event_rule.type() == LTTNG_EVENT_TRACEPOINT) {
		const auto ust_event = event_rule.as_ust_tracepoint();
		exclusion_msg = get_exclusion_names_msg(ust_event);
		if (!exclusion_msg) {
			exclusion_msg = strdup(" [failed to retrieve exclusions]");
		}
	} else {
		exclusion_msg = strdup("");
	}

	switch (event_rule.type()) {
	case LTTNG_EVENT_TRACEPOINT:
	{
		if (domain_type == LTTNG_DOMAIN_UST || domain_type == LTTNG_DOMAIN_JUL ||
		    domain_type == LTTNG_DOMAIN_LOG4J || domain_type == LTTNG_DOMAIN_LOG4J2 ||
		    domain_type == LTTNG_DOMAIN_PYTHON) {
			const auto ust_or_agent_event = event_rule.as_ust_tracepoint();
			const auto loglevel = ust_or_agent_event.log_level();

			if (loglevel != -1) {
				MSG("%s%s (loglevel%s %s (%d)) (type: tracepoint)%s%s%s",
				    indent6,
				    event_rule.name().data(),
				    logleveltype_string(ust_or_agent_event.log_level_type()),
				    mi_lttng_loglevel_string(loglevel, domain_type),
				    loglevel,
				    enabled_string(event_rule.is_enabled()),
				    safe_string(exclusion_msg),
				    safe_string(filter_msg));
			} else {
				MSG("%s%s (type: tracepoint)%s%s%s",
				    indent6,
				    event_rule.name().data(),
				    enabled_string(event_rule.is_enabled()),
				    safe_string(exclusion_msg),
				    safe_string(filter_msg));
			}
		} else {
			/* Kernel tracepoint event rule */
			MSG("%s%s (type: tracepoint)%s%s%s",
			    indent6,
			    event_rule.name().data(),
			    enabled_string(event_rule.is_enabled()),
			    safe_string(exclusion_msg),
			    safe_string(filter_msg));
		}
		break;
	}
	case LTTNG_EVENT_FUNCTION:
	case LTTNG_EVENT_PROBE:
	{
		const auto kprobe_event = event_rule.as_linux_kprobe();

		MSG("%s%s (type: %s)%s%s",
		    indent6,
		    event_rule.name().data(),
		    event_rule.type() == LTTNG_EVENT_FUNCTION ? "function" : "probe",
		    enabled_string(event_rule.is_enabled()),
		    safe_string(filter_msg));

		if (kprobe_event.address() != 0) {
			MSG("%saddr: 0x%" PRIx64, indent8, kprobe_event.address());
		} else {
			MSG("%soffset: 0x%" PRIx64, indent8, kprobe_event.offset());
			MSG("%ssymbol: %s", indent8, kprobe_event.symbol_name().data());
		}
		break;
	}
	case LTTNG_EVENT_USERSPACE_PROBE:
		print_userspace_probe_location(event_rule.as_linux_uprobe());
		break;
	case LTTNG_EVENT_SYSCALL:
		MSG("%s%s%s%s%s%s",
		    indent6,
		    event_rule.name().data(),
		    (the_config->syscall ? "" : " (type:syscall)"),
		    enabled_string(event_rule.is_enabled()),
		    bitness_event(event_rule.lib().flags),
		    safe_string(filter_msg));
		break;
	case LTTNG_EVENT_NOOP:
		MSG("%s (type: noop)%s%s",
		    indent6,
		    enabled_string(event_rule.is_enabled()),
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

static const char *field_type(const lttng::cli::tracepoint_field& field)
{
	switch (field.type()) {
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
static void print_event_field(const lttng::cli::tracepoint_field& field)
{
	if (field.name().len() == 0) {
		return;
	}

	MSG("%sfield: %s (%s)%s",
	    indent8,
	    field.name().data(),
	    field_type(field),
	    field.is_no_write() ? " [no write]" : "");
}

static int list_agent_events()
{
	int ret = CMD_SUCCESS;
	pid_t cur_pid = 0;

	LTTNG_ASSERT(the_config->domain_type);
	const char *agent_domain_str = lttng_domain_type_str(*the_config->domain_type);

	DBG("Getting %s tracing events", agent_domain_str);

	const lttng::cli::java_python_logger_set loggers(*the_config->domain_type);

	/* Pretty print */
	MSG("%s events (Logger name):\n-------------------------", agent_domain_str);

	if (loggers.is_empty()) {
		MSG("None");
	}

	for (auto& logger : loggers) {
		if (cur_pid != logger.pid()) {
			cur_pid = logger.pid();
			const auto cmdline = logger.cmdline();

			if (!cmdline) {
				ret = CMD_ERROR;
				return ret;
			}

			MSG("\nPID: %d - Name: %s", cur_pid, cmdline->c_str());
		}

		MSG("%s- %s", indent6, logger.name().data());
	}

	MSG("");
	return ret;
}

/*
 * Ask session daemon for all user space tracepoints available.
 */
static int list_ust_events()
{
	int ret = CMD_SUCCESS;
	pid_t cur_pid = 0;

	DBG("Getting UST tracing events");

	const lttng::cli::ust_tracepoint_set tracepoints;

	/* Pretty print */
	MSG("UST events:\n-------------");

	if (tracepoints.is_empty()) {
		MSG("None");
	}

	for (auto& tracepoint : tracepoints) {
		if (cur_pid != tracepoint.pid()) {
			cur_pid = tracepoint.pid();
			const auto cmdline = tracepoint.cmdline();

			if (!cmdline) {
				ret = CMD_ERROR;
				return ret;
			}

			MSG("\nPID: %d - Name: %s", cur_pid, cmdline->c_str());
		}

		print_instrumentation_point(tracepoint, LTTNG_DOMAIN_UST);
	}

	MSG("");
	return ret;
}

/*
 * Ask session daemon for all user space tracepoint fields available.
 */
static int list_ust_event_fields()
{
	int ret = CMD_SUCCESS;
	pid_t cur_pid = 0;

	DBG("Getting UST tracing event fields");

	const lttng::cli::ust_tracepoint_set tracepoints;

	/* Pretty print */
	MSG("UST events:\n-------------");

	if (tracepoints.is_empty()) {
		MSG("None");
	}

	for (auto& tracepoint : tracepoints) {
		if (cur_pid != tracepoint.pid()) {
			cur_pid = tracepoint.pid();
			const auto cmdline = tracepoint.cmdline();

			if (!cmdline) {
				ret = CMD_ERROR;
				return ret;
			}

			MSG("\nPID: %d - Name: %s", cur_pid, cmdline->c_str());
		}

		/* Print the event */
		print_instrumentation_point(tracepoint, LTTNG_DOMAIN_UST);

		/* Print all fields for this event */
		for (auto& field : tracepoint.fields()) {
			print_event_field(field);
		}
	}

	MSG("");
	return ret;
}

/*
 * Ask for all trace events in the kernel
 */
static int list_kernel_events()
{
	int ret = CMD_SUCCESS;

	DBG("Getting kernel tracing events");

	const lttng::cli::kernel_tracepoint_set tracepoints;

	MSG("Kernel events:\n-------------");

	for (auto& tracepoint : tracepoints) {
		print_instrumentation_point(tracepoint, LTTNG_DOMAIN_KERNEL);
	}

	MSG("");
	return ret;
}

/*
 * Ask for kernel system calls.
 */
static int list_syscalls()
{
	int ret = CMD_SUCCESS;

	DBG("Getting kernel system call events");

	const lttng::cli::kernel_syscall_set syscalls;

	MSG("System calls:\n-------------");

	for (auto& syscall : syscalls) {
		print_instrumentation_point(syscall, LTTNG_DOMAIN_KERNEL);
	}

	MSG("");
	return ret;
}

/*
 * List agent events for a specific session using the domain.
 *
 * Return CMD_SUCCESS on success else a negative value.
 */
static int list_session_agent_events(const lttng::cli::domain& domain)
{
	int ret = CMD_SUCCESS;

	/*
	 * For Java/Python domains, there are no channels.
	 * Get event rules directly from the domain.
	 */
	const auto event_rules = domain.as_java_python().event_rules();

	/* Pretty print */
	MSG("Event rules:\n---------------------");
	if (event_rules.is_empty()) {
		MSG("%sNone\n", indent6);
		return ret;
	}

	for (auto& event_rule : event_rules) {
		const auto agent_rule = event_rule.as_java_python_logger();
		char *filter_msg = nullptr;

		const auto filter_expr = agent_rule.filter_expression();

		if (!filter_expr) {
			filter_msg = nullptr;
		} else {
			if (asprintf(&filter_msg, " [filter: '%s']", filter_expr.data()) == -1) {
				filter_msg = nullptr;
			}
		}

		if (agent_rule.log_level_type() != LTTNG_EVENT_LOGLEVEL_ALL) {
			MSG("%s- %s%s (loglevel%s %s)%s",
			    indent4,
			    agent_rule.name().data(),
			    enabled_string(agent_rule.is_enabled()),
			    logleveltype_string(agent_rule.log_level_type()),
			    mi_lttng_loglevel_string(agent_rule.log_level(), domain.type()),
			    safe_string(filter_msg));
		} else {
			MSG("%s- %s%s%s",
			    indent4,
			    agent_rule.name().data(),
			    enabled_string(agent_rule.is_enabled()),
			    safe_string(filter_msg));
		}

		free(filter_msg);
	}

	MSG("");
	return ret;
}

/*
 * List events of channel of session and domain.
 */
static int list_events(const lttng::cli::channel& channel)
{
	int ret = CMD_SUCCESS;

	const auto event_rules = channel.event_rules();

	/* Pretty print */
	MSG("\n%sRecording event rules:", indent4);
	if (event_rules.is_empty()) {
		MSG("%sNone\n", indent6);
		return ret;
	}

	for (auto& event_rule : event_rules) {
		print_events(event_rule, channel.domain_type());
	}

	MSG("");
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

static void print_detailed_mem_usage(const lttng::cli::data_stream_info_sets& ds_info_sets)
{
	for (const auto& ds_info_set : ds_info_sets) {
		const auto uid = ds_info_set.uid();
		const auto pid = ds_info_set.pid();
		const auto app_bitness = ds_info_set.app_bitness();

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

			msg += fmt::format(
				": {}:", utils_string_from_size(ds_info_set.memory_usage_bytes()));
			MSG("%s%s", indent6, msg.c_str());
		}

		auto ds_info_i = 0U;
		for (const auto& ds_info : ds_info_set) {
			const auto cpu_id = ds_info.cpu_id();
			const auto mem_bytes = ds_info.memory_usage_bytes();

			std::string msg = fmt::format("[{}] ", ds_info_i);

			if (cpu_id) {
				msg += fmt::format("CPU {}: ", *cpu_id);
			}

			msg += utils_string_from_size(mem_bytes);
			MSG("%s%s", indent8, msg.c_str());
			++ds_info_i;
		}
	}
}

static void print_mem_usage(const lttng::cli::ust_or_java_python_channel& channel)
{
	const auto ds_info_sets = channel.data_stream_infos();
	const auto msg = fmt::format("Buffer memory usage: {}",
				     utils_string_from_size(ds_info_sets.memory_usage_bytes()));

	if (the_config->stream_info_details && !ds_info_sets.is_empty()) {
		MSG("\n%s%s:", indent4, msg.c_str());
		print_detailed_mem_usage(ds_info_sets);
	} else {
		MSG("\n%s%s", indent4, msg.c_str());
	}
}

/*
 * Pretty print channel
 */
static void print_channel(const lttng::cli::channel& channel, bool snapshot_mode)
{
	MSG("- %s:%s\n", channel.name().data(), enabled_string(channel.is_enabled()));
	MSG("%sAttributes:", indent4);

	if (is_ust_or_agent_domain(channel.domain_type())) {
		const auto& ust_channel = channel.as_ust_or_java_python();
		const auto allocation_policy_str =
			allocation_policy_to_pretty_string(ust_channel.allocation_policy());

		MSG("%sAllocation policy: %s", indent6, allocation_policy_str);

		MSG("%sPreallocation policy: %s",
		    indent6,
		    preallocation_policy_to_pretty_string(ust_channel.preallocation_policy()));
	}

	MSG("%sEvent-loss mode:   %s",
	    indent6,
	    channel.is_discard_mode() ? "discard" : "overwrite");
	MSG("%sSub-buffer size:   %" PRIu64 " bytes", indent6, channel.sub_buf_size());
	MSG("%sSub-buffer count:  %" PRIu64, indent6, channel.sub_buf_count());

	if (is_ust_or_agent_domain(channel.domain_type())) {
		static const char *const prop_name = "Automatic memory reclamation policy";
		const auto maximal_age_us =
			channel.as_ust_or_java_python().automatic_memory_reclaim_maximal_age_us();

		if (maximal_age_us) {
			if (*maximal_age_us == 0) {
				MSG("%s%s: consumed", indent6, prop_name);
			} else {
				MSG("%s%s: when older than %" PRIu64 " %s",
				    indent6,
				    prop_name,
				    *maximal_age_us,
				    USEC_UNIT);
			}
		} else {
			MSG("%s%s: none", indent6, prop_name);
		}
	}

	print_timer("Switch timer", 6, channel.switch_timer_period_us());
	print_timer("Read timer", 8, channel.read_timer_period_us());
	print_timer("Monitor timer", 5, channel.monitor_timer_period_us());

	if (is_ust_or_agent_domain(channel.domain_type())) {
		const auto watchdog_timer =
			channel.as_ust_or_java_python().watchdog_timer_period_us();
		if (watchdog_timer) {
			print_timer("Watchdog timer", 4, *watchdog_timer);
		}
	}

	if (channel.is_discard_mode() && is_ust_or_agent_domain(channel.domain_type())) {
		const auto blocking_timeout = channel.as_ust_or_java_python().blocking_timeout_us();
		if (blocking_timeout) {
			MSG("%sBlocking timeout:  %" PRIu64 " %s",
			    indent6,
			    *blocking_timeout,
			    USEC_UNIT);
		} else {
			MSG("%sBlocking timeout:  infinite", indent6);
		}
	}

	const auto trace_file_count = channel.max_trace_file_count();
	MSG("%sTrace file count:  %" PRIu64 " per stream",
	    indent6,
	    trace_file_count == 0 ? 1 : trace_file_count);

	const auto trace_file_size = channel.max_trace_file_size();
	if (trace_file_size != 0) {
		MSG("%sTrace file size:   %" PRIu64 " bytes", indent6, trace_file_size);
	} else {
		MSG("%sTrace file size:   %s", indent6, "unlimited");
	}

	if (channel.domain_type() == LTTNG_DOMAIN_KERNEL) {
		const auto output_type = channel.as_kernel().output_type();
		switch (output_type) {
		case LTTNG_EVENT_SPLICE:
			MSG("%sOutput mode:       splice", indent6);
			break;
		case LTTNG_EVENT_MMAP:
			MSG("%sOutput mode:       mmap", indent6);
			break;
		}
	}

	MSG("\n%sStatistics:", indent4);
	if (snapshot_mode) {
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

	if (channel.is_discard_mode()) {
		MSG("%sDiscarded events: %" PRIu64,
		    indent6,
		    channel.discarded_event_record_count());
	} else {
		MSG("%sLost packets:     %" PRIu64, indent6, channel.discarded_packet_count());
	}
skip_stats_printing:
	/* Print memory usage for UST and agent channels */
	if (is_ust_or_agent_domain(channel.domain_type())) {
		print_mem_usage(channel.as_ust_or_java_python());
	}
	return;
}

/*
 * List channel(s) of session and domain.
 *
 * If channel_name is NULL, all channels are listed.
 */
static int
list_channels(const lttng::cli::domain& domain, const char *channel_name, bool snapshot_mode)
{
	int ret = CMD_SUCCESS;
	unsigned int chan_found = 0;

	DBG("Listing channel(s) (%s)", channel_name ?: "<all>");

	const auto channels = domain.channels();

	/* Pretty print */
	if (!channels.is_empty()) {
		MSG("Channels:\n-------------");
	}

	for (auto& channel : channels) {
		if (channel_name != nullptr) {
			if (channel.name() == channel_name) {
				chan_found = 1;
			} else {
				continue;
			}
		}

		print_channel(channel, snapshot_mode);

		/* Listing events per channel */
		ret = list_events(channel);
		if (ret) {
			return ret;
		}

		if (chan_found) {
			break;
		}
	}

	if (!chan_found && channel_name != nullptr) {
		ret = CMD_ERROR;
		ERR("Channel %s not found", channel_name);
	}

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
static int list_process_attr_tracker(const lttng::cli::process_attr_tracker& tracker,
				     enum lttng_process_attr process_attr)
{
	int ret = CMD_SUCCESS;

	{
		char *process_attr_name;
		const int print_ret = asprintf(
			&process_attr_name, "%ss:", get_capitalized_process_attr_str(process_attr));

		if (print_ret == -1) {
			return CMD_FATAL;
		}

		_MSG("  %-22s", process_attr_name);
		free(process_attr_name);
	}

	const auto policy = tracker.tracking_policy();

	switch (policy) {
	case LTTNG_TRACKING_POLICY_INCLUDE_SET:
		break;
	case LTTNG_TRACKING_POLICY_EXCLUDE_ALL:
		MSG("none");
		return CMD_SUCCESS;
	case LTTNG_TRACKING_POLICY_INCLUDE_ALL:
		MSG("all");
		return CMD_SUCCESS;
	default:
		ERR("Unknown tracking policy encountered");
		return CMD_FATAL;
	}

	const auto inclusion_set = tracker.inclusion_set();

	if (!inclusion_set || inclusion_set->empty()) {
		/* Functionally equivalent to the 'exclude all' policy. */
		MSG("none");
		return CMD_SUCCESS;
	}

	auto first = true;

	for (auto& value : *inclusion_set) {
		if (!first) {
			_MSG(", ");
		}

		first = false;

		switch (value.type()) {
		case LTTNG_PROCESS_ATTR_VALUE_TYPE_PID:
			if (const auto pid = value.pid()) {
				_MSG("%" PRId64, static_cast<int64_t>(*pid));
			}
			break;
		case LTTNG_PROCESS_ATTR_VALUE_TYPE_UID:
			if (const auto uid = value.uid()) {
				_MSG("%" PRId64, static_cast<int64_t>(*uid));
			}
			break;
		case LTTNG_PROCESS_ATTR_VALUE_TYPE_GID:
			if (const auto gid = value.gid()) {
				_MSG("%" PRId64, static_cast<int64_t>(*gid));
			}
			break;
		case LTTNG_PROCESS_ATTR_VALUE_TYPE_USER_NAME:
			if (const auto name = value.user_name()) {
				_MSG("`%s`", name.data());
			}
			break;
		case LTTNG_PROCESS_ATTR_VALUE_TYPE_GROUP_NAME:
			if (const auto name = value.group_name()) {
				_MSG("`%s`", name.data());
			}
			break;
		default:
			ret = CMD_ERROR;
			return ret;
		}
	}

	MSG("");
	return ret;
}

/*
 * List all trackers of a domain
 */
static int list_trackers(const lttng::cli::domain& domain)
{
	int ret = CMD_SUCCESS;

	MSG("Tracked process attributes");

	switch (domain.type()) {
	case LTTNG_DOMAIN_KERNEL:
	{
		const auto kernel_domain = domain.as_kernel();

		/* pid tracker */
		ret = list_process_attr_tracker(kernel_domain.process_id_tracker(),
						LTTNG_PROCESS_ATTR_PROCESS_ID);
		if (ret) {
			return ret;
		}

		/* vpid tracker */
		ret = list_process_attr_tracker(kernel_domain.virtual_process_id_tracker(),
						LTTNG_PROCESS_ATTR_VIRTUAL_PROCESS_ID);
		if (ret) {
			return ret;
		}

		/* uid tracker */
		ret = list_process_attr_tracker(kernel_domain.user_id_tracker(),
						LTTNG_PROCESS_ATTR_USER_ID);
		if (ret) {
			return ret;
		}

		/* vuid tracker */
		ret = list_process_attr_tracker(kernel_domain.virtual_user_id_tracker(),
						LTTNG_PROCESS_ATTR_VIRTUAL_USER_ID);
		if (ret) {
			return ret;
		}

		/* gid tracker */
		ret = list_process_attr_tracker(kernel_domain.group_id_tracker(),
						LTTNG_PROCESS_ATTR_GROUP_ID);
		if (ret) {
			return ret;
		}

		/* vgid tracker */
		ret = list_process_attr_tracker(kernel_domain.virtual_group_id_tracker(),
						LTTNG_PROCESS_ATTR_VIRTUAL_GROUP_ID);
		if (ret) {
			return ret;
		}

		break;
	}
	case LTTNG_DOMAIN_UST:
	{
		const auto ust_domain = domain.as_ust();

		/* vpid tracker */
		ret = list_process_attr_tracker(ust_domain.virtual_process_id_tracker(),
						LTTNG_PROCESS_ATTR_VIRTUAL_PROCESS_ID);
		if (ret) {
			return ret;
		}

		/* vuid tracker */
		ret = list_process_attr_tracker(ust_domain.virtual_user_id_tracker(),
						LTTNG_PROCESS_ATTR_VIRTUAL_USER_ID);
		if (ret) {
			return ret;
		}

		/* vgid tracker */
		ret = list_process_attr_tracker(ust_domain.virtual_group_id_tracker(),
						LTTNG_PROCESS_ATTR_VIRTUAL_GROUP_ID);
		if (ret) {
			return ret;
		}

		break;
	}
	default:
		break;
	}

	MSG();
	return ret;
}

static enum cmd_error_code
print_periodic_rotation_schedule(const lttng::cli::rotation_schedule_periodic& schedule)
{
	MSG("    timer period: %" PRIu64 " %s", schedule.period(), USEC_UNIT);
	return CMD_SUCCESS;
}

static enum cmd_error_code
print_size_threshold_rotation_schedule(const lttng::cli::rotation_schedule_size& schedule)
{
	MSG("    size threshold: %" PRIu64 " bytes", schedule.threshold());
	return CMD_SUCCESS;
}

static enum cmd_error_code print_rotation_schedule(const lttng::cli::rotation_schedule& schedule)
{
	enum cmd_error_code ret;

	switch (schedule.type()) {
	case LTTNG_ROTATION_SCHEDULE_TYPE_SIZE_THRESHOLD:
		ret = print_size_threshold_rotation_schedule(schedule.as_size());
		break;
	case LTTNG_ROTATION_SCHEDULE_TYPE_PERIODIC:
		ret = print_periodic_rotation_schedule(schedule.as_periodic());
		break;
	default:
		ret = CMD_ERROR;
	}
	return ret;
}

/*
 * List the automatic rotation settings.
 */
static enum cmd_error_code list_rotate_settings(const lttng::cli::session& session)
{
	enum cmd_error_code cmd_ret = CMD_SUCCESS;
	const auto schedules = session.rotation_schedules();

	if (schedules.is_empty()) {
		return CMD_SUCCESS;
	}

	MSG("Automatic rotation schedules:");

	for (auto& schedule : schedules) {
		enum cmd_error_code tmp_ret = CMD_SUCCESS;

		tmp_ret = print_rotation_schedule(schedule);

		/*
		 * Report an error if the serialization of any of the
		 * descriptors failed.
		 */
		cmd_ret = cmd_ret ? cmd_ret : tmp_ret;
	}

	_MSG("\n");
	return cmd_ret;
}

/*
 * List available tracing session. List only basic information.
 *
 * If session_name is NULL, all sessions are listed.
 */
static int list_sessions(const lttng::cli::session_list& sessions, const char *session_name)
{
	int ret = CMD_SUCCESS;
	unsigned int session_found = 0;

	DBG("Session count %zu", sessions.size());

	/* Pretty print */
	if (sessions.is_empty()) {
		MSG("Currently no available recording session");
		return ret;
	}

	if (session_name == nullptr) {
		MSG("Available recording sessions:");
	}

	auto i = 0U;

	for (auto& session : sessions) {
		if (session_name != nullptr) {
			if (session.name() == session_name) {
				session_found = 1;
				MSG("Recording session %s: [%s%s]",
				    session_name,
				    active_string(session.is_active()),
				    snapshot_string(session.is_snapshot_mode()));

				if (*session.output()) {
					MSG("%sTrace output: %s\n",
					    indent4,
					    session.output().data());
				}
				break;
			}
		} else {
			MSG("  %d) %s [%s%s]",
			    i + 1,
			    session.name().data(),
			    active_string(session.is_active()),
			    snapshot_string(session.is_snapshot_mode()));

			if (*session.output()) {
				MSG("%sTrace output: %s", indent4, session.output().data());
			}

			if (const auto live_period = session.live_timer_period_us()) {
				MSG("%sLive timer interval: %u %s",
				    indent4,
				    *live_period,
				    USEC_UNIT);
			}
			MSG("");
		}

		i++;
	}

	if (!session_found && session_name != nullptr) {
		ERR("Session '%s' not found", session_name);
		ret = CMD_ERROR;
	}

	if (session_name == nullptr) {
		MSG("\nUse lttng list <session_name> for more details");
	}

	return ret;
}

/*
 * List available domain(s) for a session.
 */
static int list_domains(const lttng::cli::session& session)
{
	int ret = CMD_SUCCESS;
	const auto domains = session.domains();

	/* Pretty print */
	MSG("Domains:\n-------------");
	if (domains.is_empty()) {
		MSG("  None");
		return ret;
	}

	for (auto& domain : domains) {
		switch (domain.type()) {
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

	/* Cache configuration for use by helpers */
	the_config = &config;

	const lttng::cli::session_list sessions;

	if (!config.session_name) {
		if (!config.kernel && !config.userspace && !config.jul && !config.log4j &&
		    !config.log4j2 && !config.python) {
			ret = list_sessions(sessions, nullptr);
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
		/* Get the session set once for all operations */
		const auto found_session = sessions.find_by_name(config.session_name->c_str());

		if (!found_session) {
			ERR("Session '%s' not found", config.session_name->c_str());
			ret = CMD_ERROR;
			goto end;
		}

		auto& session = *found_session;

		/* List session attributes */
		ret = list_sessions(sessions, config.session_name->c_str());
		if (ret) {
			goto end;
		}

		ret = list_rotate_settings(session);
		if (ret) {
			goto end;
		}

		/* Domain listing */
		if (config.domain) {
			ret = list_domains(session);
			goto end;
		}

		const auto session_domains = session.domains();

		/* Channel listing */
		if (config.kernel || config.userspace) {
			LTTNG_ASSERT(config.domain_type);
			const auto domain = session_domains.find_by_type(*config.domain_type);

			if (!domain) {
				ERR("Domain not found in session");
				ret = CMD_ERROR;
				goto end;
			}

			/* Trackers */
			ret = list_trackers(*domain);
			if (ret) {
				goto end;
			}

			/* Channels */
			ret = list_channels(*domain,
					    config.channel_name ? config.channel_name->c_str() :
								  nullptr,
					    session.is_snapshot_mode());
			if (ret) {
				goto end;
			}
		} else {
			/* We want all domain(s) */
			for (auto& domain : session_domains) {
				switch (domain.type()) {
				case LTTNG_DOMAIN_KERNEL:
					MSG("=== Domain: Linux kernel ===\n");
					break;
				case LTTNG_DOMAIN_UST:
					MSG("=== Domain: User space ===\n");
					MSG("Buffering scheme: %s\n",
					    domain.buffer_ownership_model() ==
							    LTTNG_BUFFER_PER_PID ?
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

				if (is_agent_domain(domain.type())) {
					ret = list_session_agent_events(domain);
					if (ret) {
						goto end;
					}

					continue;
				}

				switch (domain.type()) {
				case LTTNG_DOMAIN_KERNEL:
				case LTTNG_DOMAIN_UST:
					ret = list_trackers(domain);
					if (ret) {
						goto end;
					}
					break;
				default:
					break;
				}

				ret = list_channels(domain,
						    config.channel_name ?
							    config.channel_name->c_str() :
							    nullptr,
						    session.is_snapshot_mode());
				if (ret) {
					goto end;
				}
			}
		}
	}

end:
	return ret;
}
