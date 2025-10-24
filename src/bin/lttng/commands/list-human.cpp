/*
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 * SPDX-FileCopyrightText: 2020 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "list-common.hpp"
#include "list-human.hpp"
#include "list-wrappers.hpp"

#include <common/exception.hpp>
#include <common/macros.hpp>
#include <common/mi-lttng.hpp>

#include <lttng/domain-internal.hpp>
#include <lttng/lttng.h>

namespace {

const char *indent4 = "    ";
const char *indent6 = "      ";
const char *indent8 = "        ";

/* Configuration for the list command */
const list_cmd_config *the_config;

const char *active_string(const bool is_active)
{
	return is_active ? "active" : "inactive";
}

const char *snapshot_string(const bool is_snapshot)
{
	return is_snapshot ? " snapshot" : "";
}

const char *enabled_string(const bool is_enabled)
{
	return is_enabled ? " [enabled]" : " [disabled]";
}

const char *logleveltype_string(enum lttng_loglevel_type value)
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

const char *bitness_event(const bool is_32_bit, const bool is_64_bit)
{
	if (is_32_bit) {
		if (is_64_bit) {
			return " [32/64-bit]";
		} else {
			return " [32-bit]";
		}
	} else if (is_64_bit) {
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
std::string get_exclusion_names_msg(const lttng::cli::ust_tracepoint_event_rule& event_rule)
{
	const auto exclusions = event_rule.exclusions();

	if (exclusions.empty()) {
		/*
		 * No exclusions: return copy of empty string so that
		 * it can be freed by caller.
		 */
		return {};
	}

	auto first = true;
	std::string exclusions_str(" [exclusions: ");

	for (const auto& exclusion : exclusions) {
		/* Append comma between exclusion names */
		if (!first) {
			exclusions_str += ',';
		}

		first = false;

		/* Append exclusion name */
		exclusions_str += exclusion.data();
	}

	/* This also puts a final '\0' at the end of exclusion_msg */
	exclusions_str += ']';
	return exclusions_str;
}

std::string realpath_str(const char *const path)
{
	const auto str = realpath(path, nullptr);

	if (!str) {
		return "NULL";
	}

	const std::string ret_str(str);

	std::free(str);
	return ret_str;
}

void print_userspace_probe_location(const lttng::cli::linux_uprobe_event_rule& uprobe_event)
{
	const auto location = uprobe_event.location();

	if (!location) {
		lttng::print("Event has no userspace probe location\n");
		return;
	}

	lttng::print("{}{} (type: userspace-probe){}\n",
		     indent6,
		     uprobe_event.name(),
		     enabled_string(uprobe_event.is_enabled()));

	switch (location->type()) {
	case LTTNG_USERSPACE_PROBE_LOCATION_TYPE_UNKNOWN:
		lttng::print("{}Type: Unknown\n", indent8);
		break;
	case LTTNG_USERSPACE_PROBE_LOCATION_TYPE_FUNCTION:
	{
		const auto func_location = location->as_function();

		lttng::print("{}Type: Function\n", indent8);
		lttng::print("{}Binary path:   {}\n",
			     indent8,
			     realpath_str(func_location.binary_path().data()));
		lttng::print("{}Function:      {}()\n", indent8, func_location.function_name());

		switch (location->lookup_method_type()) {
		case LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_FUNCTION_ELF:
			lttng::print("{}Lookup method: ELF\n", indent8);
			break;
		case LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_FUNCTION_DEFAULT:
			lttng::print("{}Lookup method: default\n", indent8);
			break;
		default:
			lttng::print("{}Lookup method: INVALID LOOKUP TYPE ENCOUNTERED\n", indent8);
			break;
		}

		break;
	}
	case LTTNG_USERSPACE_PROBE_LOCATION_TYPE_TRACEPOINT:
	{
		const auto tp_location = location->as_tracepoint();

		lttng::print("{}Type: Tracepoint\n", indent8);
		lttng::print("{}Binary path:   {}\n",
			     indent8,
			     realpath_str(tp_location.binary_path().data()));
		lttng::print("{}Tracepoint:    {}:{}\n",
			     indent8,
			     tp_location.provider_name(),
			     tp_location.probe_name());

		switch (location->lookup_method_type()) {
		case LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_TRACEPOINT_SDT:
			lttng::print("{}Lookup method: SDT\n", indent8);
			break;
		default:
			lttng::print("{}Lookup method: INVALID LOOKUP TYPE ENCOUNTERED\n", indent8);
			break;
		}

		break;
	}
	default:
		LTTNG_THROW_ERROR("Invalid probe type encountered");
	}
}

/*
 * Pretty print instrumentation point (kernel tracepoint, UST tracepoint, syscall, agent logger).
 */
void print_instrumentation_point(const lttng::cli::instrumentation_point& instr_point,
				 enum lttng_domain_type domain_type)
{
	switch (instr_point.lib().type) {
	case LTTNG_EVENT_TRACEPOINT:
	{
		if (domain_type == LTTNG_DOMAIN_KERNEL) {
			/* Kernel tracepoint - no loglevel */
			lttng::print("{}{} (type: tracepoint)\n", indent6, instr_point.name());
		} else {
			/* UST/agent instrumentation point - has loglevel */
			auto loglevel = -1;

			if (domain_type == LTTNG_DOMAIN_UST) {
				loglevel =
					static_cast<const lttng::cli::ust_tracepoint&>(instr_point)
						.log_level();
			}

			if (loglevel != -1) {
				lttng::print("{}{} (loglevel: {} ({})) (type: tracepoint)\n",
					     indent6,
					     instr_point.name(),
					     mi_lttng_loglevel_string(loglevel, domain_type),
					     loglevel);
			} else {
				lttng::print(
					"{}{} (type: tracepoint)\n", indent6, instr_point.name());
			}
		}

		break;
	}
	case LTTNG_EVENT_SYSCALL:
	{
		const auto syscall_ip = static_cast<const lttng::cli::kernel_syscall&>(instr_point);

		lttng::print("{}{}{}{}\n",
			     indent6,
			     instr_point.name(),
			     (the_config->syscall ? "" : " (type:syscall)"),
			     bitness_event(syscall_ip.is_32_bit(), syscall_ip.is_64_bit()));
	}

	break;
	default:
		/* Should not happen for instrumentation points */
		std::abort();
	}
}

/*
 * Pretty print single event rule (from a channel).
 */
void print_events(const lttng::cli::event_rule& event_rule, const lttng_domain_type domain_type)
{
	std::string filter_msg;

	if (event_rule.filter_expression()) {
		filter_msg = fmt::format(" [filter: '{}']", event_rule.filter_expression());
	}

	std::string exclusion_msg;

	/* Exclusions are only supported for UST tracepoint event rules */
	if (domain_type == LTTNG_DOMAIN_UST && event_rule.type() == LTTNG_EVENT_TRACEPOINT) {
		const auto ust_event = event_rule.as_ust_tracepoint();

		exclusion_msg = get_exclusion_names_msg(ust_event);
	}

	switch (event_rule.type()) {
	case LTTNG_EVENT_TRACEPOINT:
	{
		if (is_ust_or_agent_domain(domain_type)) {
			const auto ust_or_agent_event = event_rule.as_ust_tracepoint();

			if (ust_or_agent_event.log_level() != -1) {
				lttng::print(
					"{}{} (loglevel{} {} ({})) (type: tracepoint){}{}{}\n",
					indent6,
					event_rule.name(),
					logleveltype_string(ust_or_agent_event.log_level_type()),
					mi_lttng_loglevel_string(ust_or_agent_event.log_level(),
								 domain_type),
					ust_or_agent_event.log_level(),
					enabled_string(event_rule.is_enabled()),
					exclusion_msg,
					filter_msg);
			} else {
				lttng::print("{}{} (type: tracepoint){}{}{}\n",
					     indent6,
					     event_rule.name(),
					     enabled_string(event_rule.is_enabled()),
					     exclusion_msg,
					     filter_msg);
			}
		} else {
			/* Kernel tracepoint event rule */
			lttng::print("{}{} (type: tracepoint){}{}{}\n",
				     indent6,
				     event_rule.name(),
				     enabled_string(event_rule.is_enabled()),
				     exclusion_msg,
				     filter_msg);
		}
		break;
	}
	case LTTNG_EVENT_FUNCTION:
	case LTTNG_EVENT_PROBE:
	{
		const auto kprobe_event = event_rule.as_linux_kprobe();

		lttng::print("{}{} (type: {}){}{}\n",
			     indent6,
			     event_rule.name(),
			     event_rule.type() == LTTNG_EVENT_FUNCTION ? "function" : "probe",
			     enabled_string(event_rule.is_enabled()),
			     filter_msg);

		if (kprobe_event.address() != 0) {
			lttng::print("{}addr: {:#x}\n", indent8, kprobe_event.address());
		} else {
			lttng::print("{}offset: {:#x}\n", indent8, kprobe_event.offset());
			lttng::print("{}symbol: {}\n", indent8, kprobe_event.symbol_name());
		}
		break;
	}
	case LTTNG_EVENT_USERSPACE_PROBE:
		print_userspace_probe_location(event_rule.as_linux_uprobe());
		break;
	case LTTNG_EVENT_SYSCALL:
		lttng::print("{}{}{}{}{}\n",
			     indent6,
			     event_rule.name(),
			     (the_config->syscall ? "" : " (type:syscall)"),
			     enabled_string(event_rule.is_enabled()),
			     filter_msg);
		break;
	case LTTNG_EVENT_NOOP:
		lttng::print("{} (type: noop){}{}\n",
			     indent6,
			     enabled_string(event_rule.is_enabled()),
			     filter_msg);
		break;
	case LTTNG_EVENT_ALL:
		/* Fall-through. */
	default:
		/* We should never have "all" events in list. */
		std::abort();
	}
}

const char *field_type(const lttng::cli::tracepoint_field& field)
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
void print_event_field(const lttng::cli::tracepoint_field& field)
{
	if (field.name().len() == 0) {
		return;
	}

	lttng::print("{}field: {} ({}){}\n",
		     indent8,
		     field.name(),
		     field_type(field),
		     field.is_no_write() ? " [no write]" : "");
}

void list_agent_events()
{
	LTTNG_ASSERT(the_config->domain_type);

	const auto agent_domain_str = lttng_domain_type_str(*the_config->domain_type);

	DBG("Getting %s tracing events", agent_domain_str);

	const lttng::cli::java_python_logger_set loggers(*the_config->domain_type);

	/* Pretty print */
	lttng::print("{} events (Logger name):\n-------------------------\n", agent_domain_str);

	if (loggers.is_empty()) {
		lttng::print("None\n");
	}

	pid_t cur_pid = 0;

	for (const auto& logger : loggers) {
		if (cur_pid != logger.pid()) {
			cur_pid = logger.pid();

			const auto cmdline = logger.cmdline();

			if (!cmdline) {
				LTTNG_THROW_ERROR("Failed to get command line of PID");
			}

			lttng::print("\nPID: {} - Name: {}\n", cur_pid, *cmdline);
		}

		lttng::print("{}- {}\n", indent6, logger.name());
	}

	lttng::print("\n");
}

/*
 * Ask session daemon for all user space tracepoints available.
 */
void list_ust_events()
{
	DBG("Getting UST tracing events");

	const lttng::cli::ust_tracepoint_set tracepoints;

	/* Pretty print */
	lttng::print("UST events:\n-------------\n");

	if (tracepoints.is_empty()) {
		lttng::print("None\n");
	}

	pid_t cur_pid = 0;

	for (const auto& tracepoint : tracepoints) {
		if (cur_pid != tracepoint.pid()) {
			cur_pid = tracepoint.pid();

			const auto cmdline = tracepoint.cmdline();

			if (!cmdline) {
				LTTNG_THROW_ERROR("Failed to get command line of PID");
			}

			lttng::print("\nPID: {} - Name: {}\n", cur_pid, *cmdline);
		}

		print_instrumentation_point(tracepoint, LTTNG_DOMAIN_UST);
	}

	lttng::print("\n");
}

/*
 * Ask session daemon for all user space tracepoint fields available.
 */
void list_ust_event_fields()
{
	DBG("Getting UST tracing event fields");

	const lttng::cli::ust_tracepoint_set tracepoints;

	/* Pretty print */
	lttng::print("UST events:\n-------------\n");

	if (tracepoints.is_empty()) {
		lttng::print("None\n");
	}

	pid_t cur_pid = 0;

	for (const auto& tracepoint : tracepoints) {
		if (cur_pid != tracepoint.pid()) {
			cur_pid = tracepoint.pid();

			const auto cmdline = tracepoint.cmdline();

			if (!cmdline) {
				LTTNG_THROW_ERROR("Failed to get command line of PID");
			}

			lttng::print("\nPID: {} - Name: {}\n", cur_pid, *cmdline);
		}

		/* Print the event */
		print_instrumentation_point(tracepoint, LTTNG_DOMAIN_UST);

		/* Print all fields for this event */
		for (const auto& field : tracepoint.fields()) {
			print_event_field(field);
		}
	}

	lttng::print("\n");
}

/*
 * Ask for all trace events in the kernel
 */
void list_kernel_events()
{
	DBG("Getting kernel tracing events");

	const lttng::cli::kernel_tracepoint_set tracepoints;

	lttng::print("Kernel events:\n-------------\n");

	for (const auto& tracepoint : tracepoints) {
		print_instrumentation_point(tracepoint, LTTNG_DOMAIN_KERNEL);
	}

	lttng::print("\n");
}

/*
 * Ask for kernel system calls.
 */
void list_syscalls()
{
	DBG("Getting kernel system call events");

	const lttng::cli::kernel_syscall_set syscalls;

	lttng::print("System calls:\n-------------\n");

	for (const auto& syscall : syscalls) {
		print_instrumentation_point(syscall, LTTNG_DOMAIN_KERNEL);
	}

	lttng::print("\n");
}

/*
 * List agent events for a specific session using the domain.
 */
void list_session_agent_events(const lttng::cli::domain& domain)
{
	/*
	 * For Java/Python domains, there are no channels.
	 * Get event rules directly from the domain.
	 */
	const auto event_rules = domain.as_java_python().event_rules();

	/* Pretty print */
	lttng::print("Event rules:\n---------------------\n");

	if (event_rules.is_empty()) {
		lttng::print("{}None\n\n", indent6);
		return;
	}

	for (const auto& event_rule : event_rules) {
		const auto agent_rule = event_rule.as_java_python_logger();
		std::string filter_msg;

		if (agent_rule.filter_expression()) {
			filter_msg =
				lttng::format(" [filter: '{}']", agent_rule.filter_expression());
		}

		if (agent_rule.log_level_type() != LTTNG_EVENT_LOGLEVEL_ALL) {
			lttng::print("{}- {}{} (loglevel{} {}){}\n",
				     indent4,
				     agent_rule.name(),
				     enabled_string(agent_rule.is_enabled()),
				     logleveltype_string(agent_rule.log_level_type()),
				     mi_lttng_loglevel_string(agent_rule.log_level(),
							      domain.type()),
				     filter_msg);
		} else {
			lttng::print("{}- {}{}{}\n",
				     indent4,
				     agent_rule.name(),
				     enabled_string(agent_rule.is_enabled()),
				     filter_msg);
		}
	}

	lttng::print("\n");
}

/*
 * List events of channel of session and domain.
 */
void list_events(const lttng::cli::channel& channel)
{
	const auto event_rules = channel.event_rules();

	/* Pretty print */
	lttng::print("\n{}Recording event rules:\n", indent4);
	if (event_rules.is_empty()) {
		lttng::print("{}None\n\n", indent6);
		return;
	}

	for (const auto& event_rule : event_rules) {
		print_events(event_rule, channel.domain_type());
	}

	lttng::print("\n");
}

void print_timer(const char *const timer_name,
		 const std::uint32_t space_count,
		 const std::int64_t value)
{
	lttng::print("{}{}:", indent6, timer_name);

	for (auto i = 0U; i < space_count; ++i) {
		lttng::print(" ");
	}

	if (value) {
		lttng::print("{} {}\n", value, USEC_UNIT);
	} else {
		lttng::print("inactive\n");
	}
}

const char *allocation_policy_to_pretty_string(const lttng_channel_allocation_policy policy)
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

const char *preallocation_policy_to_pretty_string(const lttng_channel_preallocation_policy policy)
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

/*
 * Pretty print channel
 */
void print_channel(const lttng::cli::channel& channel, const bool snapshot_mode)
{
	lttng::print("- {}:{}\n\n", channel.name(), enabled_string(channel.is_enabled()));
	lttng::print("{}Attributes:\n", indent4);

	if (is_ust_or_agent_domain(channel.domain_type())) {
		const auto ust_channel = channel.as_ust_or_java_python();

		lttng::print("{}Allocation policy: {}\n",
			     indent6,
			     allocation_policy_to_pretty_string(ust_channel.allocation_policy()));
		lttng::print(
			"{}Preallocation policy: {}\n",
			indent6,
			preallocation_policy_to_pretty_string(ust_channel.preallocation_policy()));
	}

	lttng::print("{}Event-loss mode:   {}\n",
		     indent6,
		     channel.is_discard_mode() ? "discard" : "overwrite");
	lttng::print("{}Sub-buffer size:   {} bytes\n", indent6, channel.sub_buf_size());
	lttng::print("{}Sub-buffer count:  {}\n", indent6, channel.sub_buf_count());

	if (is_ust_or_agent_domain(channel.domain_type())) {
		static constexpr auto prop_name = "Automatic memory reclamation policy";
		const auto maximal_age_us =
			channel.as_ust_or_java_python().automatic_memory_reclaim_maximal_age_us();

		if (maximal_age_us) {
			if (*maximal_age_us == 0) {
				lttng::print("{}{}: consumed\n", indent6, prop_name);
			} else {
				lttng::print("{}{}: when older than {} {}\n",
					     indent6,
					     prop_name,
					     *maximal_age_us,
					     USEC_UNIT);
			}
		} else {
			lttng::print("{}{}: none\n", indent6, prop_name);
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
			lttng::print("{}Blocking timeout:  {} {}\n",
				     indent6,
				     *blocking_timeout,
				     USEC_UNIT);
		} else {
			lttng::print("{}Blocking timeout:  infinite\n", indent6);
		}
	}

	{
		const auto trace_file_count = channel.max_trace_file_count();

		lttng::print("{}Trace file count:  {} per stream\n",
			     indent6,
			     trace_file_count == 0 ? 1 : trace_file_count);
	}

	{
		const auto trace_file_size = channel.max_trace_file_size();

		if (trace_file_size != 0) {
			lttng::print("{}Trace file size:   {} bytes\n", indent6, trace_file_size);
		} else {
			lttng::print("{}Trace file size:   {}\n", indent6, "unlimited");
		}
	}

	if (channel.domain_type() == LTTNG_DOMAIN_KERNEL) {
		switch (channel.as_kernel().output_type()) {
		case LTTNG_EVENT_SPLICE:
			lttng::print("{}Output mode:       splice\n", indent6);
			break;
		case LTTNG_EVENT_MMAP:
			lttng::print("{}Output mode:       mmap\n", indent6);
			break;
		}
	}

	lttng::print("\n{}Statistics:\n", indent4);

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
		lttng::print("{}None\n", indent6);
		return;
	}

	if (channel.is_discard_mode()) {
		lttng::print("{}Discarded events: {}\n",
			     indent6,
			     channel.discarded_event_record_count());
	} else {
		lttng::print("{}Lost packets:     {}\n", indent6, channel.discarded_packet_count());
	}
}

/*
 * List channel(s) of session and domain.
 *
 * If channel_name is NULL, all channels are listed.
 */
void list_channels(const lttng::cli::domain& domain,
		   const char *const channel_name,
		   const bool snapshot_mode)
{
	DBG("Listing channel(s) (%s)", channel_name ?: "<all>");

	const auto channels = domain.channels();

	/* Pretty print */
	if (!channels.is_empty()) {
		lttng::print("Channels:\n-------------\n");
	}

	auto chan_found = false;

	for (const auto& channel : channels) {
		if (channel_name) {
			if (channel.name() == channel_name) {
				chan_found = true;
			} else {
				continue;
			}
		}

		print_channel(channel, snapshot_mode);

		/* Listing events per channel */
		list_events(channel);

		if (chan_found) {
			break;
		}
	}

	if (!chan_found && channel_name != nullptr) {
		LTTNG_THROW_ERROR(lttng::format("Channel {} not found", channel_name));
	}
}

const char *get_capitalized_process_attr_str(const lttng_process_attr process_attr)
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

/*
 * List a process attribute tracker for a session and domain tuple.
 */
void list_process_attr_tracker(const lttng::cli::process_attr_tracker& tracker,
			       const lttng_process_attr process_attr)
{
	lttng::print("  {:<22}",
		     lttng::format("{}s:", get_capitalized_process_attr_str(process_attr)));

	switch (tracker.tracking_policy()) {
	case LTTNG_TRACKING_POLICY_INCLUDE_SET:
		break;
	case LTTNG_TRACKING_POLICY_EXCLUDE_ALL:
		lttng::print("none\n");
		return;
	case LTTNG_TRACKING_POLICY_INCLUDE_ALL:
		lttng::print("all\n");
		return;
	default:
		LTTNG_THROW_ERROR("Unknown tracking policy encountered");
	}

	const auto inclusion_set = tracker.inclusion_set();

	if (!inclusion_set || inclusion_set->empty()) {
		/* Functionally equivalent to the 'exclude all' policy. */
		lttng::print("none\n");
		return;
	}

	auto first = true;

	for (const auto& value : *inclusion_set) {
		if (!first) {
			lttng::print(", ");
		}

		first = false;

		switch (value.type()) {
		case LTTNG_PROCESS_ATTR_VALUE_TYPE_PID:
			if (const auto pid = value.pid()) {
				lttng::print("{}", static_cast<int64_t>(*pid));
			}

			break;
		case LTTNG_PROCESS_ATTR_VALUE_TYPE_UID:
			if (const auto uid = value.uid()) {
				lttng::print("{}", static_cast<int64_t>(*uid));
			}

			break;
		case LTTNG_PROCESS_ATTR_VALUE_TYPE_GID:
			if (const auto gid = value.gid()) {
				lttng::print("{}", static_cast<int64_t>(*gid));
			}

			break;
		case LTTNG_PROCESS_ATTR_VALUE_TYPE_USER_NAME:
			if (const auto name = value.user_name()) {
				lttng::print("`{}`", name);
			}

			break;
		case LTTNG_PROCESS_ATTR_VALUE_TYPE_GROUP_NAME:
			if (const auto name = value.group_name()) {
				lttng::print("`{}`", name);
			}

			break;
		default:
			LTTNG_THROW_ERROR("");
		}
	}

	lttng::print("\n");
}

/*
 * List all trackers of a domain
 */
void list_trackers(const lttng::cli::domain& domain)
{
	lttng::print("Tracked process attributes\n");

	switch (domain.type()) {
	case LTTNG_DOMAIN_KERNEL:
	{
		const auto kernel_domain = domain.as_kernel();

		/* pid tracker */
		list_process_attr_tracker(kernel_domain.process_id_tracker(),
					  LTTNG_PROCESS_ATTR_PROCESS_ID);

		/* vpid tracker */
		list_process_attr_tracker(kernel_domain.virtual_process_id_tracker(),
					  LTTNG_PROCESS_ATTR_VIRTUAL_PROCESS_ID);

		/* uid tracker */
		list_process_attr_tracker(kernel_domain.user_id_tracker(),
					  LTTNG_PROCESS_ATTR_USER_ID);

		/* vuid tracker */
		list_process_attr_tracker(kernel_domain.virtual_user_id_tracker(),
					  LTTNG_PROCESS_ATTR_VIRTUAL_USER_ID);

		/* gid tracker */
		list_process_attr_tracker(kernel_domain.group_id_tracker(),
					  LTTNG_PROCESS_ATTR_GROUP_ID);

		/* vgid tracker */
		list_process_attr_tracker(kernel_domain.virtual_group_id_tracker(),
					  LTTNG_PROCESS_ATTR_VIRTUAL_GROUP_ID);
		break;
	}
	case LTTNG_DOMAIN_UST:
	{
		const auto ust_domain = domain.as_ust();

		/* vpid tracker */
		list_process_attr_tracker(ust_domain.virtual_process_id_tracker(),
					  LTTNG_PROCESS_ATTR_VIRTUAL_PROCESS_ID);

		/* vuid tracker */
		list_process_attr_tracker(ust_domain.virtual_user_id_tracker(),
					  LTTNG_PROCESS_ATTR_VIRTUAL_USER_ID);

		/* vgid tracker */
		list_process_attr_tracker(ust_domain.virtual_group_id_tracker(),
					  LTTNG_PROCESS_ATTR_VIRTUAL_GROUP_ID);
		break;
	}
	default:
		break;
	}

	lttng::print("\n");
}

void print_periodic_rotation_schedule(const lttng::cli::rotation_schedule_periodic& schedule)
{
	lttng::print("    timer period: {} {}\n", schedule.period(), USEC_UNIT);
}

void print_size_threshold_rotation_schedule(const lttng::cli::rotation_schedule_size& schedule)
{
	lttng::print("    size threshold: {} bytes\n", schedule.threshold());
}

void print_rotation_schedule(const lttng::cli::rotation_schedule& schedule)
{
	switch (schedule.type()) {
	case LTTNG_ROTATION_SCHEDULE_TYPE_SIZE_THRESHOLD:
		print_size_threshold_rotation_schedule(schedule.as_size());
		break;
	case LTTNG_ROTATION_SCHEDULE_TYPE_PERIODIC:
		print_periodic_rotation_schedule(schedule.as_periodic());
		break;
	default:
		LTTNG_THROW_ERROR("");
	}
}

/*
 * List the automatic rotation settings.
 */
void list_rotate_settings(const lttng::cli::session& session)
{
	const auto schedules = session.rotation_schedules();

	if (schedules.is_empty()) {
		return;
	}

	lttng::print("Automatic rotation schedules:\n");

	for (const auto& schedule : schedules) {
		print_rotation_schedule(schedule);
	}

	lttng::print("\n");
}

/*
 * List available tracing session. List only basic information.
 */
void list_sessions(const lttng::cli::session_list& sessions)
{
	DBG("Session count %zu", sessions.size());

	/* Pretty print */
	if (sessions.is_empty()) {
		lttng::print("Currently no available recording session\n");
		return;
	}

	if (!the_config->session_name) {
		lttng::print("Available recording sessions:\n");
	}

	auto session_found = false;
	auto i = 0U;

	for (const auto& session : sessions) {
		if (the_config->session_name) {
			if (session.name() == *the_config->session_name) {
				session_found = true;
				lttng::print("Recording session {}: [{}{}]\n",
					     *the_config->session_name,
					     active_string(session.is_active()),
					     snapshot_string(session.is_snapshot_mode()));

				if (session.output()) {
					lttng::print("{}Trace output: {}\n\n",
						     indent4,
						     session.output());
				}

				break;
			}
		} else {
			lttng::print("  {}) {} [{}{}]\n",
				     i + 1,
				     session.name(),
				     active_string(session.is_active()),
				     snapshot_string(session.is_snapshot_mode()));

			if (session.output()) {
				lttng::print("{}Trace output: {}\n", indent4, session.output());
			}

			if (const auto live_period = session.live_timer_period_us()) {
				lttng::print("{}Live timer interval: {} {}\n",
					     indent4,
					     *live_period,
					     USEC_UNIT);
			}

			lttng::print("\n");
		}

		++i;
	}

	if (!session_found && the_config->session_name) {
		LTTNG_THROW_ERROR(
			lttng::format("Session '{}' not found", *the_config->session_name));
	}

	if (!the_config->session_name) {
		lttng::print("\nUse lttng list <session_name> for more details\n");
	}
}

/*
 * List available domain(s) for a session.
 */
void list_domains(const lttng::cli::session& session)
{
	const auto domains = session.domains();

	/* Pretty print */
	lttng::print("Domains:\n-------------\n");
	if (domains.is_empty()) {
		lttng::print("  None\n");
		return;
	}

	for (const auto& domain : domains) {
		switch (domain.type()) {
		case LTTNG_DOMAIN_KERNEL:
			lttng::print("  - Kernel\n");
			break;
		case LTTNG_DOMAIN_UST:
			lttng::print("  - UST global\n");
			break;
		case LTTNG_DOMAIN_JUL:
			lttng::print("  - JUL (java.util.logging)\n");
			break;
		case LTTNG_DOMAIN_LOG4J:
			lttng::print("  - Log4j\n");
			break;
		case LTTNG_DOMAIN_LOG4J2:
			lttng::print("  - Log4j2\n");
			break;
		case LTTNG_DOMAIN_PYTHON:
			lttng::print("  - Python (logging)\n");
			break;
		default:
			break;
		}
	}
}

} /* namespace */

/*
 * Pretty-print (human-readable) output for the list command.
 *
 * This function implements the non-MI output format for listing sessions,
 * domains, channels, events, and trackers.
 */
void list_human(const list_cmd_config& config)
{
	/* Cache configuration for use by helpers */
	the_config = &config;

	const lttng::cli::session_list sessions;

	if (!config.session_name) {
		if (!config.kernel && !config.userspace && !config.jul && !config.log4j &&
		    !config.log4j2 && !config.python) {
			list_sessions(sessions);
		}
		if (config.kernel) {
			if (config.syscall) {
				list_syscalls();
			} else {
				list_kernel_events();
			}
		}
		if (config.userspace) {
			if (config.fields) {
				list_ust_event_fields();
			} else {
				list_ust_events();
			}
		}
		if (config.jul || config.log4j || config.log4j2 || config.python) {
			list_agent_events();
		}
	} else {
		/* Get the session set once for all operations */
		const auto found_session = sessions.find_by_name(config.session_name->c_str());

		if (!found_session) {
			LTTNG_THROW_ERROR(
				lttng::format("Session '{}' not found", *config.session_name));
		}

		/* List session attributes */
		list_sessions(sessions);
		list_rotate_settings(*found_session);

		/* Domain listing */
		if (config.domain) {
			list_domains(*found_session);
			return;
		}

		const auto session_domains = found_session->domains();

		/* Channel listing */
		if (config.kernel || config.userspace) {
			LTTNG_ASSERT(config.domain_type);

			const auto domain = session_domains.find_by_type(*config.domain_type);

			if (!domain) {
				LTTNG_THROW_ERROR("Domain not found in session");
			}

			/* Trackers */
			list_trackers(*domain);

			/* Channels */
			list_channels(*domain,
				      config.channel_name ? config.channel_name->c_str() : nullptr,
				      found_session->is_snapshot_mode());
		} else {
			/* We want all domain(s) */
			for (const auto& domain : session_domains) {
				switch (domain.type()) {
				case LTTNG_DOMAIN_KERNEL:
					lttng::print("=== Domain: Linux kernel ===\n\n");
					break;
				case LTTNG_DOMAIN_UST:
					lttng::print("=== Domain: User space ===\n\n");
					lttng::print("Buffering scheme: {}\n\n",
						     domain.buffer_ownership_model() ==
								     LTTNG_BUFFER_PER_PID ?
							     "per-process" :
							     "per-user");
					break;
				case LTTNG_DOMAIN_JUL:
					lttng::print("=== Domain: JUL (java.util.logging) ===\n\n");
					break;
				case LTTNG_DOMAIN_LOG4J:
					lttng::print("=== Domain: Log4j ===\n\n");
					break;
				case LTTNG_DOMAIN_LOG4J2:
					lttng::print("=== Domain: Log4j2 ===\n\n");
					break;
				case LTTNG_DOMAIN_PYTHON:
					lttng::print("=== Domain: Python logging ===\n\n");
					break;
				default:
					lttng::print("=== Domain: Unimplemented ===\n\n");
					break;
				}

				if (is_agent_domain(domain.type())) {
					list_session_agent_events(domain);
					continue;
				}

				switch (domain.type()) {
				case LTTNG_DOMAIN_KERNEL:
				case LTTNG_DOMAIN_UST:
					list_trackers(domain);
					break;
				default:
					break;
				}

				list_channels(domain,
					      config.channel_name ? config.channel_name->c_str() :
								    nullptr,
					      found_session->is_snapshot_mode());
			}
		}
	}
}
