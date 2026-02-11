/*
 * SPDX-FileCopyrightText: 2014 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include "agent-domain.hpp"
#include "context-configuration.hpp"
#include "domain.hpp"
#include "recording-channel-configuration.hpp"
#include "save.hpp"
#include "session.hpp"

#include <common/config/session-config.hpp>
#include <common/defaults.hpp>
#include <common/domain.hpp>
#include <common/error.hpp>
#include <common/file-descriptor.hpp>
#include <common/optional.hpp>
#include <common/runas.hpp>
#include <common/urcu.hpp>
#include <common/utils.hpp>

#include <lttng/event-rule/event-rule.h>
#include <lttng/event-rule/jul-logging.h>
#include <lttng/event-rule/kernel-kprobe.h>
#include <lttng/event-rule/kernel-syscall.h>
#include <lttng/event-rule/kernel-tracepoint.h>
#include <lttng/event-rule/kernel-uprobe.h>
#include <lttng/event-rule/log4j-logging.h>
#include <lttng/event-rule/log4j2-logging.h>
#include <lttng/event-rule/python-logging.h>
#include <lttng/event-rule/user-tracepoint.h>
#include <lttng/kernel-probe.h>
#include <lttng/log-level-rule.h>
#include <lttng/save-internal.hpp>
#include <lttng/userspace-probe.h>

#include <fcntl.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <urcu/uatomic.h>

namespace ls = lttng::sessiond;
namespace lsc = lttng::sessiond::config;
using rcc = lttng::sessiond::config::recording_channel_configuration;

namespace {

/*
 * RAII wrapper for config_writer that throws exceptions on error.
 */
namespace session_config {

class writer final {
public:
	explicit writer(lttng::file_descriptor fd, bool indent) :
		_fd(std::move(fd)), _writer(config_writer_create(_fd.fd(), indent ? 1 : 0))
	{
		if (!_writer) {
			LTTNG_THROW_SAVE_ERROR("Failed to create session configuration writer");
		}
	}

	~writer() noexcept
	{
		if (_writer) {
			config_writer_destroy(_writer);
		}
	}

	writer(const writer&) = delete;
	writer& operator=(const writer&) = delete;
	writer(writer&&) = delete;
	writer& operator=(writer&&) = delete;

	void open_element(lttng::c_string_view element_name)
	{
		if (config_writer_open_element(_writer, element_name)) {
			LTTNG_THROW_SAVE_ERROR(
				lttng::format("Failed to open XML element: name={}", element_name));
		}
	}

	void close_element()
	{
		if (config_writer_close_element(_writer)) {
			LTTNG_THROW_SAVE_ERROR("Failed to close XML element");
		}
	}

	void write(lttng::c_string_view element_name, lttng::c_string_view value)
	{
		if (config_writer_write_element_string(_writer, element_name, value)) {
			LTTNG_THROW_SAVE_ERROR(
				lttng::format("Failed to write string element: name={}, value=`{}`",
					      element_name,
					      value));
		}
	}

	void write(lttng::c_string_view element_name, const char *value)
	{
		write(element_name, lttng::c_string_view{ value });
	}

	void write(lttng::c_string_view element_name, std::uint64_t value)
	{
		if (config_writer_write_element_unsigned_int(_writer, element_name, value)) {
			LTTNG_THROW_SAVE_ERROR(lttng::format(
				"Failed to write unsigned int element: name={}, value={}",
				element_name,
				value));
		}
	}

	void write(lttng::c_string_view element_name, std::int64_t value)
	{
		if (config_writer_write_element_signed_int(_writer, element_name, value)) {
			LTTNG_THROW_SAVE_ERROR(lttng::format(
				"Failed to write signed int element: name={}, value={}",
				element_name,
				value));
		}
	}

	void write(lttng::c_string_view element_name, bool value)
	{
		if (config_writer_write_element_bool(_writer, element_name, value ? 1 : 0)) {
			LTTNG_THROW_SAVE_ERROR(
				lttng::format("Failed to write bool element: name={}, value={}",
					      element_name,
					      value));
		}
	}

	void write_attribute(lttng::c_string_view name, lttng::c_string_view value)
	{
		if (config_writer_write_attribute(_writer, name, value)) {
			LTTNG_THROW_SAVE_ERROR(lttng::format(
				"Failed to write attribute: name={}, value={}", name, value));
		}
	}

private:
	lttng::file_descriptor _fd;
	config_writer *_writer;
};

} /* namespace session_config */

/*
 * Helper functions for converting modern types to XML configuration strings.
 * These are used by the new domain-based save implementation.
 */

const char *get_buffer_full_policy_string(rcc::buffer_full_policy_t policy) noexcept
{
	switch (policy) {
	case rcc::buffer_full_policy_t::DISCARD_EVENT:
		return config_overwrite_mode_discard;
	case rcc::buffer_full_policy_t::OVERWRITE_OLDEST_PACKET:
		return config_overwrite_mode_overwrite;
	}

	std::abort();
}

const char *
get_buffer_consumption_backend_string(rcc::buffer_consumption_backend_t backend) noexcept
{
	switch (backend) {
	case rcc::buffer_consumption_backend_t::MMAP:
		return config_output_type_mmap;
	case rcc::buffer_consumption_backend_t::SPLICE:
		return config_output_type_splice;
	}

	std::abort();
}

const char *get_buffer_allocation_policy_string(rcc::buffer_allocation_policy_t policy) noexcept
{
	switch (policy) {
	case rcc::buffer_allocation_policy_t::PER_CPU:
		return config_element_channel_allocation_policy_per_cpu;
	case rcc::buffer_allocation_policy_t::PER_CHANNEL:
		return config_element_channel_allocation_policy_per_channel;
	}

	std::abort();
}

const char *
get_buffer_preallocation_policy_string(rcc::buffer_preallocation_policy_t policy) noexcept
{
	switch (policy) {
	case rcc::buffer_preallocation_policy_t::PREALLOCATE:
		return config_element_channel_preallocation_policy_preallocate;
	case rcc::buffer_preallocation_policy_t::ON_DEMAND:
		return config_element_channel_preallocation_policy_on_demand;
	}

	std::abort();
}

const char *get_domain_type_config_string(lttng::domain_class domain_class) noexcept
{
	switch (domain_class) {
	case lttng::domain_class::KERNEL_SPACE:
		return config_domain_type_kernel;
	case lttng::domain_class::USER_SPACE:
		return config_domain_type_ust;
	case lttng::domain_class::JAVA_UTIL_LOGGING:
		return config_domain_type_jul;
	case lttng::domain_class::LOG4J:
		return config_domain_type_log4j;
	case lttng::domain_class::LOG4J2:
		return config_domain_type_log4j2;
	case lttng::domain_class::PYTHON_LOGGING:
		return config_domain_type_python;
	}

	std::abort();
}

const char *get_context_type_string_from_config(lsc::context_configuration::type ctx_type) noexcept
{
	switch (ctx_type) {
	case lsc::context_configuration::type::PID:
		return config_event_context_pid;
	case lsc::context_configuration::type::PROCNAME:
		return config_event_context_procname;
	case lsc::context_configuration::type::PRIO:
		return config_event_context_prio;
	case lsc::context_configuration::type::NICE:
		return config_event_context_nice;
	case lsc::context_configuration::type::VPID:
		return config_event_context_vpid;
	case lsc::context_configuration::type::TID:
		return config_event_context_tid;
	case lsc::context_configuration::type::VTID:
		return config_event_context_vtid;
	case lsc::context_configuration::type::PPID:
		return config_event_context_ppid;
	case lsc::context_configuration::type::VPPID:
		return config_event_context_vppid;
	case lsc::context_configuration::type::PTHREAD_ID:
		return config_event_context_pthread_id;
	case lsc::context_configuration::type::HOSTNAME:
		return config_event_context_hostname;
	case lsc::context_configuration::type::IP:
		return config_event_context_ip;
	case lsc::context_configuration::type::INTERRUPTIBLE:
		return config_event_context_interruptible;
	case lsc::context_configuration::type::PREEMPTIBLE:
		return config_event_context_preemptible;
	case lsc::context_configuration::type::NEED_RESCHEDULE:
		return config_event_context_need_reschedule;
	case lsc::context_configuration::type::MIGRATABLE:
		return config_event_context_migratable;
	case lsc::context_configuration::type::CALLSTACK_USER:
		return config_event_context_callstack_user;
	case lsc::context_configuration::type::CALLSTACK_KERNEL:
		return config_event_context_callstack_kernel;
	case lsc::context_configuration::type::CGROUP_NS:
		return config_event_context_cgroup_ns;
	case lsc::context_configuration::type::IPC_NS:
		return config_event_context_ipc_ns;
	case lsc::context_configuration::type::MNT_NS:
		return config_event_context_mnt_ns;
	case lsc::context_configuration::type::NET_NS:
		return config_event_context_net_ns;
	case lsc::context_configuration::type::PID_NS:
		return config_event_context_pid_ns;
	case lsc::context_configuration::type::TIME_NS:
		return config_event_context_time_ns;
	case lsc::context_configuration::type::USER_NS:
		return config_event_context_user_ns;
	case lsc::context_configuration::type::UTS_NS:
		return config_event_context_uts_ns;
	case lsc::context_configuration::type::UID:
		return config_event_context_uid;
	case lsc::context_configuration::type::EUID:
		return config_event_context_euid;
	case lsc::context_configuration::type::SUID:
		return config_event_context_suid;
	case lsc::context_configuration::type::GID:
		return config_event_context_gid;
	case lsc::context_configuration::type::EGID:
		return config_event_context_egid;
	case lsc::context_configuration::type::SGID:
		return config_event_context_sgid;
	case lsc::context_configuration::type::VUID:
		return config_event_context_vuid;
	case lsc::context_configuration::type::VEUID:
		return config_event_context_veuid;
	case lsc::context_configuration::type::VSUID:
		return config_event_context_vsuid;
	case lsc::context_configuration::type::VGID:
		return config_event_context_vgid;
	case lsc::context_configuration::type::VEGID:
		return config_event_context_vegid;
	case lsc::context_configuration::type::VSGID:
		return config_event_context_vsgid;
	case lsc::context_configuration::type::CPU_ID:
		return config_event_context_cpu_id;
	case lsc::context_configuration::type::PERF_CPU_COUNTER:
	case lsc::context_configuration::type::PERF_THREAD_COUNTER:
	case lsc::context_configuration::type::APP_CONTEXT:
		/* These contexts have special handling, not a simple type string. */
		return nullptr;
	}

	std::abort();
}

/*
 * Convert a blocking timeout from the consumption_blocking_policy to the legacy
 * signed value format expected by the XML schema.
 *
 * Returns:
 *   -1 for unbounded blocking
 *    0 for no blocking
 *   >0 for timed blocking (in microseconds)
 */
std::int64_t get_blocking_timeout_value(const rcc::consumption_blocking_policy& policy) noexcept
{
	switch (policy.mode_) {
	case rcc::consumption_blocking_policy::mode::NONE:
		return 0;
	case rcc::consumption_blocking_policy::mode::UNBOUNDED:
		return -1;
	case rcc::consumption_blocking_policy::mode::TIMED:
		return policy.timeout_us.has_value() ?
			static_cast<std::int64_t>(policy.timeout_us.value()) :
			0;
	}

	return 0;
}

/*
 * Save channel attributes from a recording_channel_configuration.
 *
 * This function writes all channel attributes to the XML config file based on
 * the modern recording_channel_configuration structure.
 */
void save_channel_attributes_from_config(session_config::writer& writer,
					 const lsc::recording_channel_configuration& channel_config,
					 lttng::domain_class domain_class)
{
	/* Overwrite mode */
	const auto *overwrite_mode_str =
		get_buffer_full_policy_string(channel_config.buffer_full_policy);
	if (!overwrite_mode_str) {
		LTTNG_THROW_INVALID_ARGUMENT_ERROR("Invalid buffer full policy");
	}

	writer.write(config_element_overwrite_mode, overwrite_mode_str);

	/* Subbuffer size */
	writer.write(config_element_subbuf_size,
		     static_cast<std::uint64_t>(channel_config.subbuffer_size_bytes));

	/* Number of subbuffers */
	writer.write(config_element_num_subbuf,
		     static_cast<std::uint64_t>(channel_config.subbuffer_count));

	/* Switch timer interval */
	writer.write(config_element_switch_timer_interval,
		     channel_config.switch_timer_period_us.value_or(0));

	/* Read timer interval */
	writer.write(config_element_read_timer_interval,
		     channel_config.read_timer_period_us.value_or(0));

	/* Output type */
	const auto *output_type_str =
		get_buffer_consumption_backend_string(channel_config.buffer_consumption_backend);
	if (!output_type_str) {
		LTTNG_THROW_INVALID_ARGUMENT_ERROR("Invalid buffer consumption backend");
	}

	writer.write(config_element_output_type, output_type_str);

	/* Blocking timeout (UST only, but we always write it as the schema accepts it). */
	writer.write(config_element_blocking_timeout,
		     get_blocking_timeout_value(channel_config.consumption_blocking_policy_));

	/* Allocation policy (UST only, kernel is always global/per-cpu). */
	if (domain_class != lttng::domain_class::KERNEL_SPACE) {
		const auto *allocation_policy_str = get_buffer_allocation_policy_string(
			channel_config.buffer_allocation_policy);
		if (!allocation_policy_str) {
			LTTNG_THROW_INVALID_ARGUMENT_ERROR("Invalid buffer allocation policy");
		}

		writer.write(config_element_channel_allocation_policy, allocation_policy_str);
	}

	/* Preallocation policy (UST only). */
	if (domain_class != lttng::domain_class::KERNEL_SPACE) {
		const auto *preallocation_policy_str = get_buffer_preallocation_policy_string(
			channel_config.buffer_preallocation_policy);
		if (!preallocation_policy_str) {
			LTTNG_THROW_INVALID_ARGUMENT_ERROR("Invalid buffer preallocation policy");
		}

		writer.write(config_element_channel_preallocation_policy, preallocation_policy_str);
	}

	/* Monitor timer interval */
	if (channel_config.monitor_timer_period_us.has_value()) {
		writer.write(config_element_monitor_timer_interval,
			     channel_config.monitor_timer_period_us.value());
	}

	/* Watchdog timer interval */
	if (channel_config.watchdog_timer_period_us.has_value()) {
		writer.write(config_element_watchdog_timer_interval,
			     channel_config.watchdog_timer_period_us.value());
	}

	/* Memory reclamation policy */
	if (channel_config.automatic_memory_reclamation_maximal_age.has_value()) {
		const auto age_threshold =
			channel_config.automatic_memory_reclamation_maximal_age.value().count();

		writer.open_element(config_element_channel_reclaim_policy);

		if (age_threshold != 0) {
			writer.open_element(config_element_channel_reclaim_policy_periodic);
			writer.write(config_element_channel_reclaim_policy_periodic_age_threshold,
				     static_cast<std::uint64_t>(age_threshold));
			writer.close_element();
		} else {
			writer.open_element(config_element_channel_reclaim_policy_consumed);
			writer.close_element();
		}

		writer.close_element();
	}
}

/*
 * Save a single context from a context_configuration.
 */
void save_context_from_config(session_config::writer& writer,
			      const lsc::context_configuration& ctx_config)
{
	writer.open_element(config_element_context);

	switch (ctx_config.context_type) {
	case lsc::context_configuration::type::PERF_CPU_COUNTER:
	case lsc::context_configuration::type::PERF_THREAD_COUNTER:
	{
		const auto& perf_ctx =
			static_cast<const lsc::perf_counter_context_configuration&>(ctx_config);

		writer.open_element(config_element_context_perf);
		writer.write(config_element_type, static_cast<std::uint64_t>(perf_ctx.perf_type));
		writer.write(config_element_config,
			     static_cast<std::uint64_t>(perf_ctx.perf_config));
		writer.write(config_element_name, perf_ctx.name.c_str());
		writer.close_element();
		break;
	}
	case lsc::context_configuration::type::APP_CONTEXT:
	{
		const auto& app_ctx =
			static_cast<const lsc::app_context_configuration&>(ctx_config);

		writer.open_element(config_element_context_app);
		writer.write(config_element_context_app_provider_name,
			     app_ctx.provider_name.c_str());
		writer.write(config_element_context_app_ctx_name, app_ctx.context_name.c_str());
		writer.close_element();
		break;
	}
	default:
	{
		/* Generic context with just a type string. */
		const auto *ctx_type_str =
			get_context_type_string_from_config(ctx_config.context_type);
		if (!ctx_type_str) {
			LTTNG_THROW_INVALID_ARGUMENT_ERROR(
				"Unsupported context type in configuration");
		}

		writer.write(config_element_type, ctx_type_str);
		break;
	}
	}

	/* Close context element */
	writer.close_element();
}

/*
 * Save all contexts from a recording_channel_configuration.
 */
void save_contexts_from_config(session_config::writer& writer,
			       const lsc::recording_channel_configuration& channel_config)
{
	const auto& contexts = channel_config.get_contexts();

	if (contexts.empty()) {
		return;
	}

	writer.open_element(config_element_contexts);

	for (const auto& ctx : contexts) {
		save_context_from_config(writer, *ctx);
	}

	writer.close_element();
}

/*
 * Get the loglevel type string from a log level rule type.
 */
const char *get_loglevel_type_string_from_rule_type(lttng_log_level_rule_type rule_type) noexcept
{
	switch (rule_type) {
	case LTTNG_LOG_LEVEL_RULE_TYPE_EXACTLY:
		return config_loglevel_type_single;
	case LTTNG_LOG_LEVEL_RULE_TYPE_AT_LEAST_AS_SEVERE_AS:
		return config_loglevel_type_range;
	case LTTNG_LOG_LEVEL_RULE_TYPE_UNKNOWN:
	default:
		return config_loglevel_type_all;
	}
}

/*
 * Save a user-space tracepoint event from an event rule.
 */
void save_user_tracepoint_event_rule(session_config::writer& writer,
				     const lttng_event_rule *event_rule,
				     bool is_enabled)
{
	const char *pattern = nullptr;
	const char *filter_expr = nullptr;
	const lttng_log_level_rule *log_level_rule = nullptr;
	unsigned int exclusion_count = 0;

	writer.open_element(config_element_event);

	/* Name/pattern */
	auto status = lttng_event_rule_user_tracepoint_get_name_pattern(event_rule, &pattern);
	if (status == LTTNG_EVENT_RULE_STATUS_OK && pattern && pattern[0] != '\0') {
		writer.write(config_element_name, pattern);
	}

	/* Enabled */
	writer.write(config_element_enabled, is_enabled);

	/* Type is always TRACEPOINT for user space */
	writer.write(config_element_type, config_event_type_tracepoint);

	/* Log level */
	status = lttng_event_rule_user_tracepoint_get_log_level_rule(event_rule, &log_level_rule);
	if (status == LTTNG_EVENT_RULE_STATUS_OK && log_level_rule) {
		const auto rule_type = lttng_log_level_rule_get_type(log_level_rule);
		const auto *loglevel_type_str = get_loglevel_type_string_from_rule_type(rule_type);

		writer.write(config_element_loglevel_type, loglevel_type_str);

		int level = -1;
		if (rule_type == LTTNG_LOG_LEVEL_RULE_TYPE_EXACTLY) {
			lttng_log_level_rule_exactly_get_level(log_level_rule, &level);
		} else if (rule_type == LTTNG_LOG_LEVEL_RULE_TYPE_AT_LEAST_AS_SEVERE_AS) {
			lttng_log_level_rule_at_least_as_severe_as_get_level(log_level_rule,
									     &level);
		}

		if (rule_type != LTTNG_LOG_LEVEL_RULE_TYPE_UNKNOWN) {
			writer.write(config_element_loglevel, static_cast<std::int64_t>(level));
		}
	} else {
		/* No log level rule means "ALL" */
		writer.write(config_element_loglevel_type, config_loglevel_type_all);
	}

	/* Filter */
	status = lttng_event_rule_user_tracepoint_get_filter(event_rule, &filter_expr);
	if (status == LTTNG_EVENT_RULE_STATUS_OK && filter_expr) {
		writer.write(config_element_filter, filter_expr);
	}

	/* Exclusions */
	status = lttng_event_rule_user_tracepoint_get_name_pattern_exclusion_count(
		event_rule, &exclusion_count);
	if (status == LTTNG_EVENT_RULE_STATUS_OK && exclusion_count > 0) {
		writer.open_element(config_element_exclusions);

		for (unsigned int i = 0; i < exclusion_count; i++) {
			const char *exclusion = nullptr;
			status =
				lttng_event_rule_user_tracepoint_get_name_pattern_exclusion_at_index(
					event_rule, i, &exclusion);
			if (status != LTTNG_EVENT_RULE_STATUS_OK) {
				continue;
			}

			writer.write(config_element_exclusion, exclusion);
		}

		writer.close_element();
	}

	/* Close event element */
	writer.close_element();
}

/*
 * Helper function for agent logging event rules which share the same structure.
 *
 * This function handles the common logic for saving agent events (JUL, Log4j,
 * Log4j2, Python) that share identical configuration structures but have
 * their own domain-specific accessor functions.
 */
void save_agent_logging_event_rule(
	session_config::writer& writer,
	const lttng_event_rule *event_rule,
	bool is_enabled,
	lttng_event_rule_status (*get_name_pattern)(const struct lttng_event_rule *, const char **),
	lttng_event_rule_status (*get_log_level_rule)(const struct lttng_event_rule *,
						      const struct lttng_log_level_rule **),
	lttng_event_rule_status (*get_filter)(const struct lttng_event_rule *, const char **))
{
	const char *pattern = nullptr;
	const char *filter_expr = nullptr;
	const lttng_log_level_rule *log_level_rule = nullptr;

	writer.open_element(config_element_event);

	auto status = get_name_pattern(event_rule, &pattern);
	if (status == LTTNG_EVENT_RULE_STATUS_OK && pattern && pattern[0] != '\0') {
		writer.write(config_element_name, pattern);
	}

	writer.write(config_element_enabled, is_enabled);
	writer.write(config_element_type, config_event_type_tracepoint);

	status = get_log_level_rule(event_rule, &log_level_rule);
	if (status == LTTNG_EVENT_RULE_STATUS_OK && log_level_rule) {
		const auto rule_type = lttng_log_level_rule_get_type(log_level_rule);
		const auto *loglevel_type_str = get_loglevel_type_string_from_rule_type(rule_type);

		writer.write(config_element_loglevel_type, loglevel_type_str);

		int level = -1;
		if (rule_type == LTTNG_LOG_LEVEL_RULE_TYPE_EXACTLY) {
			lttng_log_level_rule_exactly_get_level(log_level_rule, &level);
		} else if (rule_type == LTTNG_LOG_LEVEL_RULE_TYPE_AT_LEAST_AS_SEVERE_AS) {
			lttng_log_level_rule_at_least_as_severe_as_get_level(log_level_rule,
									     &level);
		}

		if (rule_type != LTTNG_LOG_LEVEL_RULE_TYPE_UNKNOWN) {
			writer.write(config_element_loglevel, static_cast<std::int64_t>(level));
		}
	} else {
		writer.write(config_element_loglevel_type, config_loglevel_type_all);
	}

	status = get_filter(event_rule, &filter_expr);
	if (status == LTTNG_EVENT_RULE_STATUS_OK && filter_expr) {
		writer.write(config_element_filter, filter_expr);
	}

	writer.close_element();
}

void save_jul_logging_event_rule(session_config::writer& writer,
				 const lttng_event_rule *event_rule,
				 bool is_enabled)
{
	save_agent_logging_event_rule(writer,
				      event_rule,
				      is_enabled,
				      lttng_event_rule_jul_logging_get_name_pattern,
				      lttng_event_rule_jul_logging_get_log_level_rule,
				      lttng_event_rule_jul_logging_get_filter);
}

void save_log4j_logging_event_rule(session_config::writer& writer,
				   const lttng_event_rule *event_rule,
				   bool is_enabled)
{
	save_agent_logging_event_rule(writer,
				      event_rule,
				      is_enabled,
				      lttng_event_rule_log4j_logging_get_name_pattern,
				      lttng_event_rule_log4j_logging_get_log_level_rule,
				      lttng_event_rule_log4j_logging_get_filter);
}

void save_log4j2_logging_event_rule(session_config::writer& writer,
				    const lttng_event_rule *event_rule,
				    bool is_enabled)
{
	save_agent_logging_event_rule(writer,
				      event_rule,
				      is_enabled,
				      lttng_event_rule_log4j2_logging_get_name_pattern,
				      lttng_event_rule_log4j2_logging_get_log_level_rule,
				      lttng_event_rule_log4j2_logging_get_filter);
}

void save_python_logging_event_rule(session_config::writer& writer,
				    const lttng_event_rule *event_rule,
				    bool is_enabled)
{
	save_agent_logging_event_rule(writer,
				      event_rule,
				      is_enabled,
				      lttng_event_rule_python_logging_get_name_pattern,
				      lttng_event_rule_python_logging_get_log_level_rule,
				      lttng_event_rule_python_logging_get_filter);
}

/*
 * Save a kernel tracepoint event from an event rule.
 */
void save_kernel_tracepoint_event_rule(session_config::writer& writer,
				       const lttng_event_rule *event_rule,
				       bool is_enabled)
{
	const char *pattern = nullptr;
	const char *filter_expr = nullptr;

	writer.open_element(config_element_event);

	/* Name/pattern */
	auto status = lttng_event_rule_kernel_tracepoint_get_name_pattern(event_rule, &pattern);
	if (status == LTTNG_EVENT_RULE_STATUS_OK && pattern && pattern[0] != '\0') {
		writer.write(config_element_name, pattern);
	}

	/* Enabled */
	writer.write(config_element_enabled, is_enabled);

	/* Type is TRACEPOINT */
	writer.write(config_element_type, config_event_type_tracepoint);

	/* Filter */
	status = lttng_event_rule_kernel_tracepoint_get_filter(event_rule, &filter_expr);
	if (status == LTTNG_EVENT_RULE_STATUS_OK && filter_expr) {
		writer.write(config_element_filter, filter_expr);
	}

	/* Close event element */
	writer.close_element();
}

/*
 * Save a kernel syscall event from an event rule.
 */
void save_kernel_syscall_event_rule(session_config::writer& writer,
				    const lttng_event_rule *event_rule,
				    bool is_enabled)
{
	const char *pattern = nullptr;
	const char *filter_expr = nullptr;

	writer.open_element(config_element_event);

	/* Name/pattern */
	auto status = lttng_event_rule_kernel_syscall_get_name_pattern(event_rule, &pattern);
	if (status == LTTNG_EVENT_RULE_STATUS_OK && pattern && pattern[0] != '\0') {
		writer.write(config_element_name, pattern);
	}

	/* Enabled */
	writer.write(config_element_enabled, is_enabled);

	/* Type is SYSCALL */
	writer.write(config_element_type, config_event_type_syscall);

	/* Filter */
	status = lttng_event_rule_kernel_syscall_get_filter(event_rule, &filter_expr);
	if (status == LTTNG_EVENT_RULE_STATUS_OK && filter_expr) {
		writer.write(config_element_filter, filter_expr);
	}

	/* Close event element */
	writer.close_element();
}

/*
 * Save a kernel kprobe event from an event rule.
 */
void save_kernel_kprobe_event_rule(session_config::writer& writer,
				   const lttng_event_rule *event_rule,
				   bool is_enabled)
{
	const char *event_name = nullptr;
	const lttng_kernel_probe_location *location = nullptr;

	writer.open_element(config_element_event);

	/* Event name */
	auto status = lttng_event_rule_kernel_kprobe_get_event_name(event_rule, &event_name);
	if (status == LTTNG_EVENT_RULE_STATUS_OK && event_name && event_name[0] != '\0') {
		writer.write(config_element_name, event_name);
	}

	/* Enabled */
	writer.write(config_element_enabled, is_enabled);

	/* Type is PROBE (kprobe) */
	writer.write(config_element_type, config_event_type_probe);

	/* Probe attributes */
	status = lttng_event_rule_kernel_kprobe_get_location(event_rule, &location);
	if (status == LTTNG_EVENT_RULE_STATUS_OK && location) {
		writer.open_element(config_element_attributes);
		writer.open_element(config_element_probe_attributes);

		const auto loc_type = lttng_kernel_probe_location_get_type(location);
		if (loc_type == LTTNG_KERNEL_PROBE_LOCATION_TYPE_ADDRESS) {
			std::uint64_t addr = 0;
			lttng_kernel_probe_location_address_get_address(location, &addr);
			writer.write(config_element_address, addr);
		} else if (loc_type == LTTNG_KERNEL_PROBE_LOCATION_TYPE_SYMBOL_OFFSET) {
			const char *symbol = lttng_kernel_probe_location_symbol_get_name(location);
			std::uint64_t offset = 0;
			lttng_kernel_probe_location_symbol_get_offset(location, &offset);

			if (symbol) {
				writer.write(config_element_symbol_name, symbol);
			}
			if (offset != 0) {
				writer.write(config_element_offset, offset);
			}
		}

		/* Close probe_attributes */
		writer.close_element();
		/* Close attributes */
		writer.close_element();
	}

	/* Close event element */
	writer.close_element();
}

/*
 * Save a kernel uprobe event from an event rule.
 */
void save_kernel_uprobe_event_rule(session_config::writer& writer,
				   const lttng_event_rule *event_rule,
				   bool is_enabled)
{
	const char *event_name = nullptr;
	const lttng_userspace_probe_location *location = nullptr;

	writer.open_element(config_element_event);

	/* Event name */
	auto status = lttng_event_rule_kernel_uprobe_get_event_name(event_rule, &event_name);
	if (status == LTTNG_EVENT_RULE_STATUS_OK && event_name && event_name[0] != '\0') {
		writer.write(config_element_name, event_name);
	}

	/* Enabled */
	writer.write(config_element_enabled, is_enabled);

	/* Type is USERSPACE_PROBE */
	writer.write(config_element_type, config_event_type_userspace_probe);

	/* Userspace probe attributes */
	status = lttng_event_rule_kernel_uprobe_get_location(event_rule, &location);
	if (status == LTTNG_EVENT_RULE_STATUS_OK && location) {
		const auto loc_type = lttng_userspace_probe_location_get_type(location);

		writer.open_element(config_element_attributes);

		if (loc_type == LTTNG_USERSPACE_PROBE_LOCATION_TYPE_FUNCTION) {
			const auto *lookup_method =
				lttng_userspace_probe_location_get_lookup_method(location);
			const auto lookup_type =
				lttng_userspace_probe_location_lookup_method_get_type(
					lookup_method);

			const char *binary_path =
				lttng_userspace_probe_location_function_get_binary_path(location);
			const char *function_name =
				lttng_userspace_probe_location_function_get_function_name(location);

			writer.open_element(config_element_userspace_probe_function_attributes);

			const char *lookup_method_str;
			switch (lookup_type) {
			case LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_FUNCTION_ELF:
				lookup_method_str =
					config_element_userspace_probe_lookup_function_elf;
				break;
			case LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_FUNCTION_DEFAULT:
			default:
				lookup_method_str =
					config_element_userspace_probe_lookup_function_default;
				break;
			}

			writer.write(config_element_userspace_probe_lookup, lookup_method_str);

			if (binary_path) {
				writer.write(config_element_userspace_probe_location_binary_path,
					     binary_path);
			}

			if (function_name) {
				writer.write(
					config_element_userspace_probe_function_location_function_name,
					function_name);
			}

			/* Close function attributes */
			writer.close_element();
		} else if (loc_type == LTTNG_USERSPACE_PROBE_LOCATION_TYPE_TRACEPOINT) {
			const char *binary_path =
				lttng_userspace_probe_location_tracepoint_get_binary_path(location);
			const char *probe_name =
				lttng_userspace_probe_location_tracepoint_get_probe_name(location);
			const char *provider_name =
				lttng_userspace_probe_location_tracepoint_get_provider_name(
					location);

			writer.open_element(config_element_userspace_probe_tracepoint_attributes);

			writer.write(config_element_userspace_probe_lookup,
				     config_element_userspace_probe_lookup_tracepoint_sdt);

			if (binary_path) {
				writer.write(config_element_userspace_probe_location_binary_path,
					     binary_path);
			}

			if (provider_name) {
				writer.write(
					config_element_userspace_probe_tracepoint_location_provider_name,
					provider_name);
			}

			if (probe_name) {
				writer.write(
					config_element_userspace_probe_tracepoint_location_probe_name,
					probe_name);
			}

			/* Close tracepoint attributes */
			writer.close_element();
		}

		/* Close attributes */
		writer.close_element();
	}

	/* Close event element */
	writer.close_element();
}

/*
 * Save a single event from an event_rule_configuration.
 */
void save_event_from_event_rule(session_config::writer& writer,
				const lsc::event_rule_configuration& event_config)
{
	const auto *event_rule = event_config.event_rule.get();
	const auto event_rule_type = lttng_event_rule_get_type(event_rule);

	switch (event_rule_type) {
	case LTTNG_EVENT_RULE_TYPE_USER_TRACEPOINT:
		save_user_tracepoint_event_rule(writer, event_rule, event_config.is_enabled);
		break;
	case LTTNG_EVENT_RULE_TYPE_JUL_LOGGING:
		save_jul_logging_event_rule(writer, event_rule, event_config.is_enabled);
		break;
	case LTTNG_EVENT_RULE_TYPE_LOG4J_LOGGING:
		save_log4j_logging_event_rule(writer, event_rule, event_config.is_enabled);
		break;
	case LTTNG_EVENT_RULE_TYPE_LOG4J2_LOGGING:
		save_log4j2_logging_event_rule(writer, event_rule, event_config.is_enabled);
		break;
	case LTTNG_EVENT_RULE_TYPE_PYTHON_LOGGING:
		save_python_logging_event_rule(writer, event_rule, event_config.is_enabled);
		break;
	case LTTNG_EVENT_RULE_TYPE_KERNEL_TRACEPOINT:
		save_kernel_tracepoint_event_rule(writer, event_rule, event_config.is_enabled);
		break;
	case LTTNG_EVENT_RULE_TYPE_KERNEL_SYSCALL:
		save_kernel_syscall_event_rule(writer, event_rule, event_config.is_enabled);
		break;
	case LTTNG_EVENT_RULE_TYPE_KERNEL_KPROBE:
		save_kernel_kprobe_event_rule(writer, event_rule, event_config.is_enabled);
		break;
	case LTTNG_EVENT_RULE_TYPE_KERNEL_UPROBE:
		save_kernel_uprobe_event_rule(writer, event_rule, event_config.is_enabled);
		break;
	default:
		LTTNG_THROW_INVALID_ARGUMENT_ERROR(lttng::format(
			"Unsupported event rule type: {}", static_cast<int>(event_rule_type)));
	}
}

/*
 * Save all events from a recording_channel_configuration.
 */
void save_events_from_config(session_config::writer& writer,
			     const lsc::recording_channel_configuration& channel_config)
{
	writer.open_element(config_element_events);

	for (const auto& event_pair : channel_config.event_rules) {
		const auto& event_config = *event_pair.second;
		save_event_from_event_rule(writer, event_config);
	}

	/* Close events element */
	writer.close_element();
}

/*
 * Save a channel from a recording_channel_configuration.
 */
void save_channel_from_config(session_config::writer& writer,
			      const lsc::recording_channel_configuration& channel_config,
			      lttng::domain_class domain_class,
			      std::uint64_t live_timer_interval)
{
	writer.open_element(config_element_channel);

	/* Channel name */
	writer.write(config_element_name, channel_config.name.c_str());

	/* Enabled */
	writer.write(config_element_enabled, channel_config.is_enabled);

	/* Channel attributes */
	save_channel_attributes_from_config(writer, channel_config, domain_class);

	/* Tracefile size */
	writer.write(
		config_element_tracefile_size,
		static_cast<std::uint64_t>(channel_config.trace_file_size_limit_bytes.value_or(0)));

	/* Tracefile count */
	writer.write(config_element_tracefile_count,
		     static_cast<std::uint64_t>(channel_config.trace_file_count_limit.value_or(0)));

	/* Live timer interval */
	writer.write(config_element_live_timer_interval, live_timer_interval);

	/* Events */
	save_events_from_config(writer, channel_config);

	/* Contexts */
	save_contexts_from_config(writer, channel_config);

	/* Close channel element */
	writer.close_element();
}

/*
 * Save a single process ID tracker (pid or vpid) from the new domain tracker types.
 */
template <typename TrackerType>
void save_process_id_tracker_from_domain(session_config::writer& writer,
					 const TrackerType& tracker,
					 lttng::c_string_view element_id_tracker,
					 lttng::c_string_view element_target_id)
{
	if (tracker.policy() == lsc::tracking_policy::INCLUDE_ALL) {
		/* Tracking all is the default, nothing to save. */
		return;
	}

	writer.open_element(element_id_tracker);
	writer.open_element(config_element_process_attr_values);

	if (tracker.policy() == lsc::tracking_policy::INCLUDE_SET) {
		for (const auto& value : tracker.inclusion_set()) {
			writer.open_element(element_target_id);
			writer.write(config_element_process_attr_id,
				     static_cast<std::uint64_t>(value));
			/* Close target_id element. */
			writer.close_element();
		}
	}
	/* For EXCLUDE_ALL, we write an empty values element. */

	/* Close values element. */
	writer.close_element();

	/* Close tracker element. */
	writer.close_element();
}

/*
 * Save a UID/GID tracker (uid, vuid, gid, vgid) from the new domain tracker types.
 *
 * These trackers store resolved_process_attr_value which can have both a numeric ID
 * and an optional original name. We prefer to save the name if available.
 */
template <typename TrackerType>
void save_resolved_id_tracker_from_domain(session_config::writer& writer,
					  const TrackerType& tracker,
					  lttng::c_string_view element_id_tracker,
					  lttng::c_string_view element_target_id)
{
	if (tracker.policy() == lsc::tracking_policy::INCLUDE_ALL) {
		/* Tracking all is the default, nothing to save. */
		return;
	}

	writer.open_element(element_id_tracker);
	writer.open_element(config_element_process_attr_values);

	if (tracker.policy() == lsc::tracking_policy::INCLUDE_SET) {
		for (const auto& value : tracker.inclusion_set()) {
			writer.open_element(element_target_id);

			if (value.has_name()) {
				writer.write(config_element_name, value.name().c_str());
			} else {
				writer.write(config_element_process_attr_id,
					     static_cast<std::uint64_t>(value.id()));
			}

			/* Close target_id element. */
			writer.close_element();
		}
	}
	/* For EXCLUDE_ALL, we write an empty values element. */

	/* Close values element. */
	writer.close_element();

	/* Close tracker element. */
	writer.close_element();
}

/*
 * Save all process attribute trackers from a domain.
 *
 * This function saves trackers from the new lttng::sessiond::config::domain structure.
 * The available trackers depend on the domain type:
 * - Kernel: pid, vpid, uid, vuid, gid, vgid
 * - User space: vpid, vuid, vgid
 */
void save_process_attr_trackers_from_domain(session_config::writer& writer,
					    const lsc::domain& domain)
{
	writer.open_element(config_element_process_attr_trackers);

	if (domain.domain_class_ == lttng::domain_class::KERNEL_SPACE) {
		/* Kernel domain: save all 6 trackers. */
		save_process_id_tracker_from_domain(writer,
						    domain.process_id_tracker(),
						    config_element_process_attr_tracker_pid,
						    config_element_process_attr_pid_value);

		save_process_id_tracker_from_domain(writer,
						    domain.virtual_process_id_tracker(),
						    config_element_process_attr_tracker_vpid,
						    config_element_process_attr_vpid_value);

		save_resolved_id_tracker_from_domain(writer,
						     domain.user_id_tracker(),
						     config_element_process_attr_tracker_uid,
						     config_element_process_attr_uid_value);

		save_resolved_id_tracker_from_domain(writer,
						     domain.virtual_user_id_tracker(),
						     config_element_process_attr_tracker_vuid,
						     config_element_process_attr_vuid_value);

		save_resolved_id_tracker_from_domain(writer,
						     domain.group_id_tracker(),
						     config_element_process_attr_tracker_gid,
						     config_element_process_attr_gid_value);

		save_resolved_id_tracker_from_domain(writer,
						     domain.virtual_group_id_tracker(),
						     config_element_process_attr_tracker_vgid,
						     config_element_process_attr_vgid_value);
	} else if (domain.domain_class_ == lttng::domain_class::USER_SPACE) {
		/* UST domain: save 3 virtual trackers. */
		save_process_id_tracker_from_domain(writer,
						    domain.virtual_process_id_tracker(),
						    config_element_process_attr_tracker_vpid,
						    config_element_process_attr_vpid_value);

		save_resolved_id_tracker_from_domain(writer,
						     domain.virtual_user_id_tracker(),
						     config_element_process_attr_tracker_vuid,
						     config_element_process_attr_vuid_value);

		save_resolved_id_tracker_from_domain(writer,
						     domain.virtual_group_id_tracker(),
						     config_element_process_attr_tracker_vgid,
						     config_element_process_attr_vgid_value);
	}
	/* Agent domains don't have process attribute trackers. */

	/* Close process_attr_trackers element. */
	writer.close_element();
}

/*
 * Get buffer type string for a domain.
 *
 * For kernel, it's always "GLOBAL".
 * For UST, we need to check the ownership model from the first channel in the domain.
 */
const char *get_buffer_type_string_for_domain(const lsc::domain& domain, const ltt_session& session)
{
	if (domain.domain_class_ == lttng::domain_class::KERNEL_SPACE) {
		return config_buffer_type_global;
	}

	/*
	 * For UST domains, we need to derive the buffer type from the session's ust_session.
	 * The buffer type is consistent across all channels in the domain.
	 */
	if (session.ust_session) {
		switch (session.ust_session->buffer_type) {
		case LTTNG_BUFFER_PER_PID:
			return config_buffer_type_per_pid;
		case LTTNG_BUFFER_PER_UID:
			return config_buffer_type_per_uid;
		case LTTNG_BUFFER_GLOBAL:
			return config_buffer_type_global;
		}
	}

	/* Default to per-uid for UST. */
	return config_buffer_type_per_uid;
}

bool is_internal_channel(const lttng::c_string_view channel_name) noexcept
{
	return channel_name == DEFAULT_JUL_CHANNEL_NAME ||
		channel_name == DEFAULT_LOG4J_CHANNEL_NAME ||
		channel_name == DEFAULT_LOG4J2_CHANNEL_NAME ||
		channel_name == DEFAULT_PYTHON_CHANNEL_NAME;
}

/*
 * Save a domain from an lttng::sessiond::config::domain using the new configuration types.
 */
void save_domain_from_config(session_config::writer& writer,
			     const lsc::domain& domain,
			     const ltt_session& session,
			     std::uint64_t live_timer_interval)
{
	writer.open_element(config_element_domain);

	/* Domain type */
	const auto *domain_type_str = get_domain_type_config_string(domain.domain_class_);
	if (!domain_type_str) {
		LTTNG_THROW_INVALID_ARGUMENT_ERROR("Invalid domain class");
	}

	writer.write(config_element_type, domain_type_str);

	/* Buffer type */
	const auto *buffer_type_str = get_buffer_type_string_for_domain(domain, session);
	if (!buffer_type_str) {
		LTTNG_THROW_INVALID_ARGUMENT_ERROR("Invalid buffer type");
	}

	writer.write(config_element_buffer_type, buffer_type_str);

	/* Channels */
	writer.open_element(config_element_channels);

	for (const auto& channel_config : domain.recording_channels()) {
		if (is_internal_channel(channel_config.name)) {
			/* Skip internal agent channels. */
			continue;
		}

		save_channel_from_config(
			writer, channel_config, domain.domain_class_, live_timer_interval);
	}

	/* Close channels element */
	writer.close_element();

	save_process_attr_trackers_from_domain(writer, domain);

	/* Close domain element */
	writer.close_element();
}

/*
 * Get the default channel name for an agent domain.
 */
const char *get_agent_domain_default_channel_name(lttng::domain_class domain_class) noexcept
{
	switch (domain_class) {
	case lttng::domain_class::JAVA_UTIL_LOGGING:
		return DEFAULT_JUL_CHANNEL_NAME;
	case lttng::domain_class::LOG4J:
		return DEFAULT_LOG4J_CHANNEL_NAME;
	case lttng::domain_class::LOG4J2:
		return DEFAULT_LOG4J2_CHANNEL_NAME;
	case lttng::domain_class::PYTHON_LOGGING:
		return DEFAULT_PYTHON_CHANNEL_NAME;
	default:
		std::abort();
	}
}

/*
 * Save all events from an agent_domain.
 *
 * Agent domains store event rules directly without channels, so we iterate
 * over the agent_domain's event_rules() instead of a channel's event_rules.
 */
void save_events_from_agent_domain(session_config::writer& writer,
				   const lsc::agent_domain& agent_domain)
{
	writer.open_element(config_element_events);

	for (const auto& event_config : agent_domain.event_rules()) {
		save_event_from_event_rule(writer, event_config);
	}

	/* Close events element */
	writer.close_element();
}

/*
 * Get the default channel from user_space_domain for the given agent domain.
 * Returns nullptr if the channel is not found.
 */
const lsc::recording_channel_configuration *
get_agent_domain_default_channel(const lsc::domain& user_space_domain,
				 lttng::domain_class agent_domain_class)
{
	const char *channel_name = get_agent_domain_default_channel_name(agent_domain_class);
	try {
		return &user_space_domain.get_channel(channel_name);
	} catch (const lsc::exceptions::channel_not_found_error&) {
		return nullptr;
	}
}

/*
 * Save an agent channel.
 *
 * Agent channels are a combination of:
 * - Channel attributes from the underlying UST channel (stored in user_space_domain)
 * - Event rules from the agent_domain
 * - Contexts from the underlying UST channel
 */
void save_agent_channel_from_config(session_config::writer& writer,
				    const lsc::recording_channel_configuration& channel_config,
				    const lsc::agent_domain& agent_domain,
				    std::uint64_t live_timer_interval)
{
	writer.open_element(config_element_channel);

	/* Channel name */
	writer.write(config_element_name, channel_config.name.c_str());

	/* Enabled */
	writer.write(config_element_enabled, channel_config.is_enabled);

	/* Channel attributes */
	save_channel_attributes_from_config(writer, channel_config, agent_domain.domain_class_);

	/* Tracefile size */
	writer.write(
		config_element_tracefile_size,
		static_cast<std::uint64_t>(channel_config.trace_file_size_limit_bytes.value_or(0)));

	/* Tracefile count */
	writer.write(config_element_tracefile_count,
		     static_cast<std::uint64_t>(channel_config.trace_file_count_limit.value_or(0)));

	/* Live timer interval */
	writer.write(config_element_live_timer_interval, live_timer_interval);

	/* Events from agent domain (not from channel config) */
	save_events_from_agent_domain(writer, agent_domain);

	/* Contexts from channel config */
	save_contexts_from_config(writer, channel_config);

	/* Close channel element */
	writer.close_element();
}

/*
 * Save an agent domain from an lttng::sessiond::config::agent_domain.
 *
 * Agent domains (JUL, Log4j, Log4j2, Python) are saved as domains with a single
 * channel. The channel attributes come from the underlying UST channel in the
 * user_space_domain, while the event rules come from the agent_domain itself.
 */
void save_agent_domain_from_config(session_config::writer& writer,
				   const lsc::agent_domain& agent_domain,
				   const lsc::recording_channel_configuration *default_channel,
				   const ltt_session& session,
				   std::uint64_t live_timer_interval)
{
	writer.open_element(config_element_domain);

	/* Domain type */
	const auto *domain_type_str = get_domain_type_config_string(agent_domain.domain_class_);
	if (!domain_type_str) {
		LTTNG_THROW_INVALID_ARGUMENT_ERROR("Invalid agent domain class");
	}

	writer.write(config_element_type, domain_type_str);

	/* Buffer type - get from ust_session */
	const char *buffer_type_str = nullptr;
	if (session.ust_session) {
		switch (session.ust_session->buffer_type) {
		case LTTNG_BUFFER_PER_PID:
			buffer_type_str = config_buffer_type_per_pid;
			break;
		case LTTNG_BUFFER_PER_UID:
			buffer_type_str = config_buffer_type_per_uid;
			break;
		case LTTNG_BUFFER_GLOBAL:
			buffer_type_str = config_buffer_type_global;
			break;
		}
	}

	if (!buffer_type_str) {
		/* Default to per-uid for agent domains. */
		buffer_type_str = config_buffer_type_per_uid;
	}

	writer.write(config_element_buffer_type, buffer_type_str);

	/* Channels */
	writer.open_element(config_element_channels);

	/*
	 * Save the agent channel if it exists in user_space_domain.
	 * If it doesn't exist, we save an empty channels element.
	 */
	if (default_channel) {
		save_agent_channel_from_config(
			writer, *default_channel, agent_domain, live_timer_interval);
	}

	/* Close channels element */
	writer.close_element();

	/* Close domain element */
	writer.close_element();
}

void save_domains(session_config::writer& writer, const ltt_session::locked_ref& session)
{
	if (!session->kernel_session && !session->ust_session) {
		return;
	}

	writer.open_element(config_element_domains);

	if (session->kernel_session) {
		const std::uint64_t live_timer_interval = session->live_timer;

		save_domain_from_config(
			writer, session->kernel_space_domain, *session, live_timer_interval);
	}

	if (session->ust_session) {
		const std::uint64_t live_timer_interval = session->live_timer;

		save_domain_from_config(
			writer, session->user_space_domain, *session, live_timer_interval);

		/*
		 * Look up the default channels for each agent domain in the user_space_domain.
		 */
		const auto jul_channel = get_agent_domain_default_channel(
			session->user_space_domain, lttng::domain_class::JAVA_UTIL_LOGGING);
		const auto log4j_channel = get_agent_domain_default_channel(
			session->user_space_domain, lttng::domain_class::LOG4J);
		const auto log4j2_channel = get_agent_domain_default_channel(
			session->user_space_domain, lttng::domain_class::LOG4J2);
		const auto python_channel = get_agent_domain_default_channel(
			session->user_space_domain, lttng::domain_class::PYTHON_LOGGING);

		save_agent_domain_from_config(
			writer, session->jul_domain, jul_channel, *session, live_timer_interval);

		save_agent_domain_from_config(writer,
					      session->log4j_domain,
					      log4j_channel,
					      *session,
					      live_timer_interval);

		save_agent_domain_from_config(writer,
					      session->log4j2_domain,
					      log4j2_channel,
					      *session,
					      live_timer_interval);

		save_agent_domain_from_config(writer,
					      session->python_domain,
					      python_channel,
					      *session,
					      live_timer_interval);
	}

	/* /domains */
	writer.close_element();
}

void save_consumer_output(session_config::writer& writer, struct consumer_output *output)
{
	LTTNG_ASSERT(output);

	writer.open_element(config_element_consumer_output);
	writer.write(config_element_enabled, output->enabled);
	writer.open_element(config_element_destination);

	switch (output->type) {
	case CONSUMER_DST_LOCAL:
		writer.write(config_element_path, output->dst.session_root_path);
		break;
	case CONSUMER_DST_NET:
	{
		if (!output->dst.net.control_isset) {
			LTTNG_THROW_INVALID_ARGUMENT_ERROR("Missing control URI");
		}
		if (!output->dst.net.data_isset) {
			LTTNG_THROW_INVALID_ARGUMENT_ERROR("Missing data URI");
		}

		std::vector<char> uri(PATH_MAX);

		writer.open_element(config_element_net_output);

		if (uri_to_str_url(&output->dst.net.control, uri.data(), PATH_MAX) < 0) {
			LTTNG_THROW_INVALID_ARGUMENT_ERROR("Failed to convert control URI");
		}
		writer.write(config_element_control_uri, uri.data());

		if (uri_to_str_url(&output->dst.net.data, uri.data(), PATH_MAX) < 0) {
			LTTNG_THROW_INVALID_ARGUMENT_ERROR("Failed to convert data URI");
		}
		writer.write(config_element_data_uri, uri.data());

		/* /net_output */
		writer.close_element();
		break;
	}
	default:
		LTTNG_THROW_INVALID_ARGUMENT_ERROR("Unsupported consumer output type");
	}

	/* /destination */
	writer.close_element();

	/* /consumer_output */
	writer.close_element();
}

void save_snapshot_outputs(session_config::writer& writer, struct snapshot *snapshot)
{
	LTTNG_ASSERT(snapshot);

	writer.open_element(config_element_snapshot_outputs);

	for (auto *output : lttng::urcu::lfht_iteration_adapter<snapshot_output,
								decltype(snapshot_output::node),
								&snapshot_output::node>(
		     *snapshot->output_ht->ht)) {
		writer.open_element(config_element_output);
		writer.write(config_element_name, output->name);
		writer.write(config_element_max_size, static_cast<std::uint64_t>(output->max_size));
		save_consumer_output(writer, output->consumer);
		/* /output */
		writer.close_element();
	}

	/* /snapshot_outputs */
	writer.close_element();
}

void save_session_output(session_config::writer& writer, const ltt_session::locked_ref& session)
{
	if ((session->snapshot_mode && session->snapshot.nb_output == 0) ||
	    (!session->snapshot_mode && !session->consumer)) {
		/* Session is in no output mode */
		return;
	}

	writer.open_element(config_element_output);

	if (session->snapshot_mode) {
		save_snapshot_outputs(writer, &session->snapshot);
	} else {
		if (session->consumer) {
			save_consumer_output(writer, session->consumer);
		}
	}

	/* /output */
	writer.close_element();
}

void save_session_rotation_schedule(session_config::writer& writer,
				    lttng_rotation_schedule_type type,
				    uint64_t value)
{
	const char *element_name;
	const char *value_name;

	switch (type) {
	case LTTNG_ROTATION_SCHEDULE_TYPE_PERIODIC:
		element_name = config_element_rotation_schedule_periodic;
		value_name = config_element_rotation_schedule_periodic_time_us;
		break;
	case LTTNG_ROTATION_SCHEDULE_TYPE_SIZE_THRESHOLD:
		element_name = config_element_rotation_schedule_size_threshold;
		value_name = config_element_rotation_schedule_size_threshold_bytes;
		break;
	default:
		LTTNG_THROW_INVALID_ARGUMENT_ERROR("Invalid rotation schedule type");
	}

	writer.open_element(element_name);
	writer.write(value_name, static_cast<std::uint64_t>(value));
	/* Close schedule descriptor element. */
	writer.close_element();
}

void save_session_rotation_schedules(session_config::writer& writer,
				     const ltt_session::locked_ref& session)
{
	writer.open_element(config_element_rotation_schedules);

	if (session->rotate_timer_period) {
		save_session_rotation_schedule(writer,
					       LTTNG_ROTATION_SCHEDULE_TYPE_PERIODIC,
					       session->rotate_timer_period);
	}
	if (session->rotate_size) {
		save_session_rotation_schedule(
			writer, LTTNG_ROTATION_SCHEDULE_TYPE_SIZE_THRESHOLD, session->rotate_size);
	}

	/* Close rotation schedules element. */
	writer.close_element();
}

/*
 * Save the given session.
 *
 * Return LTTNG_OK on success else a LTTNG_ERR* code.
 */
int save_session(const ltt_session::locked_ref& session,
		 lttng_save_session_attr *attr,
		 lttng_sock_cred *creds)
{
	char config_file_path[LTTNG_PATH_MAX];
	size_t len;
	size_t session_name_len;
	const char *provided_path;
	int file_open_flags = O_CREAT | O_WRONLY | O_TRUNC;

	LTTNG_ASSERT(attr);
	LTTNG_ASSERT(creds);

	session_name_len = strlen(session->name);
	memset(config_file_path, 0, sizeof(config_file_path));

	if (!session_access_ok(session, LTTNG_SOCK_GET_UID_CRED(creds)) || session->destroyed) {
		return LTTNG_ERR_EPERM;
	}

	provided_path = lttng_save_session_attr_get_output_url(attr);
	if (provided_path) {
		DBG3("Save session in provided path %s", provided_path);
		len = strlen(provided_path);
		if (len >= sizeof(config_file_path)) {
			return LTTNG_ERR_SET_URL;
		}
		strncpy(config_file_path, provided_path, sizeof(config_file_path));
	} else {
		char *home_dir = utils_get_user_home_dir(LTTNG_SOCK_GET_UID_CRED(creds));
		if (!home_dir) {
			return LTTNG_ERR_SET_URL;
		}

		const auto ret_len = snprintf(config_file_path,
					      sizeof(config_file_path),
					      DEFAULT_SESSION_HOME_CONFIGPATH,
					      home_dir);
		free(home_dir);
		if (ret_len < 0) {
			PERROR("snprintf save session");
			return LTTNG_ERR_SET_URL;
		}
		len = ret_len;
	}

	/*
	 * Check the path fits in the config file path dst including the '/'
	 * followed by trailing .lttng extension and the NULL terminated string.
	 */
	if ((len + session_name_len + 2 + sizeof(DEFAULT_SESSION_CONFIG_FILE_EXTENSION)) >
	    sizeof(config_file_path)) {
		return LTTNG_ERR_SET_URL;
	}

	if (run_as_mkdir_recursive(config_file_path,
				   S_IRWXU | S_IRWXG,
				   LTTNG_SOCK_GET_UID_CRED(creds),
				   LTTNG_SOCK_GET_GID_CRED(creds))) {
		return LTTNG_ERR_SET_URL;
	}

	/*
	 * At this point, we know that everything fits in the buffer. Validation
	 * was done just above.
	 */
	config_file_path[len++] = '/';
	strncpy(config_file_path + len, session->name, sizeof(config_file_path) - len);
	len += session_name_len;
	strcpy(config_file_path + len, DEFAULT_SESSION_CONFIG_FILE_EXTENSION);
	len += sizeof(DEFAULT_SESSION_CONFIG_FILE_EXTENSION);
	config_file_path[len] = '\0';

	if (!attr->overwrite) {
		file_open_flags |= O_EXCL;
	}

	const int raw_fd = run_as_open(config_file_path,
				       file_open_flags,
				       S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP,
				       LTTNG_SOCK_GET_UID_CRED(creds),
				       LTTNG_SOCK_GET_GID_CRED(creds));
	if (raw_fd < 0) {
		PERROR("Could not create configuration file");
		switch (errno) {
		case EEXIST:
			return LTTNG_ERR_SAVE_FILE_EXIST;
		case EACCES:
			return LTTNG_ERR_EPERM;
		default:
			return LTTNG_ERR_SAVE_IO_FAIL;
		}
	}

	/* Use scope_exit to ensure file cleanup on error. */
	auto unlink_file_on_error = lttng::make_scope_exit([&config_file_path, raw_fd]() noexcept {
		if (unlink(config_file_path)) {
			PERROR("Unlinking XML session configuration.");
		}
	});

	/* Create the RAII writer which takes ownership of a dup'd fd. */
	session_config::writer writer(lttng::file_descriptor(raw_fd), true);

	writer.open_element(config_element_sessions);
	writer.open_element(config_element_session);
	writer.write(config_element_name, session->name);

	if (session->shm_path[0] != '\0') {
		writer.write(config_element_shared_memory_path, session->shm_path);
	}

	writer.write(config_element_trace_format,
		     session->trace_format == LTTNG_TRACE_FORMAT_CTF_1_8 ?
			     config_element_trace_format_ctf_1_8 :
			     config_element_trace_format_ctf_2);

	save_domains(writer, session);

	writer.write(config_element_started, session->active);

	if (session->snapshot_mode || session->live_timer || session->rotate_timer_period ||
	    session->rotate_size) {
		writer.open_element(config_element_attributes);

		if (session->snapshot_mode) {
			writer.write(config_element_snapshot_mode, true);
		} else if (session->live_timer) {
			writer.write(config_element_live_timer_interval,
				     static_cast<std::uint64_t>(session->live_timer));
		}
		if (session->rotate_timer_period || session->rotate_size) {
			save_session_rotation_schedules(writer, session);
		}

		/* /attributes */
		writer.close_element();
	}

	save_session_output(writer, session);

	/* /session */
	writer.close_element();

	/* /sessions */
	writer.close_element();

	/* Success - disarm the cleanup. */
	unlink_file_on_error.disarm();

	return LTTNG_OK;
}

} /* anonymous namespace */

int cmd_save_sessions(lttng_save_session_attr *attr, lttng_sock_cred *creds)
{
	const auto list_lock = lttng::sessiond::lock_session_list();
	const auto session_name = lttng_save_session_attr_get_session_name(attr);

	if (session_name) {
		/*
		 * Mind the order of the declaration of list_lock vs session:
		 * the session list lock must always be released _after_ the release of
		 * a session's reference (the destruction of a ref/locked_ref) to ensure
		 * since the reference's release may unpublish the session from the list of
		 * sessions.
		 */
		try {
			const auto session = ltt_session::find_locked_session(session_name);
			const auto save_ret = save_session(session, attr, creds);
			if (save_ret != LTTNG_OK) {
				return save_ret;
			}
		} catch (const lttng::sessiond::exceptions::session_not_found_error& ex) {
			WARN_FMT("Failed to save session: {} {}", ex.what(), ex.source_location);
			return LTTNG_ERR_SESS_NOT_FOUND;
		}
	} else {
		const auto *list = session_get_list();

		for (auto raw_session_ptr :
		     lttng::urcu::list_iteration_adapter<ltt_session, &ltt_session::list>(
			     list->head)) {
			auto session = [raw_session_ptr]() {
				session_get(raw_session_ptr);
				raw_session_ptr->lock();
				return ltt_session::make_locked_ref(*raw_session_ptr);
			}();
			const auto save_ret = save_session(session, attr, creds);

			/* Don't abort if we don't have the required permissions. */
			if (save_ret != LTTNG_OK && save_ret != LTTNG_ERR_EPERM) {
				return save_ret;
			}
		}
	}

	return LTTNG_OK;
}
