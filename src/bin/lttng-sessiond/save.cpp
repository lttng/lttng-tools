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
using rcc = lttng::sessiond::recording_channel_configuration;

namespace {
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

	return nullptr;
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

	return nullptr;
}

const char *get_buffer_allocation_policy_string(rcc::buffer_allocation_policy_t policy) noexcept
{
	switch (policy) {
	case rcc::buffer_allocation_policy_t::PER_CPU:
		return config_element_channel_allocation_policy_per_cpu;
	case rcc::buffer_allocation_policy_t::PER_CHANNEL:
		return config_element_channel_allocation_policy_per_channel;
	}

	return nullptr;
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

	return nullptr;
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

	return nullptr;
}

const char *get_context_type_string_from_config(ls::context_configuration::type ctx_type) noexcept
{
	switch (ctx_type) {
	case ls::context_configuration::type::PID:
		return config_event_context_pid;
	case ls::context_configuration::type::PROCNAME:
		return config_event_context_procname;
	case ls::context_configuration::type::PRIO:
		return config_event_context_prio;
	case ls::context_configuration::type::NICE:
		return config_event_context_nice;
	case ls::context_configuration::type::VPID:
		return config_event_context_vpid;
	case ls::context_configuration::type::TID:
		return config_event_context_tid;
	case ls::context_configuration::type::VTID:
		return config_event_context_vtid;
	case ls::context_configuration::type::PPID:
		return config_event_context_ppid;
	case ls::context_configuration::type::VPPID:
		return config_event_context_vppid;
	case ls::context_configuration::type::PTHREAD_ID:
		return config_event_context_pthread_id;
	case ls::context_configuration::type::HOSTNAME:
		return config_event_context_hostname;
	case ls::context_configuration::type::IP:
		return config_event_context_ip;
	case ls::context_configuration::type::INTERRUPTIBLE:
		return config_event_context_interruptible;
	case ls::context_configuration::type::PREEMPTIBLE:
		return config_event_context_preemptible;
	case ls::context_configuration::type::NEED_RESCHEDULE:
		return config_event_context_need_reschedule;
	case ls::context_configuration::type::MIGRATABLE:
		return config_event_context_migratable;
	case ls::context_configuration::type::CALLSTACK_USER:
		return config_event_context_callstack_user;
	case ls::context_configuration::type::CALLSTACK_KERNEL:
		return config_event_context_callstack_kernel;
	case ls::context_configuration::type::CGROUP_NS:
		return config_event_context_cgroup_ns;
	case ls::context_configuration::type::IPC_NS:
		return config_event_context_ipc_ns;
	case ls::context_configuration::type::MNT_NS:
		return config_event_context_mnt_ns;
	case ls::context_configuration::type::NET_NS:
		return config_event_context_net_ns;
	case ls::context_configuration::type::PID_NS:
		return config_event_context_pid_ns;
	case ls::context_configuration::type::TIME_NS:
		return config_event_context_time_ns;
	case ls::context_configuration::type::USER_NS:
		return config_event_context_user_ns;
	case ls::context_configuration::type::UTS_NS:
		return config_event_context_uts_ns;
	case ls::context_configuration::type::UID:
		return config_event_context_uid;
	case ls::context_configuration::type::EUID:
		return config_event_context_euid;
	case ls::context_configuration::type::SUID:
		return config_event_context_suid;
	case ls::context_configuration::type::GID:
		return config_event_context_gid;
	case ls::context_configuration::type::EGID:
		return config_event_context_egid;
	case ls::context_configuration::type::SGID:
		return config_event_context_sgid;
	case ls::context_configuration::type::VUID:
		return config_event_context_vuid;
	case ls::context_configuration::type::VEUID:
		return config_event_context_veuid;
	case ls::context_configuration::type::VSUID:
		return config_event_context_vsuid;
	case ls::context_configuration::type::VGID:
		return config_event_context_vgid;
	case ls::context_configuration::type::VEGID:
		return config_event_context_vegid;
	case ls::context_configuration::type::VSGID:
		return config_event_context_vsgid;
	case ls::context_configuration::type::CPU_ID:
		return config_event_context_cpu_id;
	case ls::context_configuration::type::PERF_CPU_COUNTER:
	case ls::context_configuration::type::PERF_THREAD_COUNTER:
	case ls::context_configuration::type::APP_CONTEXT:
		/* These contexts have special handling, not a simple type string. */
		return nullptr;
	}

	return nullptr;
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

/* Forward declarations for save functions using the new config types. */
int save_channel_from_config(config_writer *writer,
			     const ls::recording_channel_configuration& channel_config,
			     lttng::domain_class domain_class,
			     std::uint64_t live_timer_interval);
int save_events_from_config(config_writer *writer,
			    const ls::recording_channel_configuration& channel_config,
			    lttng::domain_class domain_class);
int save_contexts_from_config(config_writer *writer,
			      const ls::recording_channel_configuration& channel_config);
int save_event_from_event_rule(config_writer *writer,
			       const ls::event_rule_configuration& event_config,
			       lttng::domain_class domain_class);

/*
 * Save channel attributes from a recording_channel_configuration.
 *
 * This function writes all channel attributes to the XML config file based on
 * the modern recording_channel_configuration structure.
 */
int save_channel_attributes_from_config(config_writer *writer,
					const ls::recording_channel_configuration& channel_config,
					lttng::domain_class domain_class)
{
	int ret;
	const char *overwrite_mode_str = nullptr;
	const char *output_type_str = nullptr;
	const char *allocation_policy_str = nullptr;
	const char *preallocation_policy_str = nullptr;

	/* Overwrite mode */
	overwrite_mode_str = get_buffer_full_policy_string(channel_config.buffer_full_policy);
	if (!overwrite_mode_str) {
		ret = LTTNG_ERR_INVALID;
		goto end;
	}

	ret = config_writer_write_element_string(
		writer, config_element_overwrite_mode, overwrite_mode_str);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	/* Subbuffer size */
	ret = config_writer_write_element_unsigned_int(
		writer, config_element_subbuf_size, channel_config.subbuffer_size_bytes);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	/* Number of subbuffers */
	ret = config_writer_write_element_unsigned_int(
		writer, config_element_num_subbuf, channel_config.subbuffer_count);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	/* Switch timer interval */
	ret = config_writer_write_element_unsigned_int(
		writer,
		config_element_switch_timer_interval,
		channel_config.switch_timer_period_us.value_or(0));
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	/* Read timer interval */
	ret = config_writer_write_element_unsigned_int(
		writer,
		config_element_read_timer_interval,
		channel_config.read_timer_period_us.value_or(0));
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	/* Output type */
	output_type_str =
		get_buffer_consumption_backend_string(channel_config.buffer_consumption_backend);
	if (!output_type_str) {
		ret = LTTNG_ERR_INVALID;
		goto end;
	}

	ret = config_writer_write_element_string(
		writer, config_element_output_type, output_type_str);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	/* Blocking timeout (UST only, but we always write it as the schema accepts it). */
	ret = config_writer_write_element_signed_int(
		writer,
		config_element_blocking_timeout,
		get_blocking_timeout_value(channel_config.consumption_blocking_policy_));
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	/* Allocation policy (UST only, kernel is always global/per-cpu). */
	if (domain_class != lttng::domain_class::KERNEL_SPACE) {
		allocation_policy_str = get_buffer_allocation_policy_string(
			channel_config.buffer_allocation_policy);
		if (!allocation_policy_str) {
			ret = LTTNG_ERR_INVALID;
			goto end;
		}

		ret = config_writer_write_element_string(
			writer, config_element_channel_allocation_policy, allocation_policy_str);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}
	}

	/* Preallocation policy (UST only). */
	if (domain_class != lttng::domain_class::KERNEL_SPACE) {
		preallocation_policy_str = get_buffer_preallocation_policy_string(
			channel_config.buffer_preallocation_policy);
		if (!preallocation_policy_str) {
			ret = LTTNG_ERR_INVALID;
			goto end;
		}

		ret = config_writer_write_element_string(
			writer,
			config_element_channel_preallocation_policy,
			preallocation_policy_str);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}
	}

	/* Monitor timer interval */
	if (channel_config.monitor_timer_period_us.has_value()) {
		ret = config_writer_write_element_unsigned_int(
			writer,
			config_element_monitor_timer_interval,
			channel_config.monitor_timer_period_us.value());
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}
	}

	/* Watchdog timer interval */
	if (channel_config.watchdog_timer_period_us.has_value()) {
		ret = config_writer_write_element_unsigned_int(
			writer,
			config_element_watchdog_timer_interval,
			channel_config.watchdog_timer_period_us.value());
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}
	}

	/* Memory reclamation policy */
	if (channel_config.automatic_memory_reclamation_maximal_age.has_value()) {
		const auto age_threshold =
			channel_config.automatic_memory_reclamation_maximal_age.value().count();

		ret = config_writer_open_element(writer, config_element_channel_reclaim_policy);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}

		if (age_threshold != 0) {
			ret = config_writer_open_element(
				writer, config_element_channel_reclaim_policy_periodic);
			if (ret) {
				ret = LTTNG_ERR_SAVE_IO_FAIL;
				goto end;
			}
			ret = config_writer_write_element_unsigned_int(
				writer,
				config_element_channel_reclaim_policy_periodic_age_threshold,
				static_cast<std::uint64_t>(age_threshold));
			if (ret) {
				ret = LTTNG_ERR_SAVE_IO_FAIL;
				goto end;
			}
			ret = config_writer_close_element(writer);
			if (ret) {
				ret = LTTNG_ERR_SAVE_IO_FAIL;
				goto end;
			}
		} else {
			ret = config_writer_open_element(
				writer, config_element_channel_reclaim_policy_consumed);
			if (ret) {
				ret = LTTNG_ERR_SAVE_IO_FAIL;
				goto end;
			}
			ret = config_writer_close_element(writer);
			if (ret) {
				ret = LTTNG_ERR_SAVE_IO_FAIL;
				goto end;
			}
		}

		ret = config_writer_close_element(writer);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}
	}

	ret = LTTNG_OK;
end:
	return ret;
}

/*
 * Save a single context from a context_configuration.
 */
int save_context_from_config(config_writer *writer, const ls::context_configuration& ctx_config)
{
	int ret;

	ret = config_writer_open_element(writer, config_element_context);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	switch (ctx_config.context_type) {
	case ls::context_configuration::type::PERF_CPU_COUNTER:
	case ls::context_configuration::type::PERF_THREAD_COUNTER:
	{
		const auto& perf_ctx =
			static_cast<const ls::perf_counter_context_configuration&>(ctx_config);

		ret = config_writer_open_element(writer, config_element_context_perf);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}

		ret = config_writer_write_element_unsigned_int(
			writer,
			config_element_type,
			static_cast<std::uint32_t>(perf_ctx.perf_type));
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}

		ret = config_writer_write_element_unsigned_int(
			writer, config_element_config, perf_ctx.perf_config);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}

		ret = config_writer_write_element_string(
			writer, config_element_name, perf_ctx.name.c_str());
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}

		/* Close perf element */
		ret = config_writer_close_element(writer);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}

		break;
	}
	case ls::context_configuration::type::APP_CONTEXT:
	{
		const auto& app_ctx = static_cast<const ls::app_context_configuration&>(ctx_config);

		ret = config_writer_open_element(writer, config_element_context_app);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}

		ret = config_writer_write_element_string(writer,
							 config_element_context_app_provider_name,
							 app_ctx.provider_name.c_str());
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}

		ret = config_writer_write_element_string(
			writer, config_element_context_app_ctx_name, app_ctx.context_name.c_str());
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}

		/* Close app element */
		ret = config_writer_close_element(writer);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}

		break;
	}
	default:
	{
		/* Generic context with just a type string. */
		const auto *ctx_type_str =
			get_context_type_string_from_config(ctx_config.context_type);
		if (!ctx_type_str) {
			ERR("Unsupported context type in configuration");
			ret = LTTNG_ERR_INVALID;
			goto end;
		}

		ret = config_writer_write_element_string(writer, config_element_type, ctx_type_str);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}

		break;
	}
	}

	/* Close context element */
	ret = config_writer_close_element(writer);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = LTTNG_OK;
end:
	return ret;
}

/*
 * Save all contexts from a recording_channel_configuration.
 */
int save_contexts_from_config(config_writer *writer,
			      const ls::recording_channel_configuration& channel_config)
{
	int ret;
	const auto& contexts = channel_config.get_contexts();

	if (contexts.empty()) {
		return LTTNG_OK;
	}

	ret = config_writer_open_element(writer, config_element_contexts);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	for (const auto& ctx : contexts) {
		ret = save_context_from_config(writer, *ctx);
		if (ret != LTTNG_OK) {
			goto end;
		}
	}

	/* Close contexts element */
	ret = config_writer_close_element(writer);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = LTTNG_OK;
end:
	return ret;
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
int save_user_tracepoint_event_rule(config_writer *writer,
				    const lttng_event_rule *event_rule,
				    bool is_enabled)
{
	int ret;
	const char *pattern = nullptr;
	const char *filter_expr = nullptr;
	const lttng_log_level_rule *log_level_rule = nullptr;
	unsigned int exclusion_count = 0;
	lttng_event_rule_status status;

	ret = config_writer_open_element(writer, config_element_event);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	/* Name/pattern */
	status = lttng_event_rule_user_tracepoint_get_name_pattern(event_rule, &pattern);
	if (status == LTTNG_EVENT_RULE_STATUS_OK && pattern && pattern[0] != '\0') {
		ret = config_writer_write_element_string(writer, config_element_name, pattern);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}
	}

	/* Enabled */
	ret = config_writer_write_element_bool(writer, config_element_enabled, is_enabled);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	/* Type is always TRACEPOINT for user space */
	ret = config_writer_write_element_string(
		writer, config_element_type, config_event_type_tracepoint);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	/* Log level */
	status = lttng_event_rule_user_tracepoint_get_log_level_rule(event_rule, &log_level_rule);
	if (status == LTTNG_EVENT_RULE_STATUS_OK && log_level_rule) {
		const auto rule_type = lttng_log_level_rule_get_type(log_level_rule);
		const char *loglevel_type_str = get_loglevel_type_string_from_rule_type(rule_type);

		ret = config_writer_write_element_string(
			writer, config_element_loglevel_type, loglevel_type_str);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}

		int level;
		if (rule_type == LTTNG_LOG_LEVEL_RULE_TYPE_EXACTLY) {
			lttng_log_level_rule_exactly_get_level(log_level_rule, &level);
		} else if (rule_type == LTTNG_LOG_LEVEL_RULE_TYPE_AT_LEAST_AS_SEVERE_AS) {
			lttng_log_level_rule_at_least_as_severe_as_get_level(log_level_rule,
									     &level);
		} else {
			level = -1;
		}

		if (rule_type != LTTNG_LOG_LEVEL_RULE_TYPE_UNKNOWN) {
			ret = config_writer_write_element_signed_int(
				writer, config_element_loglevel, level);
			if (ret) {
				ret = LTTNG_ERR_SAVE_IO_FAIL;
				goto end;
			}
		}
	} else {
		/* No log level rule means "ALL" */
		ret = config_writer_write_element_string(
			writer, config_element_loglevel_type, config_loglevel_type_all);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}
	}

	/* Filter */
	status = lttng_event_rule_user_tracepoint_get_filter(event_rule, &filter_expr);
	if (status == LTTNG_EVENT_RULE_STATUS_OK && filter_expr) {
		ret = config_writer_write_element_string(
			writer, config_element_filter, filter_expr);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}
	}

	/* Exclusions */
	status = lttng_event_rule_user_tracepoint_get_name_pattern_exclusion_count(
		event_rule, &exclusion_count);
	if (status == LTTNG_EVENT_RULE_STATUS_OK && exclusion_count > 0) {
		ret = config_writer_open_element(writer, config_element_exclusions);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}

		for (unsigned int i = 0; i < exclusion_count; i++) {
			const char *exclusion = nullptr;
			status =
				lttng_event_rule_user_tracepoint_get_name_pattern_exclusion_at_index(
					event_rule, i, &exclusion);
			if (status != LTTNG_EVENT_RULE_STATUS_OK) {
				continue;
			}

			ret = config_writer_write_element_string(
				writer, config_element_exclusion, exclusion);
			if (ret) {
				ret = LTTNG_ERR_SAVE_IO_FAIL;
				goto end;
			}
		}

		ret = config_writer_close_element(writer);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}
	}

	/* Close event element */
	ret = config_writer_close_element(writer);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = LTTNG_OK;
end:
	return ret;
}

/*
 * Helper function for agent logging event rules which share the same structure.
 *
 * This function handles the common logic for saving agent events (JUL, Log4j,
 * Log4j2, Python) that share identical configuration structures but have
 * their own domain-specific accessor functions.
 */
static int save_agent_logging_event_rule(
	config_writer *writer,
	const lttng_event_rule *event_rule,
	bool is_enabled,
	lttng_event_rule_status (*get_name_pattern)(const struct lttng_event_rule *, const char **),
	lttng_event_rule_status (*get_log_level_rule)(const struct lttng_event_rule *,
						      const struct lttng_log_level_rule **),
	lttng_event_rule_status (*get_filter)(const struct lttng_event_rule *, const char **))
{
	int ret;
	const char *pattern = nullptr;
	const char *filter_expr = nullptr;
	const lttng_log_level_rule *log_level_rule = nullptr;
	lttng_event_rule_status status;

	ret = config_writer_open_element(writer, config_element_event);
	if (ret) {
		return LTTNG_ERR_SAVE_IO_FAIL;
	}

	status = get_name_pattern(event_rule, &pattern);
	if (status == LTTNG_EVENT_RULE_STATUS_OK && pattern && pattern[0] != '\0') {
		ret = config_writer_write_element_string(writer, config_element_name, pattern);
		if (ret) {
			return LTTNG_ERR_SAVE_IO_FAIL;
		}
	}

	ret = config_writer_write_element_bool(writer, config_element_enabled, is_enabled);
	if (ret) {
		return LTTNG_ERR_SAVE_IO_FAIL;
	}

	ret = config_writer_write_element_string(
		writer, config_element_type, config_event_type_tracepoint);
	if (ret) {
		return LTTNG_ERR_SAVE_IO_FAIL;
	}

	status = get_log_level_rule(event_rule, &log_level_rule);
	if (status == LTTNG_EVENT_RULE_STATUS_OK && log_level_rule) {
		const auto rule_type = lttng_log_level_rule_get_type(log_level_rule);
		const char *loglevel_type_str = get_loglevel_type_string_from_rule_type(rule_type);

		ret = config_writer_write_element_string(
			writer, config_element_loglevel_type, loglevel_type_str);
		if (ret) {
			return LTTNG_ERR_SAVE_IO_FAIL;
		}

		int level = -1;
		if (rule_type == LTTNG_LOG_LEVEL_RULE_TYPE_EXACTLY) {
			lttng_log_level_rule_exactly_get_level(log_level_rule, &level);
		} else if (rule_type == LTTNG_LOG_LEVEL_RULE_TYPE_AT_LEAST_AS_SEVERE_AS) {
			lttng_log_level_rule_at_least_as_severe_as_get_level(log_level_rule,
									     &level);
		}

		if (rule_type != LTTNG_LOG_LEVEL_RULE_TYPE_UNKNOWN) {
			ret = config_writer_write_element_signed_int(
				writer, config_element_loglevel, level);
			if (ret) {
				return LTTNG_ERR_SAVE_IO_FAIL;
			}
		}
	} else {
		ret = config_writer_write_element_string(
			writer, config_element_loglevel_type, config_loglevel_type_all);
		if (ret) {
			return LTTNG_ERR_SAVE_IO_FAIL;
		}
	}

	status = get_filter(event_rule, &filter_expr);
	if (status == LTTNG_EVENT_RULE_STATUS_OK && filter_expr) {
		ret = config_writer_write_element_string(
			writer, config_element_filter, filter_expr);
		if (ret) {
			return LTTNG_ERR_SAVE_IO_FAIL;
		}
	}

	ret = config_writer_close_element(writer);
	if (ret) {
		return LTTNG_ERR_SAVE_IO_FAIL;
	}

	return LTTNG_OK;
}

int save_jul_logging_event_rule(config_writer *writer,
				const lttng_event_rule *event_rule,
				bool is_enabled)
{
	return save_agent_logging_event_rule(writer,
					     event_rule,
					     is_enabled,
					     lttng_event_rule_jul_logging_get_name_pattern,
					     lttng_event_rule_jul_logging_get_log_level_rule,
					     lttng_event_rule_jul_logging_get_filter);
}

int save_log4j_logging_event_rule(config_writer *writer,
				  const lttng_event_rule *event_rule,
				  bool is_enabled)
{
	return save_agent_logging_event_rule(writer,
					     event_rule,
					     is_enabled,
					     lttng_event_rule_log4j_logging_get_name_pattern,
					     lttng_event_rule_log4j_logging_get_log_level_rule,
					     lttng_event_rule_log4j_logging_get_filter);
}

int save_log4j2_logging_event_rule(config_writer *writer,
				   const lttng_event_rule *event_rule,
				   bool is_enabled)
{
	return save_agent_logging_event_rule(writer,
					     event_rule,
					     is_enabled,
					     lttng_event_rule_log4j2_logging_get_name_pattern,
					     lttng_event_rule_log4j2_logging_get_log_level_rule,
					     lttng_event_rule_log4j2_logging_get_filter);
}

int save_python_logging_event_rule(config_writer *writer,
				   const lttng_event_rule *event_rule,
				   bool is_enabled)
{
	return save_agent_logging_event_rule(writer,
					     event_rule,
					     is_enabled,
					     lttng_event_rule_python_logging_get_name_pattern,
					     lttng_event_rule_python_logging_get_log_level_rule,
					     lttng_event_rule_python_logging_get_filter);
}

/*
 * Save a kernel tracepoint event from an event rule.
 */
int save_kernel_tracepoint_event_rule(config_writer *writer,
				      const lttng_event_rule *event_rule,
				      bool is_enabled)
{
	int ret;
	const char *pattern = nullptr;
	const char *filter_expr = nullptr;
	lttng_event_rule_status status;

	ret = config_writer_open_element(writer, config_element_event);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	/* Name/pattern */
	status = lttng_event_rule_kernel_tracepoint_get_name_pattern(event_rule, &pattern);
	if (status == LTTNG_EVENT_RULE_STATUS_OK && pattern && pattern[0] != '\0') {
		ret = config_writer_write_element_string(writer, config_element_name, pattern);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}
	}

	/* Enabled */
	ret = config_writer_write_element_bool(writer, config_element_enabled, is_enabled);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	/* Type is TRACEPOINT */
	ret = config_writer_write_element_string(
		writer, config_element_type, config_event_type_tracepoint);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	/* Filter */
	status = lttng_event_rule_kernel_tracepoint_get_filter(event_rule, &filter_expr);
	if (status == LTTNG_EVENT_RULE_STATUS_OK && filter_expr) {
		ret = config_writer_write_element_string(
			writer, config_element_filter, filter_expr);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}
	}

	/* Close event element */
	ret = config_writer_close_element(writer);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = LTTNG_OK;
end:
	return ret;
}

/*
 * Save a kernel syscall event from an event rule.
 */
int save_kernel_syscall_event_rule(config_writer *writer,
				   const lttng_event_rule *event_rule,
				   bool is_enabled)
{
	int ret;
	const char *pattern = nullptr;
	const char *filter_expr = nullptr;
	lttng_event_rule_status status;

	ret = config_writer_open_element(writer, config_element_event);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	/* Name/pattern */
	status = lttng_event_rule_kernel_syscall_get_name_pattern(event_rule, &pattern);
	if (status == LTTNG_EVENT_RULE_STATUS_OK && pattern && pattern[0] != '\0') {
		ret = config_writer_write_element_string(writer, config_element_name, pattern);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}
	}

	/* Enabled */
	ret = config_writer_write_element_bool(writer, config_element_enabled, is_enabled);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	/* Type is SYSCALL */
	ret = config_writer_write_element_string(
		writer, config_element_type, config_event_type_syscall);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	/* Filter */
	status = lttng_event_rule_kernel_syscall_get_filter(event_rule, &filter_expr);
	if (status == LTTNG_EVENT_RULE_STATUS_OK && filter_expr) {
		ret = config_writer_write_element_string(
			writer, config_element_filter, filter_expr);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}
	}

	/* Close event element */
	ret = config_writer_close_element(writer);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = LTTNG_OK;
end:
	return ret;
}

/*
 * Save a kernel kprobe event from an event rule.
 */
int save_kernel_kprobe_event_rule(config_writer *writer,
				  const lttng_event_rule *event_rule,
				  bool is_enabled)
{
	int ret;
	const char *event_name = nullptr;
	const lttng_kernel_probe_location *location = nullptr;
	lttng_event_rule_status status;

	ret = config_writer_open_element(writer, config_element_event);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	/* Event name */
	status = lttng_event_rule_kernel_kprobe_get_event_name(event_rule, &event_name);
	if (status == LTTNG_EVENT_RULE_STATUS_OK && event_name && event_name[0] != '\0') {
		ret = config_writer_write_element_string(writer, config_element_name, event_name);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}
	}

	/* Enabled */
	ret = config_writer_write_element_bool(writer, config_element_enabled, is_enabled);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	/* Type is PROBE (kprobe) */
	ret = config_writer_write_element_string(
		writer, config_element_type, config_event_type_probe);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	/* Probe attributes */
	status = lttng_event_rule_kernel_kprobe_get_location(event_rule, &location);
	if (status == LTTNG_EVENT_RULE_STATUS_OK && location) {
		ret = config_writer_open_element(writer, config_element_attributes);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}

		ret = config_writer_open_element(writer, config_element_probe_attributes);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}

		const auto loc_type = lttng_kernel_probe_location_get_type(location);
		if (loc_type == LTTNG_KERNEL_PROBE_LOCATION_TYPE_ADDRESS) {
			std::uint64_t addr = 0;
			lttng_kernel_probe_location_address_get_address(location, &addr);
			ret = config_writer_write_element_unsigned_int(
				writer, config_element_address, addr);
			if (ret) {
				ret = LTTNG_ERR_SAVE_IO_FAIL;
				goto end;
			}
		} else if (loc_type == LTTNG_KERNEL_PROBE_LOCATION_TYPE_SYMBOL_OFFSET) {
			const char *symbol = lttng_kernel_probe_location_symbol_get_name(location);
			std::uint64_t offset = 0;
			lttng_kernel_probe_location_symbol_get_offset(location, &offset);

			if (symbol) {
				ret = config_writer_write_element_string(
					writer, config_element_symbol_name, symbol);
				if (ret) {
					ret = LTTNG_ERR_SAVE_IO_FAIL;
					goto end;
				}
			}
			if (offset != 0) {
				ret = config_writer_write_element_unsigned_int(
					writer, config_element_offset, offset);
				if (ret) {
					ret = LTTNG_ERR_SAVE_IO_FAIL;
					goto end;
				}
			}
		}

		/* Close probe_attributes */
		ret = config_writer_close_element(writer);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}

		/* Close attributes */
		ret = config_writer_close_element(writer);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}
	}

	/* Close event element */
	ret = config_writer_close_element(writer);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = LTTNG_OK;
end:
	return ret;
}

/*
 * Save a kernel uprobe event from an event rule.
 */
int save_kernel_uprobe_event_rule(config_writer *writer,
				  const lttng_event_rule *event_rule,
				  bool is_enabled)
{
	int ret;
	const char *event_name = nullptr;
	const lttng_userspace_probe_location *location = nullptr;
	lttng_event_rule_status status;

	ret = config_writer_open_element(writer, config_element_event);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	/* Event name */
	status = lttng_event_rule_kernel_uprobe_get_event_name(event_rule, &event_name);
	if (status == LTTNG_EVENT_RULE_STATUS_OK && event_name && event_name[0] != '\0') {
		ret = config_writer_write_element_string(writer, config_element_name, event_name);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}
	}

	/* Enabled */
	ret = config_writer_write_element_bool(writer, config_element_enabled, is_enabled);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	/* Type is USERSPACE_PROBE */
	ret = config_writer_write_element_string(
		writer, config_element_type, config_event_type_userspace_probe);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	/* Userspace probe attributes */
	status = lttng_event_rule_kernel_uprobe_get_location(event_rule, &location);
	if (status == LTTNG_EVENT_RULE_STATUS_OK && location) {
		const auto loc_type = lttng_userspace_probe_location_get_type(location);

		ret = config_writer_open_element(writer, config_element_attributes);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}

		if (loc_type == LTTNG_USERSPACE_PROBE_LOCATION_TYPE_FUNCTION) {
			const char *binary_path = nullptr;
			const char *function_name = nullptr;
			const auto *lookup_method =
				lttng_userspace_probe_location_get_lookup_method(location);
			const auto lookup_type =
				lttng_userspace_probe_location_lookup_method_get_type(
					lookup_method);

			binary_path =
				lttng_userspace_probe_location_function_get_binary_path(location);
			function_name =
				lttng_userspace_probe_location_function_get_function_name(location);

			ret = config_writer_open_element(
				writer, config_element_userspace_probe_function_attributes);
			if (ret) {
				ret = LTTNG_ERR_SAVE_IO_FAIL;
				goto end;
			}

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

			ret = config_writer_write_element_string(
				writer, config_element_userspace_probe_lookup, lookup_method_str);
			if (ret) {
				ret = LTTNG_ERR_SAVE_IO_FAIL;
				goto end;
			}

			if (binary_path) {
				ret = config_writer_write_element_string(
					writer,
					config_element_userspace_probe_location_binary_path,
					binary_path);
				if (ret) {
					ret = LTTNG_ERR_SAVE_IO_FAIL;
					goto end;
				}
			}

			if (function_name) {
				ret = config_writer_write_element_string(
					writer,
					config_element_userspace_probe_function_location_function_name,
					function_name);
				if (ret) {
					ret = LTTNG_ERR_SAVE_IO_FAIL;
					goto end;
				}
			}

			/* Close function attributes */
			ret = config_writer_close_element(writer);
			if (ret) {
				ret = LTTNG_ERR_SAVE_IO_FAIL;
				goto end;
			}
		} else if (loc_type == LTTNG_USERSPACE_PROBE_LOCATION_TYPE_TRACEPOINT) {
			const char *binary_path = nullptr;
			const char *probe_name = nullptr;
			const char *provider_name = nullptr;

			binary_path =
				lttng_userspace_probe_location_tracepoint_get_binary_path(location);
			probe_name =
				lttng_userspace_probe_location_tracepoint_get_probe_name(location);
			provider_name = lttng_userspace_probe_location_tracepoint_get_provider_name(
				location);

			ret = config_writer_open_element(
				writer, config_element_userspace_probe_tracepoint_attributes);
			if (ret) {
				ret = LTTNG_ERR_SAVE_IO_FAIL;
				goto end;
			}

			const char *lookup_method_str =
				config_element_userspace_probe_lookup_tracepoint_sdt;

			ret = config_writer_write_element_string(
				writer, config_element_userspace_probe_lookup, lookup_method_str);
			if (ret) {
				ret = LTTNG_ERR_SAVE_IO_FAIL;
				goto end;
			}

			if (binary_path) {
				ret = config_writer_write_element_string(
					writer,
					config_element_userspace_probe_location_binary_path,
					binary_path);
				if (ret) {
					ret = LTTNG_ERR_SAVE_IO_FAIL;
					goto end;
				}
			}

			if (provider_name) {
				ret = config_writer_write_element_string(
					writer,
					config_element_userspace_probe_tracepoint_location_provider_name,
					provider_name);
				if (ret) {
					ret = LTTNG_ERR_SAVE_IO_FAIL;
					goto end;
				}
			}

			if (probe_name) {
				ret = config_writer_write_element_string(
					writer,
					config_element_userspace_probe_tracepoint_location_probe_name,
					probe_name);
				if (ret) {
					ret = LTTNG_ERR_SAVE_IO_FAIL;
					goto end;
				}
			}

			/* Close tracepoint attributes */
			ret = config_writer_close_element(writer);
			if (ret) {
				ret = LTTNG_ERR_SAVE_IO_FAIL;
				goto end;
			}
		}

		/* Close attributes */
		ret = config_writer_close_element(writer);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}
	}

	/* Close event element */
	ret = config_writer_close_element(writer);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = LTTNG_OK;
end:
	return ret;
}

/*
 * Save a single event from an event_rule_configuration.
 */
int save_event_from_event_rule(config_writer *writer,
			       const ls::event_rule_configuration& event_config,
			       lttng::domain_class /* domain_class */)
{
	const auto *event_rule = event_config.event_rule.get();
	const auto event_rule_type = lttng_event_rule_get_type(event_rule);

	switch (event_rule_type) {
	case LTTNG_EVENT_RULE_TYPE_USER_TRACEPOINT:
		return save_user_tracepoint_event_rule(writer, event_rule, event_config.is_enabled);
	case LTTNG_EVENT_RULE_TYPE_JUL_LOGGING:
		return save_jul_logging_event_rule(writer, event_rule, event_config.is_enabled);
	case LTTNG_EVENT_RULE_TYPE_LOG4J_LOGGING:
		return save_log4j_logging_event_rule(writer, event_rule, event_config.is_enabled);
	case LTTNG_EVENT_RULE_TYPE_LOG4J2_LOGGING:
		return save_log4j2_logging_event_rule(writer, event_rule, event_config.is_enabled);
	case LTTNG_EVENT_RULE_TYPE_PYTHON_LOGGING:
		return save_python_logging_event_rule(writer, event_rule, event_config.is_enabled);
	case LTTNG_EVENT_RULE_TYPE_KERNEL_TRACEPOINT:
		return save_kernel_tracepoint_event_rule(
			writer, event_rule, event_config.is_enabled);
	case LTTNG_EVENT_RULE_TYPE_KERNEL_SYSCALL:
		return save_kernel_syscall_event_rule(writer, event_rule, event_config.is_enabled);
	case LTTNG_EVENT_RULE_TYPE_KERNEL_KPROBE:
		return save_kernel_kprobe_event_rule(writer, event_rule, event_config.is_enabled);
	case LTTNG_EVENT_RULE_TYPE_KERNEL_UPROBE:
		return save_kernel_uprobe_event_rule(writer, event_rule, event_config.is_enabled);
	default:
		ERR("Unsupported event rule type: %d", static_cast<int>(event_rule_type));
		return LTTNG_ERR_INVALID;
	}
}

/*
 * Save all events from a recording_channel_configuration.
 */
int save_events_from_config(config_writer *writer,
			    const ls::recording_channel_configuration& channel_config,
			    lttng::domain_class domain_class)
{
	int ret;

	ret = config_writer_open_element(writer, config_element_events);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	for (const auto& event_pair : channel_config.event_rules) {
		const auto& event_config = *event_pair.second;
		ret = save_event_from_event_rule(writer, event_config, domain_class);
		if (ret != LTTNG_OK) {
			goto end;
		}
	}

	/* Close events element */
	ret = config_writer_close_element(writer);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = LTTNG_OK;
end:
	return ret;
}

/*
 * Save a channel from a recording_channel_configuration.
 */
int save_channel_from_config(config_writer *writer,
			     const ls::recording_channel_configuration& channel_config,
			     lttng::domain_class domain_class,
			     std::uint64_t live_timer_interval)
{
	int ret;

	ret = config_writer_open_element(writer, config_element_channel);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	/* Channel name */
	ret = config_writer_write_element_string(
		writer, config_element_name, channel_config.name.c_str());
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	/* Enabled */
	ret = config_writer_write_element_bool(
		writer, config_element_enabled, channel_config.is_enabled);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	/* Channel attributes */
	ret = save_channel_attributes_from_config(writer, channel_config, domain_class);
	if (ret != LTTNG_OK) {
		goto end;
	}

	/* Tracefile size */
	ret = config_writer_write_element_unsigned_int(
		writer,
		config_element_tracefile_size,
		channel_config.trace_file_size_limit_bytes.value_or(0));
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	/* Tracefile count */
	ret = config_writer_write_element_unsigned_int(
		writer,
		config_element_tracefile_count,
		channel_config.trace_file_count_limit.value_or(0));
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	/* Live timer interval */
	ret = config_writer_write_element_unsigned_int(
		writer, config_element_live_timer_interval, live_timer_interval);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	/* Events */
	ret = save_events_from_config(writer, channel_config, domain_class);
	if (ret != LTTNG_OK) {
		goto end;
	}

	/* Contexts */
	ret = save_contexts_from_config(writer, channel_config);
	if (ret != LTTNG_OK) {
		goto end;
	}

	/* Close channel element */
	ret = config_writer_close_element(writer);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = LTTNG_OK;
end:
	return ret;
}

/*
 * Save a single process ID tracker (pid or vpid) from the new domain tracker types.
 *
 * Returns LTTNG_OK on success, or a LTTNG_ERR_* code on error.
 */
template <typename TrackerType>
int save_process_id_tracker_from_domain(config_writer *writer,
					const TrackerType& tracker,
					const char *element_id_tracker,
					const char *element_target_id)
{
	int ret;

	if (tracker.policy() == ls::tracking_policy::INCLUDE_ALL) {
		/* Tracking all is the default, nothing to save. */
		return LTTNG_OK;
	}

	ret = config_writer_open_element(writer, element_id_tracker);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = config_writer_open_element(writer, config_element_process_attr_values);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	if (tracker.policy() == ls::tracking_policy::INCLUDE_SET) {
		for (const auto& value : tracker.inclusion_set()) {
			ret = config_writer_open_element(writer, element_target_id);
			if (ret) {
				ret = LTTNG_ERR_SAVE_IO_FAIL;
				goto end;
			}

			ret = config_writer_write_element_unsigned_int(
				writer,
				config_element_process_attr_id,
				static_cast<unsigned int>(value));
			if (ret) {
				ret = LTTNG_ERR_SAVE_IO_FAIL;
				goto end;
			}

			/* Close target_id element. */
			ret = config_writer_close_element(writer);
			if (ret) {
				ret = LTTNG_ERR_SAVE_IO_FAIL;
				goto end;
			}
		}
	}
	/* For EXCLUDE_ALL, we write an empty values element. */

	/* Close values element. */
	ret = config_writer_close_element(writer);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	/* Close tracker element. */
	ret = config_writer_close_element(writer);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = LTTNG_OK;
end:
	return ret;
}

/*
 * Save a UID/GID tracker (uid, vuid, gid, vgid) from the new domain tracker types.
 *
 * These trackers store resolved_process_attr_value which can have both a numeric ID
 * and an optional original name. We prefer to save the name if available.
 *
 * Returns LTTNG_OK on success, or a LTTNG_ERR_* code on error.
 */
template <typename TrackerType>
int save_resolved_id_tracker_from_domain(config_writer *writer,
					 const TrackerType& tracker,
					 const char *element_id_tracker,
					 const char *element_target_id)
{
	int ret;

	if (tracker.policy() == ls::tracking_policy::INCLUDE_ALL) {
		/* Tracking all is the default, nothing to save. */
		return LTTNG_OK;
	}

	ret = config_writer_open_element(writer, element_id_tracker);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = config_writer_open_element(writer, config_element_process_attr_values);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	if (tracker.policy() == ls::tracking_policy::INCLUDE_SET) {
		for (const auto& value : tracker.inclusion_set()) {
			ret = config_writer_open_element(writer, element_target_id);
			if (ret) {
				ret = LTTNG_ERR_SAVE_IO_FAIL;
				goto end;
			}

			if (value.has_name()) {
				ret = config_writer_write_element_string(
					writer, config_element_name, value.name().c_str());
			} else {
				ret = config_writer_write_element_unsigned_int(
					writer,
					config_element_process_attr_id,
					static_cast<unsigned int>(value.id()));
			}
			if (ret) {
				ret = LTTNG_ERR_SAVE_IO_FAIL;
				goto end;
			}

			/* Close target_id element. */
			ret = config_writer_close_element(writer);
			if (ret) {
				ret = LTTNG_ERR_SAVE_IO_FAIL;
				goto end;
			}
		}
	}
	/* For EXCLUDE_ALL, we write an empty values element. */

	/* Close values element. */
	ret = config_writer_close_element(writer);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	/* Close tracker element. */
	ret = config_writer_close_element(writer);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = LTTNG_OK;
end:
	return ret;
}

/*
 * Save all process attribute trackers from a domain.
 *
 * This function saves trackers from the new lttng::sessiond::domain structure.
 * The available trackers depend on the domain type:
 * - Kernel: pid, vpid, uid, vuid, gid, vgid
 * - User space: vpid, vuid, vgid
 *
 * Returns LTTNG_OK on success, or a LTTNG_ERR_* code on error.
 */
int save_process_attr_trackers_from_domain(config_writer *writer, const ls::domain& domain)
{
	int ret;

	ret = config_writer_open_element(writer, config_element_process_attr_trackers);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	if (domain.domain_class_ == lttng::domain_class::KERNEL_SPACE) {
		/* Kernel domain: save all 6 trackers. */
		ret = save_process_id_tracker_from_domain(writer,
							  domain.process_id_tracker(),
							  config_element_process_attr_tracker_pid,
							  config_element_process_attr_pid_value);
		if (ret != LTTNG_OK) {
			goto end;
		}

		ret = save_process_id_tracker_from_domain(writer,
							  domain.virtual_process_id_tracker(),
							  config_element_process_attr_tracker_vpid,
							  config_element_process_attr_vpid_value);
		if (ret != LTTNG_OK) {
			goto end;
		}

		ret = save_resolved_id_tracker_from_domain(writer,
							   domain.user_id_tracker(),
							   config_element_process_attr_tracker_uid,
							   config_element_process_attr_uid_value);
		if (ret != LTTNG_OK) {
			goto end;
		}

		ret = save_resolved_id_tracker_from_domain(writer,
							   domain.virtual_user_id_tracker(),
							   config_element_process_attr_tracker_vuid,
							   config_element_process_attr_vuid_value);
		if (ret != LTTNG_OK) {
			goto end;
		}

		ret = save_resolved_id_tracker_from_domain(writer,
							   domain.group_id_tracker(),
							   config_element_process_attr_tracker_gid,
							   config_element_process_attr_gid_value);
		if (ret != LTTNG_OK) {
			goto end;
		}

		ret = save_resolved_id_tracker_from_domain(writer,
							   domain.virtual_group_id_tracker(),
							   config_element_process_attr_tracker_vgid,
							   config_element_process_attr_vgid_value);
		if (ret != LTTNG_OK) {
			goto end;
		}
	} else if (domain.domain_class_ == lttng::domain_class::USER_SPACE) {
		/* UST domain: save 3 virtual trackers. */
		ret = save_process_id_tracker_from_domain(writer,
							  domain.virtual_process_id_tracker(),
							  config_element_process_attr_tracker_vpid,
							  config_element_process_attr_vpid_value);
		if (ret != LTTNG_OK) {
			goto end;
		}

		ret = save_resolved_id_tracker_from_domain(writer,
							   domain.virtual_user_id_tracker(),
							   config_element_process_attr_tracker_vuid,
							   config_element_process_attr_vuid_value);
		if (ret != LTTNG_OK) {
			goto end;
		}

		ret = save_resolved_id_tracker_from_domain(writer,
							   domain.virtual_group_id_tracker(),
							   config_element_process_attr_tracker_vgid,
							   config_element_process_attr_vgid_value);
		if (ret != LTTNG_OK) {
			goto end;
		}
	}
	/* Agent domains don't have process attribute trackers. */

	/* Close process_attr_trackers element. */
	ret = config_writer_close_element(writer);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = LTTNG_OK;
end:
	return ret;
}

/*
 * Get buffer type string for a domain.
 *
 * For kernel, it's always "GLOBAL".
 * For UST, we need to check the ownership model from the first channel in the domain.
 */
const char *get_buffer_type_string_for_domain(const ls::domain& domain, const ltt_session& session)
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
 * Save a domain from an lttng::sessiond::domain using the new configuration types.
 */
int save_domain_from_config(config_writer *writer,
			    const ls::domain& domain,
			    const ltt_session& session,
			    std::uint64_t live_timer_interval)
{
	int ret;
	const char *domain_type_str = nullptr;
	const char *buffer_type_str = nullptr;

	ret = config_writer_open_element(writer, config_element_domain);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	/* Domain type */
	domain_type_str = get_domain_type_config_string(domain.domain_class_);
	if (!domain_type_str) {
		ret = LTTNG_ERR_INVALID;
		goto end;
	}

	ret = config_writer_write_element_string(writer, config_element_type, domain_type_str);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	/* Buffer type */
	buffer_type_str = get_buffer_type_string_for_domain(domain, session);
	if (!buffer_type_str) {
		ret = LTTNG_ERR_INVALID;
		goto end;
	}

	ret = config_writer_write_element_string(
		writer, config_element_buffer_type, buffer_type_str);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	/* Channels */
	ret = config_writer_open_element(writer, config_element_channels);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	for (const auto& channel_config : domain.recording_channels()) {
		if (is_internal_channel(channel_config.name)) {
			/* Skip internal agent channels. */
			continue;
		}

		ret = save_channel_from_config(
			writer, channel_config, domain.domain_class_, live_timer_interval);
		if (ret != LTTNG_OK) {
			goto end;
		}
	}

	/* Close channels element */
	ret = config_writer_close_element(writer);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = save_process_attr_trackers_from_domain(writer, domain);
	if (ret != LTTNG_OK) {
		goto end;
	}

	/* Close domain element */
	ret = config_writer_close_element(writer);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = LTTNG_OK;
end:
	return ret;
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
int save_events_from_agent_domain(config_writer *writer, const ls::agent_domain& agent_domain)
{
	int ret;

	ret = config_writer_open_element(writer, config_element_events);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	for (const auto& event_config : agent_domain.event_rules()) {
		ret = save_event_from_event_rule(writer, event_config, agent_domain.domain_class_);
		if (ret != LTTNG_OK) {
			goto end;
		}
	}

	/* Close events element */
	ret = config_writer_close_element(writer);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = LTTNG_OK;
end:
	return ret;
}

/*
 * Get the default channel from user_space_domain for the given agent domain.
 * Returns nullptr if the channel is not found.
 */
const ls::recording_channel_configuration *
get_agent_domain_default_channel(const ls::domain& user_space_domain,
				 lttng::domain_class agent_domain_class)
{
	const char *channel_name = get_agent_domain_default_channel_name(agent_domain_class);
	try {
		return &user_space_domain.get_channel(channel_name);
	} catch (const ls::exceptions::channel_not_found_error&) {
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
int save_agent_channel_from_config(config_writer *writer,
				   const ls::recording_channel_configuration& channel_config,
				   const ls::agent_domain& agent_domain,
				   std::uint64_t live_timer_interval)
{
	int ret;

	ret = config_writer_open_element(writer, config_element_channel);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	/* Channel name */
	ret = config_writer_write_element_string(
		writer, config_element_name, channel_config.name.c_str());
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	/* Enabled */
	ret = config_writer_write_element_bool(
		writer, config_element_enabled, channel_config.is_enabled);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	/* Channel attributes */
	ret = save_channel_attributes_from_config(
		writer, channel_config, agent_domain.domain_class_);
	if (ret != LTTNG_OK) {
		goto end;
	}

	/* Tracefile size */
	ret = config_writer_write_element_unsigned_int(
		writer,
		config_element_tracefile_size,
		channel_config.trace_file_size_limit_bytes.value_or(0));
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	/* Tracefile count */
	ret = config_writer_write_element_unsigned_int(
		writer,
		config_element_tracefile_count,
		channel_config.trace_file_count_limit.value_or(0));
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	/* Live timer interval */
	ret = config_writer_write_element_unsigned_int(
		writer, config_element_live_timer_interval, live_timer_interval);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	/* Events from agent domain (not from channel config) */
	ret = save_events_from_agent_domain(writer, agent_domain);
	if (ret != LTTNG_OK) {
		goto end;
	}

	/* Contexts from channel config */
	ret = save_contexts_from_config(writer, channel_config);
	if (ret != LTTNG_OK) {
		goto end;
	}

	/* Close channel element */
	ret = config_writer_close_element(writer);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = LTTNG_OK;
end:
	return ret;
}

/*
 * Save an agent domain from an lttng::sessiond::agent_domain.
 *
 * Agent domains (JUL, Log4j, Log4j2, Python) are saved as domains with a single
 * channel. The channel attributes come from the underlying UST channel in the
 * user_space_domain, while the event rules come from the agent_domain itself.
 */
int save_agent_domain_from_config(config_writer *writer,
				  const ls::agent_domain& agent_domain,
				  const ls::recording_channel_configuration *default_channel,
				  const ltt_session& session,
				  std::uint64_t live_timer_interval)
{
	int ret;
	const char *domain_type_str = nullptr;
	const char *buffer_type_str = nullptr;

	ret = config_writer_open_element(writer, config_element_domain);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	/* Domain type */
	domain_type_str = get_domain_type_config_string(agent_domain.domain_class_);
	if (!domain_type_str) {
		ret = LTTNG_ERR_INVALID;
		goto end;
	}

	ret = config_writer_write_element_string(writer, config_element_type, domain_type_str);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	/* Buffer type - get from ust_session */
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

	ret = config_writer_write_element_string(
		writer, config_element_buffer_type, buffer_type_str);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	/* Channels */
	ret = config_writer_open_element(writer, config_element_channels);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	/*
	 * Save the agent channel if it exists in user_space_domain.
	 * If it doesn't exist, we save an empty channels element.
	 */
	if (default_channel) {
		ret = save_agent_channel_from_config(
			writer, *default_channel, agent_domain, live_timer_interval);
		if (ret != LTTNG_OK) {
			goto end;
		}
	}

	/* Close channels element */
	ret = config_writer_close_element(writer);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	/* Close domain element */
	ret = config_writer_close_element(writer);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = LTTNG_OK;
end:
	return ret;
}

} /* anonymous namespace */

/* Return LTTNG_OK on success else a LTTNG_ERR* code. */
static int save_domains(struct config_writer *writer, const ltt_session::locked_ref& session)
{
	int ret = LTTNG_OK;

	LTTNG_ASSERT(writer);

	if (!session->kernel_session && !session->ust_session) {
		goto end;
	}

	ret = config_writer_open_element(writer, config_element_domains);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	if (session->kernel_session) {
		const std::uint64_t live_timer_interval = session->live_timer;

		ret = save_domain_from_config(
			writer, session->kernel_space_domain, *session, live_timer_interval);
		if (ret != LTTNG_OK) {
			goto end;
		}
	}

	if (session->ust_session) {
		const std::uint64_t live_timer_interval = session->live_timer;

		ret = save_domain_from_config(
			writer, session->user_space_domain, *session, live_timer_interval);
		if (ret != LTTNG_OK) {
			goto end;
		}

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

		ret = save_agent_domain_from_config(
			writer, session->jul_domain, jul_channel, *session, live_timer_interval);
		if (ret != LTTNG_OK) {
			goto end;
		}

		ret = save_agent_domain_from_config(writer,
						    session->log4j_domain,
						    log4j_channel,
						    *session,
						    live_timer_interval);
		if (ret != LTTNG_OK) {
			goto end;
		}

		ret = save_agent_domain_from_config(writer,
						    session->log4j2_domain,
						    log4j2_channel,
						    *session,
						    live_timer_interval);
		if (ret != LTTNG_OK) {
			goto end;
		}

		ret = save_agent_domain_from_config(writer,
						    session->python_domain,
						    python_channel,
						    *session,
						    live_timer_interval);
		if (ret != LTTNG_OK) {
			goto end;
		}
	}

	/* /domains */
	ret = config_writer_close_element(writer);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = LTTNG_OK;
end:
	return ret;
}

/* Return LTTNG_OK on success else a LTTNG_ERR* code. */
static int save_consumer_output(struct config_writer *writer, struct consumer_output *output)
{
	int ret;

	LTTNG_ASSERT(writer);
	LTTNG_ASSERT(output);

	ret = config_writer_open_element(writer, config_element_consumer_output);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = config_writer_write_element_bool(writer, config_element_enabled, output->enabled);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = config_writer_open_element(writer, config_element_destination);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	switch (output->type) {
	case CONSUMER_DST_LOCAL:
		ret = config_writer_write_element_string(
			writer, config_element_path, output->dst.session_root_path);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}
		break;
	case CONSUMER_DST_NET:
	{
		char *uri;

		uri = calloc<char>(PATH_MAX);
		if (!uri) {
			ret = LTTNG_ERR_NOMEM;
			goto end;
		}

		ret = config_writer_open_element(writer, config_element_net_output);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end_net_output;
		}

		if (output->dst.net.control_isset && output->dst.net.data_isset) {
			ret = uri_to_str_url(&output->dst.net.control, uri, PATH_MAX);
			if (ret < 0) {
				ret = LTTNG_ERR_INVALID;
				goto end_net_output;
			}

			ret = config_writer_write_element_string(
				writer, config_element_control_uri, uri);
			if (ret) {
				ret = LTTNG_ERR_SAVE_IO_FAIL;
				goto end_net_output;
			}

			ret = uri_to_str_url(&output->dst.net.data, uri, PATH_MAX);
			if (ret < 0) {
				ret = LTTNG_ERR_INVALID;
				goto end_net_output;
			}

			ret = config_writer_write_element_string(
				writer, config_element_data_uri, uri);
			if (ret) {
				ret = LTTNG_ERR_SAVE_IO_FAIL;
				goto end_net_output;
			}
			ret = LTTNG_OK;
		end_net_output:
			free(uri);
			if (ret != LTTNG_OK) {
				goto end;
			}
		} else {
			ret = !output->dst.net.control_isset ? LTTNG_ERR_URL_CTRL_MISS :
							       LTTNG_ERR_URL_DATA_MISS;
			free(uri);
			goto end;
		}

		ret = config_writer_close_element(writer);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}
		break;
	}
	default:
		ERR("Unsupported consumer output type.");
		ret = LTTNG_ERR_INVALID;
		goto end;
	}

	/* /destination */
	ret = config_writer_close_element(writer);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	/* /consumer_output */
	ret = config_writer_close_element(writer);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = LTTNG_OK;
end:
	return ret;
}

/* Return LTTNG_OK on success else a LTTNG_ERR* code. */
static int save_snapshot_outputs(struct config_writer *writer, struct snapshot *snapshot)
{
	LTTNG_ASSERT(writer);
	LTTNG_ASSERT(snapshot);

	int ret = config_writer_open_element(writer, config_element_snapshot_outputs);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	for (auto *output : lttng::urcu::lfht_iteration_adapter<snapshot_output,
								decltype(snapshot_output::node),
								&snapshot_output::node>(
		     *snapshot->output_ht->ht)) {
		ret = config_writer_open_element(writer, config_element_output);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end_unlock;
		}

		ret = config_writer_write_element_string(writer, config_element_name, output->name);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end_unlock;
		}

		ret = config_writer_write_element_unsigned_int(
			writer, config_element_max_size, output->max_size);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end_unlock;
		}

		ret = save_consumer_output(writer, output->consumer);
		if (ret != LTTNG_OK) {
			goto end_unlock;
		}

		/* /output */
		ret = config_writer_close_element(writer);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end_unlock;
		}
	}

	/* /snapshot_outputs */
	ret = config_writer_close_element(writer);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = LTTNG_OK;
end:
	return ret;
end_unlock:
	return ret;
}

/* Return LTTNG_OK on success else a LTTNG_ERR* code. */
static int save_session_output(struct config_writer *writer, const ltt_session::locked_ref& session)
{
	int ret;

	LTTNG_ASSERT(writer);

	if ((session->snapshot_mode && session->snapshot.nb_output == 0) ||
	    (!session->snapshot_mode && !session->consumer)) {
		/* Session is in no output mode */
		ret = LTTNG_OK;
		goto end;
	}

	ret = config_writer_open_element(writer, config_element_output);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	if (session->snapshot_mode) {
		ret = save_snapshot_outputs(writer, &session->snapshot);
		if (ret != LTTNG_OK) {
			goto end;
		}
	} else {
		if (session->consumer) {
			ret = save_consumer_output(writer, session->consumer);
			if (ret != LTTNG_OK) {
				goto end;
			}
		}
	}

	/* /output */
	ret = config_writer_close_element(writer);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}
	ret = LTTNG_OK;
end:
	return ret;
}

static int save_session_rotation_schedule(struct config_writer *writer,
					  enum lttng_rotation_schedule_type type,
					  uint64_t value)
{
	int ret = 0;
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
		ret = -1;
		goto end;
	}

	ret = config_writer_open_element(writer, element_name);
	if (ret) {
		goto end;
	}

	ret = config_writer_write_element_unsigned_int(writer, value_name, value);
	if (ret) {
		goto end;
	}

	/* Close schedule descriptor element. */
	ret = config_writer_close_element(writer);
	if (ret) {
		goto end;
	}
end:
	return ret;
}

static int save_session_rotation_schedules(struct config_writer *writer,
					   const ltt_session::locked_ref& session)
{
	int ret;

	ret = config_writer_open_element(writer, config_element_rotation_schedules);
	if (ret) {
		goto end;
	}
	if (session->rotate_timer_period) {
		ret = save_session_rotation_schedule(writer,
						     LTTNG_ROTATION_SCHEDULE_TYPE_PERIODIC,
						     session->rotate_timer_period);
		if (ret) {
			goto close_schedules;
		}
	}
	if (session->rotate_size) {
		ret = save_session_rotation_schedule(
			writer, LTTNG_ROTATION_SCHEDULE_TYPE_SIZE_THRESHOLD, session->rotate_size);
		if (ret) {
			goto close_schedules;
		}
	}

close_schedules:
	/* Close rotation schedules element. */
	ret = config_writer_close_element(writer);
	if (ret) {
		goto end;
	}
end:
	return ret;
}

/*
 * Save the given session.
 *
 * Return LTTNG_OK on success else a LTTNG_ERR* code.
 */
static int save_session(const ltt_session::locked_ref& session,
			struct lttng_save_session_attr *attr,
			lttng_sock_cred *creds)
{
	int ret, fd = -1;
	char config_file_path[LTTNG_PATH_MAX];
	size_t len;
	struct config_writer *writer = nullptr;
	size_t session_name_len;
	const char *provided_path;
	int file_open_flags = O_CREAT | O_WRONLY | O_TRUNC;

	LTTNG_ASSERT(attr);
	LTTNG_ASSERT(creds);

	session_name_len = strlen(session->name);
	memset(config_file_path, 0, sizeof(config_file_path));

	if (!session_access_ok(session, LTTNG_SOCK_GET_UID_CRED(creds)) || session->destroyed) {
		ret = LTTNG_ERR_EPERM;
		goto end;
	}

	provided_path = lttng_save_session_attr_get_output_url(attr);
	if (provided_path) {
		DBG3("Save session in provided path %s", provided_path);
		len = strlen(provided_path);
		if (len >= sizeof(config_file_path)) {
			ret = LTTNG_ERR_SET_URL;
			goto end;
		}
		strncpy(config_file_path, provided_path, sizeof(config_file_path));
	} else {
		ssize_t ret_len;
		char *home_dir = utils_get_user_home_dir(LTTNG_SOCK_GET_UID_CRED(creds));
		if (!home_dir) {
			ret = LTTNG_ERR_SET_URL;
			goto end;
		}

		ret_len = snprintf(config_file_path,
				   sizeof(config_file_path),
				   DEFAULT_SESSION_HOME_CONFIGPATH,
				   home_dir);
		free(home_dir);
		if (ret_len < 0) {
			PERROR("snprintf save session");
			ret = LTTNG_ERR_SET_URL;
			goto end;
		}
		len = ret_len;
	}

	/*
	 * Check the path fits in the config file path dst including the '/'
	 * followed by trailing .lttng extension and the NULL terminated string.
	 */
	if ((len + session_name_len + 2 + sizeof(DEFAULT_SESSION_CONFIG_FILE_EXTENSION)) >
	    sizeof(config_file_path)) {
		ret = LTTNG_ERR_SET_URL;
		goto end;
	}

	ret = run_as_mkdir_recursive(config_file_path,
				     S_IRWXU | S_IRWXG,
				     LTTNG_SOCK_GET_UID_CRED(creds),
				     LTTNG_SOCK_GET_GID_CRED(creds));
	if (ret) {
		ret = LTTNG_ERR_SET_URL;
		goto end;
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

	fd = run_as_open(config_file_path,
			 file_open_flags,
			 S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP,
			 LTTNG_SOCK_GET_UID_CRED(creds),
			 LTTNG_SOCK_GET_GID_CRED(creds));
	if (fd < 0) {
		PERROR("Could not create configuration file");
		switch (errno) {
		case EEXIST:
			ret = LTTNG_ERR_SAVE_FILE_EXIST;
			break;
		case EACCES:
			ret = LTTNG_ERR_EPERM;
			break;
		default:
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			break;
		}
		goto end;
	}

	writer = config_writer_create(fd, 1);
	if (!writer) {
		ret = LTTNG_ERR_NOMEM;
		goto end;
	}

	ret = config_writer_open_element(writer, config_element_sessions);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = config_writer_open_element(writer, config_element_session);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = config_writer_write_element_string(writer, config_element_name, session->name);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	if (session->shm_path[0] != '\0') {
		ret = config_writer_write_element_string(
			writer, config_element_shared_memory_path, session->shm_path);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}
	}

	ret = config_writer_write_element_string(writer,
						 config_element_trace_format,
						 session->trace_format ==
								 LTTNG_TRACE_FORMAT_CTF_1_8 ?
							 config_element_trace_format_ctf_1_8 :
							 config_element_trace_format_ctf_2);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = save_domains(writer, session);
	if (ret != LTTNG_OK) {
		goto end;
	}

	ret = config_writer_write_element_bool(writer, config_element_started, session->active);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	if (session->snapshot_mode || session->live_timer || session->rotate_timer_period ||
	    session->rotate_size) {
		ret = config_writer_open_element(writer, config_element_attributes);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}

		if (session->snapshot_mode) {
			ret = config_writer_write_element_bool(
				writer, config_element_snapshot_mode, 1);
			if (ret) {
				ret = LTTNG_ERR_SAVE_IO_FAIL;
				goto end;
			}
		} else if (session->live_timer) {
			ret = config_writer_write_element_unsigned_int(
				writer, config_element_live_timer_interval, session->live_timer);
			if (ret) {
				ret = LTTNG_ERR_SAVE_IO_FAIL;
				goto end;
			}
		}
		if (session->rotate_timer_period || session->rotate_size) {
			ret = save_session_rotation_schedules(writer, session);
			if (ret) {
				ret = LTTNG_ERR_SAVE_IO_FAIL;
				goto end;
			}
		}

		/* /attributes */
		ret = config_writer_close_element(writer);
		if (ret) {
			ret = LTTNG_ERR_SAVE_IO_FAIL;
			goto end;
		}
	}

	ret = save_session_output(writer, session);
	if (ret != LTTNG_OK) {
		goto end;
	}

	/* /session */
	ret = config_writer_close_element(writer);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	/* /sessions */
	ret = config_writer_close_element(writer);
	if (ret) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	ret = LTTNG_OK;
end:
	if (writer && config_writer_destroy(writer)) {
		/* Preserve the original error code */
		ret = ret != LTTNG_OK ? ret : LTTNG_ERR_SAVE_IO_FAIL;
	}
	if (ret != LTTNG_OK) {
		/* Delete file in case of error */
		if ((fd >= 0) && unlink(config_file_path)) {
			PERROR("Unlinking XML session configuration.");
		}
	}

	if (fd >= 0) {
		int closeret;

		closeret = close(fd);
		if (closeret) {
			PERROR("Closing XML session configuration");
		}
	}

	return ret;
}

int cmd_save_sessions(struct lttng_save_session_attr *attr, lttng_sock_cred *creds)
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
		struct ltt_session_list *list = session_get_list();

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
