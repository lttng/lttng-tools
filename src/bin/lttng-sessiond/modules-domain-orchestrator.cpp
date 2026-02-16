/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "channel.hpp"
#include "cmd.hpp"
#include "consumer.hpp"
#include "context.hpp"
#include "event.hpp"
#include "kernel-consumer.hpp"
#include "kernel.hpp"
#include "lttng-sessiond.hpp"
#include "modules-domain-orchestrator.hpp"
#include "process-attribute-tracker.hpp"
#include "trace-kernel.hpp"

#include <common/ctl/memory.hpp>
#include <common/error.hpp>
#include <common/exception.hpp>
#include <common/kernel-ctl/kernel-ctl.hpp>
#include <common/macros.hpp>
#include <common/make-unique-wrapper.hpp>
#include <common/tracker.hpp>
#include <common/urcu.hpp>

#include <lttng/channel-internal.hpp>
#include <lttng/channel.h>
#include <lttng/event-internal.hpp>
#include <lttng/event-rule/event-rule-internal.hpp>
#include <lttng/lttng-error.h>

#include <inttypes.h>

namespace ls = lttng::sessiond;
namespace lsc = lttng::sessiond::config;

/*
 * The modules domain orchestrator is temporarily a thin delegation layer. Each method delegates to
 * the existing kernel_*, channel_kernel_*, event_kernel_*, and context_kernel_* functions which
 * operate on the legacy ltt_kernel_session / ltt_kernel_channel / ltt_kernel_event objects.
 *
 * The _channels and _metadata maps declared in the header are unused for the moment.
 * The existing legacy objects remain the authoritative runtime state.
 */

namespace {
/*
 * Find the legacy kernel channel matching a config object by name.
 * Throws channel_not_found_error if no match exists.
 */
ltt_kernel_channel& find_legacy_channel(ltt_kernel_session& ksess,
					const lsc::recording_channel_configuration& channel_config)
{
	auto *kchan = trace_kernel_get_channel_by_name(channel_config.name.c_str(), &ksess);

	if (!kchan) {
		LTTNG_THROW_CHANNEL_NOT_FOUND_BY_NAME_ERROR(channel_config.name);
	}

	return *kchan;
}

/*
 * Build a legacy lttng_channel from a recording_channel_configuration.
 *
 * This conversion is a temporary bridge used during the refactor.
 */
lttng::ctl::lttng_channel_uptr
make_lttng_channel_from_config(const lsc::recording_channel_configuration& channel_config)
{
	auto attr = lttng::make_unique_wrapper<lttng_channel, lttng_channel_destroy>(
		lttng_channel_create_internal());
	if (!attr) {
		LTTNG_THROW_POSIX("Failed to allocate lttng_channel", ENOMEM);
	}

	if (lttng_strncpy(attr->name, channel_config.name.c_str(), sizeof(attr->name))) {
		LTTNG_THROW_INVALID_ARGUMENT_ERROR("Channel name too long");
	}

	attr->attr.overwrite = channel_config.buffer_full_policy ==
			lsc::channel_configuration::buffer_full_policy_t::OVERWRITE_OLDEST_PACKET ?
		1 :
		0;
	attr->attr.subbuf_size = channel_config.subbuffer_size_bytes;
	attr->attr.num_subbuf = channel_config.subbuffer_count;
	attr->attr.switch_timer_interval = channel_config.switch_timer_period_us.value_or(0);
	attr->attr.read_timer_interval = channel_config.read_timer_period_us.value_or(0);
	attr->attr.output = channel_config.buffer_consumption_backend ==
			lsc::channel_configuration::buffer_consumption_backend_t::MMAP ?
		LTTNG_EVENT_MMAP :
		LTTNG_EVENT_SPLICE;

	if (channel_config.live_timer_period_us) {
		attr->attr.live_timer_interval = *channel_config.live_timer_period_us;
	}

	if (channel_config.monitor_timer_period_us) {
		lttng_channel_set_monitor_timer_interval(attr.get(),
							 *channel_config.monitor_timer_period_us);
	}

	if (channel_config.trace_file_size_limit_bytes) {
		attr->attr.tracefile_size = *channel_config.trace_file_size_limit_bytes;
	}

	if (channel_config.trace_file_count_limit) {
		attr->attr.tracefile_count = *channel_config.trace_file_count_limit;
	}

	return attr;
}
} /* namespace */

void ls::modules::domain_orchestrator::create_channel(
	const lsc::recording_channel_configuration& channel_config)
{
	LTTNG_ASSERT(_legacy_kernel_session);

	auto attr = make_lttng_channel_from_config(channel_config);

	/* Enforce mmap output for snapshot sessions. */
	if (_legacy_kernel_session->snapshot_mode) {
		attr->attr.output = LTTNG_EVENT_MMAP;
	}

	const auto ret_code =
		channel_kernel_create(_legacy_kernel_session, attr.get(), _kernel_pipe);
	if (ret_code != LTTNG_OK) {
		LTTNG_THROW_CTL("Failed to create kernel channel", ret_code);
	}

	if (channel_config.name != DEFAULT_CHANNEL_NAME) {
		_legacy_kernel_session->has_non_default_channel = 1;
	}

	kernel_wait_quiescent();
}

void ls::modules::domain_orchestrator::enable_channel(
	const lsc::recording_channel_configuration& channel_config)
{
	LTTNG_ASSERT(_legacy_kernel_session);

	auto& kchan = find_legacy_channel(*_legacy_kernel_session, channel_config);
	const auto ret_code = channel_kernel_enable(_legacy_kernel_session, &kchan);

	if (ret_code != LTTNG_OK) {
		LTTNG_THROW_CTL("Failed to enable kernel channel", ret_code);
	}

	kernel_wait_quiescent();
}

void ls::modules::domain_orchestrator::disable_channel(
	const lsc::recording_channel_configuration& channel_config)
{
	LTTNG_ASSERT(_legacy_kernel_session);

	const auto ret = channel_kernel_disable(_legacy_kernel_session,
						const_cast<char *>(channel_config.name.c_str()));

	if (ret != LTTNG_OK) {
		LTTNG_THROW_CTL("Failed to disable kernel channel",
				static_cast<lttng_error_code>(ret));
	}

	kernel_wait_quiescent();
}

namespace {
/*
 * Duplicate filter expression and bytecode from an event rule.
 *
 * event_kernel_enable_event() takes ownership of both, so we must
 * duplicate them from the rule which retains its own copies.
 */
struct duplicated_filter {
	char *expression;
	struct lttng_bytecode *bytecode;
};

duplicated_filter duplicate_filter_from_rule(const struct lttng_event_rule *rule)
{
	duplicated_filter result = { nullptr, nullptr };

	const auto *filter_expression = lttng_event_rule_get_filter_expression(rule);
	if (filter_expression) {
		result.expression = strdup(filter_expression);
		if (!result.expression) {
			LTTNG_THROW_POSIX("Failed to duplicate filter expression", errno);
		}
	}

	const auto *bytecode = lttng_event_rule_get_filter_bytecode(rule);
	if (bytecode) {
		const auto bytecode_size = sizeof(*bytecode) + bytecode->len;

		result.bytecode = zmalloc<lttng_bytecode>(bytecode_size);
		if (!result.bytecode) {
			free(result.expression);
			LTTNG_THROW_POSIX("Failed to duplicate filter bytecode", errno);
		}

		memcpy(result.bytecode, bytecode, bytecode_size);
	}

	return result;
}

/*
 * Build a legacy lttng_event_context from a context_configuration.
 *
 * This is the reverse of make_context_configuration_from_event_context() and
 * is a temporary bridge used during the refactor so that the orchestrator's
 * add_context() can delegate to context_kernel_add().
 *
 * It will be eliminated when context_kernel_add() is changed to accept a
 * context_configuration directly.
 */
lttng_event_context make_lttng_event_context_from_context_configuration(
	const lsc::context_configuration& context_config)
{
	struct lttng_event_context event_ctx = {};

	switch (context_config.context_type) {
	case lsc::context_configuration::type::PID:
		event_ctx.ctx = LTTNG_EVENT_CONTEXT_PID;
		break;
	case lsc::context_configuration::type::VPID:
		event_ctx.ctx = LTTNG_EVENT_CONTEXT_VPID;
		break;
	case lsc::context_configuration::type::TID:
		event_ctx.ctx = LTTNG_EVENT_CONTEXT_TID;
		break;
	case lsc::context_configuration::type::VTID:
		event_ctx.ctx = LTTNG_EVENT_CONTEXT_VTID;
		break;
	case lsc::context_configuration::type::PPID:
		event_ctx.ctx = LTTNG_EVENT_CONTEXT_PPID;
		break;
	case lsc::context_configuration::type::VPPID:
		event_ctx.ctx = LTTNG_EVENT_CONTEXT_VPPID;
		break;
	case lsc::context_configuration::type::PTHREAD_ID:
		event_ctx.ctx = LTTNG_EVENT_CONTEXT_PTHREAD_ID;
		break;
	case lsc::context_configuration::type::PROCNAME:
		event_ctx.ctx = LTTNG_EVENT_CONTEXT_PROCNAME;
		break;
	case lsc::context_configuration::type::PRIO:
		event_ctx.ctx = LTTNG_EVENT_CONTEXT_PRIO;
		break;
	case lsc::context_configuration::type::NICE:
		event_ctx.ctx = LTTNG_EVENT_CONTEXT_NICE;
		break;
	case lsc::context_configuration::type::INTERRUPTIBLE:
		event_ctx.ctx = LTTNG_EVENT_CONTEXT_INTERRUPTIBLE;
		break;
	case lsc::context_configuration::type::PREEMPTIBLE:
		event_ctx.ctx = LTTNG_EVENT_CONTEXT_PREEMPTIBLE;
		break;
	case lsc::context_configuration::type::NEED_RESCHEDULE:
		event_ctx.ctx = LTTNG_EVENT_CONTEXT_NEED_RESCHEDULE;
		break;
	case lsc::context_configuration::type::MIGRATABLE:
		event_ctx.ctx = LTTNG_EVENT_CONTEXT_MIGRATABLE;
		break;
	case lsc::context_configuration::type::HOSTNAME:
		event_ctx.ctx = LTTNG_EVENT_CONTEXT_HOSTNAME;
		break;
	case lsc::context_configuration::type::CPU_ID:
		event_ctx.ctx = LTTNG_EVENT_CONTEXT_CPU_ID;
		break;
	case lsc::context_configuration::type::CGROUP_NS:
		event_ctx.ctx = LTTNG_EVENT_CONTEXT_CGROUP_NS;
		break;
	case lsc::context_configuration::type::IPC_NS:
		event_ctx.ctx = LTTNG_EVENT_CONTEXT_IPC_NS;
		break;
	case lsc::context_configuration::type::MNT_NS:
		event_ctx.ctx = LTTNG_EVENT_CONTEXT_MNT_NS;
		break;
	case lsc::context_configuration::type::NET_NS:
		event_ctx.ctx = LTTNG_EVENT_CONTEXT_NET_NS;
		break;
	case lsc::context_configuration::type::PID_NS:
		event_ctx.ctx = LTTNG_EVENT_CONTEXT_PID_NS;
		break;
	case lsc::context_configuration::type::USER_NS:
		event_ctx.ctx = LTTNG_EVENT_CONTEXT_USER_NS;
		break;
	case lsc::context_configuration::type::UTS_NS:
		event_ctx.ctx = LTTNG_EVENT_CONTEXT_UTS_NS;
		break;
	case lsc::context_configuration::type::TIME_NS:
		event_ctx.ctx = LTTNG_EVENT_CONTEXT_TIME_NS;
		break;
	case lsc::context_configuration::type::UID:
		event_ctx.ctx = LTTNG_EVENT_CONTEXT_UID;
		break;
	case lsc::context_configuration::type::EUID:
		event_ctx.ctx = LTTNG_EVENT_CONTEXT_EUID;
		break;
	case lsc::context_configuration::type::SUID:
		event_ctx.ctx = LTTNG_EVENT_CONTEXT_SUID;
		break;
	case lsc::context_configuration::type::GID:
		event_ctx.ctx = LTTNG_EVENT_CONTEXT_GID;
		break;
	case lsc::context_configuration::type::EGID:
		event_ctx.ctx = LTTNG_EVENT_CONTEXT_EGID;
		break;
	case lsc::context_configuration::type::SGID:
		event_ctx.ctx = LTTNG_EVENT_CONTEXT_SGID;
		break;
	case lsc::context_configuration::type::VUID:
		event_ctx.ctx = LTTNG_EVENT_CONTEXT_VUID;
		break;
	case lsc::context_configuration::type::VEUID:
		event_ctx.ctx = LTTNG_EVENT_CONTEXT_VEUID;
		break;
	case lsc::context_configuration::type::VSUID:
		event_ctx.ctx = LTTNG_EVENT_CONTEXT_VSUID;
		break;
	case lsc::context_configuration::type::VGID:
		event_ctx.ctx = LTTNG_EVENT_CONTEXT_VGID;
		break;
	case lsc::context_configuration::type::VEGID:
		event_ctx.ctx = LTTNG_EVENT_CONTEXT_VEGID;
		break;
	case lsc::context_configuration::type::VSGID:
		event_ctx.ctx = LTTNG_EVENT_CONTEXT_VSGID;
		break;
	case lsc::context_configuration::type::CALLSTACK_KERNEL:
		event_ctx.ctx = LTTNG_EVENT_CONTEXT_CALLSTACK_KERNEL;
		break;
	case lsc::context_configuration::type::CALLSTACK_USER:
		event_ctx.ctx = LTTNG_EVENT_CONTEXT_CALLSTACK_USER;
		break;
	case lsc::context_configuration::type::IP:
		event_ctx.ctx = LTTNG_EVENT_CONTEXT_IP;
		break;
	case lsc::context_configuration::type::PERF_CPU_COUNTER:
	{
		event_ctx.ctx = LTTNG_EVENT_CONTEXT_PERF_CPU_COUNTER;
		const auto& perf_config =
			static_cast<const lsc::perf_counter_context_configuration&>(context_config);

		event_ctx.u.perf_counter.type = static_cast<uint32_t>(perf_config.perf_type);
		event_ctx.u.perf_counter.config = perf_config.perf_config;
		if (lttng_strncpy(event_ctx.u.perf_counter.name,
				  perf_config.name.c_str(),
				  sizeof(event_ctx.u.perf_counter.name))) {
			LTTNG_THROW_INVALID_ARGUMENT_ERROR("Perf counter name too long");
		}
		break;
	}
	case lsc::context_configuration::type::PERF_THREAD_COUNTER:
	{
		event_ctx.ctx = LTTNG_EVENT_CONTEXT_PERF_THREAD_COUNTER;
		const auto& perf_config =
			static_cast<const lsc::perf_counter_context_configuration&>(context_config);

		event_ctx.u.perf_counter.type = static_cast<uint32_t>(perf_config.perf_type);
		event_ctx.u.perf_counter.config = perf_config.perf_config;
		if (lttng_strncpy(event_ctx.u.perf_counter.name,
				  perf_config.name.c_str(),
				  sizeof(event_ctx.u.perf_counter.name))) {
			LTTNG_THROW_INVALID_ARGUMENT_ERROR("Perf counter name too long");
		}
		break;
	}
	case lsc::context_configuration::type::APP_CONTEXT:
	{
		/*
		 * APP_CONTEXT is not relevant for the kernel domain, but convert it
		 * faithfully for completeness. Note: the caller must ensure the
		 * lifetime of the returned struct does not outlive the strings.
		 */
		event_ctx.ctx = LTTNG_EVENT_CONTEXT_APP_CONTEXT;
		const auto& app_config =
			static_cast<const lsc::app_context_configuration&>(context_config);

		event_ctx.u.app_ctx.provider_name =
			const_cast<char *>(app_config.provider_name.c_str());
		event_ctx.u.app_ctx.ctx_name = const_cast<char *>(app_config.context_name.c_str());
		break;
	}
	default:
		LTTNG_THROW_INVALID_ARGUMENT_ERROR("Unknown context configuration type");
	}

	return event_ctx;
}

void enable_single_kernel_event(struct ltt_kernel_channel& kchan,
				struct lttng_event *event,
				char *filter_expression,
				struct lttng_bytecode *bytecode)
{
	const auto ret = event_kernel_enable_event(&kchan, event, filter_expression, bytecode);
	if (ret != LTTNG_OK) {
		LTTNG_THROW_CTL("Failed to enable kernel event",
				static_cast<lttng_error_code>(ret));
	}
}
} /* namespace */

void ls::modules::domain_orchestrator::enable_event(
	const lsc::recording_channel_configuration& channel_config,
	const lsc::event_rule_configuration& event_rule_config)
{
	LTTNG_ASSERT(_legacy_kernel_session);

	auto& kchan = find_legacy_channel(*_legacy_kernel_session, channel_config);

	const auto *rule = event_rule_config.event_rule.get();
	auto event = lttng::make_unique_wrapper<lttng_event, lttng_event_destroy>(
		lttng_event_rule_generate_lttng_event(rule));
	if (!event) {
		LTTNG_THROW_ERROR("Failed to generate lttng_event from event rule");
	}

	auto filter = duplicate_filter_from_rule(rule);

	enable_single_kernel_event(kchan, event.get(), filter.expression, filter.bytecode);

	auto *kevent = trace_kernel_get_event_by_name(event->name, &kchan, event->type);
	if (kevent) {
		_event_rule_to_legacy_events.emplace(&event_rule_config, kevent);
	}

	kernel_wait_quiescent();
}

void ls::modules::domain_orchestrator::disable_event(
	const lsc::recording_channel_configuration& channel_config __attribute__((unused)),
	const lsc::event_rule_configuration& event_rule_config)
{
	LTTNG_ASSERT(_legacy_kernel_session);

	const auto it = _event_rule_to_legacy_events.find(&event_rule_config);
	if (it == _event_rule_to_legacy_events.end()) {
		LTTNG_THROW_CTL("Failed to disable kernel event: no legacy event found for rule",
				LTTNG_ERR_KERN_DISABLE_FAIL);
	}

	const auto ret = kernel_disable_event(it->second);
	if (ret < 0) {
		LTTNG_THROW_CTL("Failed to disable kernel event", LTTNG_ERR_KERN_DISABLE_FAIL);
	}

	kernel_wait_quiescent();
}

void ls::modules::domain_orchestrator::add_context(
	const lsc::recording_channel_configuration& channel_config,
	const lsc::context_configuration& context_config)
{
	LTTNG_ASSERT(_legacy_kernel_session);

	const auto event_ctx = make_lttng_event_context_from_context_configuration(context_config);

	const auto ret =
		context_kernel_add(_legacy_kernel_session, &event_ctx, channel_config.name.c_str());
	if (ret != LTTNG_OK) {
		LTTNG_THROW_CTL("Failed to add kernel context", static_cast<lttng_error_code>(ret));
	}
}

namespace {
/*
 * Convert a config::process_attribute_type to the legacy lttng_process_attr
 * enum used by the kernel tracker functions.
 */
lttng_process_attr to_lttng_process_attr(lsc::process_attribute_type attribute_type)
{
	switch (attribute_type) {
	case lsc::process_attribute_type::PID:
		return LTTNG_PROCESS_ATTR_PROCESS_ID;
	case lsc::process_attribute_type::VPID:
		return LTTNG_PROCESS_ATTR_VIRTUAL_PROCESS_ID;
	case lsc::process_attribute_type::UID:
		return LTTNG_PROCESS_ATTR_USER_ID;
	case lsc::process_attribute_type::VUID:
		return LTTNG_PROCESS_ATTR_VIRTUAL_USER_ID;
	case lsc::process_attribute_type::GID:
		return LTTNG_PROCESS_ATTR_GROUP_ID;
	case lsc::process_attribute_type::VGID:
		return LTTNG_PROCESS_ATTR_VIRTUAL_GROUP_ID;
	default:
		abort();
	}
}

/*
 * Convert a config::tracking_policy to the legacy lttng_tracking_policy enum
 * used by the kernel tracker functions.
 */
lttng_tracking_policy to_lttng_tracking_policy(lsc::tracking_policy policy)
{
	switch (policy) {
	case lsc::tracking_policy::INCLUDE_ALL:
		return LTTNG_TRACKING_POLICY_INCLUDE_ALL;
	case lsc::tracking_policy::EXCLUDE_ALL:
		return LTTNG_TRACKING_POLICY_EXCLUDE_ALL;
	case lsc::tracking_policy::INCLUDE_SET:
		return LTTNG_TRACKING_POLICY_INCLUDE_SET;
	default:
		abort();
	}
}

/*
 * Build a process_attr_value from a numeric value and process attribute type.
 *
 * By the time the orchestrator is called, user/group names have already been
 * resolved to numeric IDs by the cmd.cpp helpers, so we only need the
 * numeric variant here.
 */
process_attr_value make_process_attr_value(lttng_process_attr process_attr, std::uint64_t value)
{
	struct process_attr_value attr_value = {};

	switch (process_attr) {
	case LTTNG_PROCESS_ATTR_PROCESS_ID:
	case LTTNG_PROCESS_ATTR_VIRTUAL_PROCESS_ID:
		attr_value.type = LTTNG_PROCESS_ATTR_VALUE_TYPE_PID;
		attr_value.value.pid = static_cast<pid_t>(value);
		break;
	case LTTNG_PROCESS_ATTR_USER_ID:
	case LTTNG_PROCESS_ATTR_VIRTUAL_USER_ID:
		attr_value.type = LTTNG_PROCESS_ATTR_VALUE_TYPE_UID;
		attr_value.value.uid = static_cast<uid_t>(value);
		break;
	case LTTNG_PROCESS_ATTR_GROUP_ID:
	case LTTNG_PROCESS_ATTR_VIRTUAL_GROUP_ID:
		attr_value.type = LTTNG_PROCESS_ATTR_VALUE_TYPE_GID;
		attr_value.value.gid = static_cast<gid_t>(value);
		break;
	default:
		abort();
	}

	return attr_value;
}
} /* namespace */

void ls::modules::domain_orchestrator::set_tracking_policy(
	config::process_attribute_type attribute_type, config::tracking_policy policy)
{
	LTTNG_ASSERT(_legacy_kernel_session);

	const auto process_attr = to_lttng_process_attr(attribute_type);
	const auto legacy_policy = to_lttng_tracking_policy(policy);

	const auto ret_code = kernel_process_attr_tracker_set_tracking_policy(
		_legacy_kernel_session, process_attr, legacy_policy);
	if (ret_code != LTTNG_OK) {
		LTTNG_THROW_CTL("Failed to set kernel tracking policy", ret_code);
	}
}

void ls::modules::domain_orchestrator::track_process_attribute(
	config::process_attribute_type attribute_type, std::uint64_t value)
{
	LTTNG_ASSERT(_legacy_kernel_session);

	const auto process_attr = to_lttng_process_attr(attribute_type);
	auto attr_value = make_process_attr_value(process_attr, value);

	const auto ret_code = kernel_process_attr_tracker_inclusion_set_add_value(
		_legacy_kernel_session, process_attr, &attr_value);
	if (ret_code != LTTNG_OK) {
		LTTNG_THROW_CTL("Failed to track kernel process attribute", ret_code);
	}
}

void ls::modules::domain_orchestrator::untrack_process_attribute(
	config::process_attribute_type attribute_type, std::uint64_t value)
{
	LTTNG_ASSERT(_legacy_kernel_session);

	const auto process_attr = to_lttng_process_attr(attribute_type);
	auto attr_value = make_process_attr_value(process_attr, value);

	const auto ret_code = kernel_process_attr_tracker_inclusion_set_remove_value(
		_legacy_kernel_session, process_attr, &attr_value);
	if (ret_code != LTTNG_OK) {
		LTTNG_THROW_CTL("Failed to untrack kernel process attribute", ret_code);
	}
}

void ls::modules::domain_orchestrator::start()
{
	LTTNG_ASSERT(_legacy_kernel_session);

	const auto ret = start_kernel_session(_legacy_kernel_session,
					      _domain_configuration.metadata_channel());

	if (ret != LTTNG_OK) {
		LTTNG_THROW_CTL("Failed to start kernel session",
				static_cast<lttng_error_code>(ret));
	}
}

void ls::modules::domain_orchestrator::stop()
{
	LTTNG_ASSERT(_legacy_kernel_session);

	const auto ret = stop_kernel_session(_legacy_kernel_session);

	if (ret != LTTNG_OK) {
		LTTNG_THROW_CTL("Failed to stop kernel session",
				static_cast<lttng_error_code>(ret));
	}
}

void ls::modules::domain_orchestrator::rotate()
{
	LTTNG_ASSERT(_legacy_kernel_session);

	const auto ret = kernel_rotate_session(_legacy_kernel_session);

	if (ret != LTTNG_OK) {
		LTTNG_THROW_CTL("Failed to rotate kernel session",
				static_cast<lttng_error_code>(ret));
	}
}

void ls::modules::domain_orchestrator::clear()
{
	LTTNG_ASSERT(_legacy_kernel_session);

	const auto ret = kernel_clear_session(_legacy_kernel_session);

	if (ret != LTTNG_OK) {
		LTTNG_THROW_CTL("Failed to clear kernel session",
				static_cast<lttng_error_code>(ret));
	}
}

void ls::modules::domain_orchestrator::open_packets()
{
	LTTNG_ASSERT(_legacy_kernel_session);

	const auto ret = kernel_open_packets(_legacy_kernel_session);

	if (ret != LTTNG_OK) {
		LTTNG_THROW_CTL("Failed to open packets of kernel session",
				static_cast<lttng_error_code>(ret));
	}
}

void ls::modules::domain_orchestrator::record_snapshot(
	const struct consumer_output& snapshot_consumer, std::uint64_t nb_packets_per_stream)
{
	LTTNG_ASSERT(_legacy_kernel_session);

	const auto ret_code = kernel_snapshot_record(_legacy_kernel_session,
						     _domain_configuration.metadata_channel(),
						     &snapshot_consumer,
						     nb_packets_per_stream);
	if (ret_code != LTTNG_OK) {
		LTTNG_THROW_CTL("Failed to record kernel snapshot", ret_code);
	}
}

void ls::modules::domain_orchestrator::regenerate_metadata()
{
	LTTNG_ASSERT(_legacy_kernel_session);

	const auto ret = kernctl_session_regenerate_metadata(_legacy_kernel_session->fd);
	if (ret < 0) {
		LTTNG_THROW_POSIX("Failed to regenerate kernel metadata", -ret);
	}
}

void ls::modules::domain_orchestrator::regenerate_statedump()
{
	LTTNG_ASSERT(_legacy_kernel_session);

	const auto ret = kernctl_session_regenerate_statedump(_legacy_kernel_session->fd);
	if (ret < 0) {
		if (ret == -ENOMEM) {
			LTTNG_THROW_POSIX("Failed to regenerate kernel statedump: out of memory",
					  ENOMEM);
		}

		LTTNG_THROW_POSIX("Failed to regenerate kernel statedump", -ret);
	}
}

void ls::modules::domain_orchestrator::reclaim_channel_memory(
	const lsc::recording_channel_configuration& target_channel [[maybe_unused]])
{
	LTTNG_THROW_UNSUPPORTED_ERROR(
		"Channel memory reclamation is not supported by the lttng-modules tracer");
}
