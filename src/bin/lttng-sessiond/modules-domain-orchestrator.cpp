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
#include "utils.hpp"

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

#include <fcntl.h>
#include <inttypes.h>

namespace ls = lttng::sessiond;
namespace lsc = lttng::sessiond::config;

/*
 * Domain orchestrator for the lttng-modules kernel tracer.
 *
 * Channel creation is performed directly by the orchestrator: it builds the
 * kernel ABI struct from the configuration, issues the ioctl, and creates a
 * legacy ltt_kernel_channel struct for downstream code that still reads from
 * the legacy hierarchy (channel listing, consumer communication, kernel thread
 * stream opening, notification thread).
 *
 * Other operations (enable/disable channel, events, context, start/stop, etc.)
 * still delegate to the existing kernel_*, channel_kernel_*, event_kernel_*,
 * and context_kernel_* functions during the transition. These will be
 * internalized progressively.
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
 * This conversion is a transitional bridge: the legacy ltt_kernel_channel
 * struct still carries a lttng_channel pointer that downstream code reads
 * from (channel listing, consumer channel send, etc.). Once those readers
 * are migrated to read from the configuration objects directly, this
 * conversion will be eliminated.
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

	auto kernel_abi_channel = make_kernel_abi_channel(channel_config);

	/* Enforce mmap output for snapshot sessions. */
	if (_legacy_kernel_session->snapshot_mode) {
		kernel_abi_channel.output = LTTNG_EVENT_MMAP;
	}

	/* Create the channel in the kernel tracer via ioctl. */
	const auto raw_channel_fd =
		kernctl_create_channel(_tracer_session_fd.fd(), kernel_abi_channel);
	if (raw_channel_fd < 0) {
		LTTNG_THROW_POSIX("Failed to create kernel channel", -raw_channel_fd);
	}

	lttng::file_descriptor channel_fd(raw_channel_fd);

	/* Prevent the fd from leaking across exec. */
	if (fcntl(channel_fd.fd(), F_SETFD, FD_CLOEXEC) < 0) {
		LTTNG_THROW_POSIX("Failed to set FD_CLOEXEC on kernel channel fd", errno);
	}

	/*
	 * Create a legacy ltt_kernel_channel for downstream code that still
	 * reads from the legacy hierarchy: channel listing, consumer channel
	 * send, kernel thread stream opening, and notification thread.
	 *
	 * The legacy struct owns the channel fd during the transition period.
	 * This dual-write will be removed once all downstream readers are
	 * migrated to the orchestrator's modern channel objects.
	 */
	auto legacy_channel_attr = make_lttng_channel_from_config(channel_config);
	if (_legacy_kernel_session->snapshot_mode) {
		legacy_channel_attr->attr.output = LTTNG_EVENT_MMAP;
	}

	auto *lkc = trace_kernel_create_channel(legacy_channel_attr.get());
	if (!lkc) {
		LTTNG_THROW_ALLOCATION_FAILURE_ERROR(
			"Failed to allocate legacy ltt_kernel_channel");
	}

	/* Transfer fd ownership to the legacy struct. */
	lkc->fd = channel_fd.release();
	lkc->key = allocate_next_kernel_channel_key();
	lkc->session = _legacy_kernel_session;
	cds_list_add(&lkc->list, &_legacy_kernel_session->channel_list.head);
	_legacy_kernel_session->channel_count++;

	if (channel_config.name != DEFAULT_CHANNEL_NAME) {
		_legacy_kernel_session->has_non_default_channel = 1;
	}

	/* Notify the kernel thread that a new channel exists. */
	if (notify_thread_pipe(_kernel_pipe) < 0) {
		LTTNG_THROW_ERROR("Failed to notify kernel thread of new channel");
	}

	DBG("Kernel channel %s created (fd: %d, key: %" PRIu64 ")",
	    channel_config.name.c_str(),
	    lkc->fd,
	    lkc->key);

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

lttng_kernel_abi_tracker_type to_modules_tracker_type(lsc::process_attribute_type attribute_type)
{
	switch (attribute_type) {
	case lsc::process_attribute_type::PID:
		return LTTNG_KERNEL_ABI_TRACKER_PID;
	case lsc::process_attribute_type::VPID:
		return LTTNG_KERNEL_ABI_TRACKER_VPID;
	case lsc::process_attribute_type::UID:
		return LTTNG_KERNEL_ABI_TRACKER_UID;
	case lsc::process_attribute_type::VUID:
		return LTTNG_KERNEL_ABI_TRACKER_VUID;
	case lsc::process_attribute_type::GID:
		return LTTNG_KERNEL_ABI_TRACKER_GID;
	case lsc::process_attribute_type::VGID:
		return LTTNG_KERNEL_ABI_TRACKER_VGID;
	default:
		LTTNG_THROW_INVALID_ARGUMENT_ERROR("Unknown process attribute type");
	}
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

void ls::modules::domain_orchestrator::set_tracking_policy(
	config::process_attribute_type attribute_type, config::tracking_policy policy)
{
	const auto modules_tracker_type = to_modules_tracker_type(attribute_type);
	int modules_ret = 0;

	switch (policy) {
	case lsc::tracking_policy::INCLUDE_ALL:
		if (attribute_type == lsc::process_attribute_type::PID) {
			modules_ret = kernctl_track_pid(_tracer_session_fd.fd(), -1);
		} else {
			modules_ret =
				kernctl_track_id(_tracer_session_fd.fd(), modules_tracker_type, -1);
		}

		break;
	case lsc::tracking_policy::EXCLUDE_ALL:
	case lsc::tracking_policy::INCLUDE_SET:
		/* fall-through. */
		if (attribute_type == lsc::process_attribute_type::PID) {
			/*
			 * Maintain a special case for the process ID process
			 * attribute tracker as it was the only supported
			 * attribute prior to 2.12.
			 */
			modules_ret = kernctl_untrack_pid(_tracer_session_fd.fd(), -1);
		} else {
			modules_ret = kernctl_untrack_id(
				_tracer_session_fd.fd(), modules_tracker_type, -1);
		}

		break;
	default:
		std::abort();
	}

	switch (-modules_ret) {
	case 0:
		return;
	case EINVAL:
		LTTNG_THROW_INVALID_ARGUMENT_ERROR(
			"Failed to set tracking policy: LTTng-modules reports an invalid argument");
	case ENOMEM:
		LTTNG_THROW_ALLOCATION_FAILURE_ERROR(
			"Failed to set tracking policy: LTTng-modules is out of memory");
	case EEXIST:
		LTTNG_THROW_CTL(
			"Failed to set tracking policy: LTTng-modules reports the specified tracking policy is already set",
			LTTNG_ERR_PROCESS_ATTR_EXISTS);
	default:
		LTTNG_THROW_ERROR(fmt::format(
			"Failed to set tracking policy: unexpected error from LTTng-modules ({})",
			modules_ret));
	}
}

void ls::modules::domain_orchestrator::track_process_attribute(
	config::process_attribute_type attribute_type, std::uint64_t value)
{
	const auto modules_tracker_type = to_modules_tracker_type(attribute_type);
	int modules_ret = 0;

	if (attribute_type == lsc::process_attribute_type::PID) {
		modules_ret = kernctl_track_pid(_tracer_session_fd.fd(), value);
	} else {
		modules_ret =
			kernctl_track_id(_tracer_session_fd.fd(), modules_tracker_type, value);
	}

	switch (-modules_ret) {
	case 0:
		kernel_wait_quiescent();
		return;
	case EINVAL:
		LTTNG_THROW_INVALID_ARGUMENT_ERROR(fmt::format(
			"Failed to track process attribute: type={}, value={}: LTTng-modules reports an invalid argument",
			attribute_type,
			value));
	case ENOMEM:
		LTTNG_THROW_ALLOCATION_FAILURE_ERROR(fmt::format(
			"Failed to track process attribute: type={}, value={}: LTTng-modules is out of memory",
			attribute_type,
			value));
	case EEXIST:
		LTTNG_THROW_CTL(
			fmt::format(
				"Failed to track process attribute: type={}, value={}: LTTng-modules reports the specified value is already tracked",
				attribute_type,
				value),
			LTTNG_ERR_PROCESS_ATTR_EXISTS);
	default:
		LTTNG_THROW_ERROR(fmt::format(
			"Failed to track process attribute: type={}, value={}: unexpected error from LTTng-modules ({})",
			attribute_type,
			value,
			modules_ret));
	}
}

void ls::modules::domain_orchestrator::untrack_process_attribute(
	config::process_attribute_type attribute_type, std::uint64_t value)
{
	const auto modules_tracker_type = to_modules_tracker_type(attribute_type);
	int modules_ret = 0;

	if (attribute_type == lsc::process_attribute_type::PID) {
		modules_ret = kernctl_untrack_pid(_tracer_session_fd.fd(), value);
	} else {
		modules_ret =
			kernctl_untrack_id(_tracer_session_fd.fd(), modules_tracker_type, value);
	}

	switch (-modules_ret) {
	case 0:
		kernel_wait_quiescent();
		return;
	case EINVAL:
		LTTNG_THROW_INVALID_ARGUMENT_ERROR(fmt::format(
			"Failed to untrack process attribute: type={}, value={}: LTTng-modules reports an invalid argument",
			attribute_type,
			value));
	case ENOMEM:
		LTTNG_THROW_ALLOCATION_FAILURE_ERROR(fmt::format(
			"Failed to untrack process attribute: type={}, value={}: LTTng-modules is out of memory",
			attribute_type,
			value));
	case ENOENT:
		LTTNG_THROW_CTL(
			fmt::format(
				"Failed to untrack process attribute: type={}, value={}: LTTng-modules reports the specified tracked value does not exist",
				attribute_type,
				value),
			LTTNG_ERR_PROCESS_ATTR_MISSING);
	default:
		LTTNG_THROW_ERROR(fmt::format(
			"Failed to untrack process attribute: type={}, value={}: unexpected error from LTTng-modules ({})",
			attribute_type,
			value,
			modules_ret));
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
	const auto ret = kernctl_session_regenerate_metadata(_tracer_session_fd.fd());
	if (ret < 0) {
		LTTNG_THROW_POSIX("Failed to regenerate kernel metadata", -ret);
	}
}

void ls::modules::domain_orchestrator::regenerate_statedump()
{
	const auto ret = kernctl_session_regenerate_statedump(_tracer_session_fd.fd());
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
