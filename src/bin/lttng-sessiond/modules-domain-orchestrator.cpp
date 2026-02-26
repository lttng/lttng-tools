/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "consumer.hpp"
#include "health-sessiond.hpp"
#include "kernel.hpp"
#include "lttng-channel-from-config.hpp"
#include "lttng-sessiond.hpp"
#include "modules-domain-orchestrator.hpp"
#include "notification-thread-commands.hpp"
#include "process-attribute-tracker.hpp"
#include "session.hpp"
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
#include <lttng/event-rule/event-rule-internal.hpp>
#include <lttng/event-rule/kernel-kprobe-internal.hpp>
#include <lttng/event-rule/kernel-kprobe.h>
#include <lttng/event-rule/kernel-syscall-internal.hpp>
#include <lttng/event-rule/kernel-syscall.h>
#include <lttng/event-rule/kernel-tracepoint-internal.hpp>
#include <lttng/event-rule/kernel-tracepoint.h>
#include <lttng/event-rule/kernel-uprobe-internal.hpp>
#include <lttng/event-rule/kernel-uprobe.h>
#include <lttng/lttng-error.h>
#include <lttng/userspace-probe-internal.hpp>

#include <fcntl.h>
#include <inttypes.h>

namespace ls = lttng::sessiond;
namespace lsc = lttng::sessiond::config;

/*
 * Domain orchestrator for the lttng-modules kernel tracer.
 *
 * Channel and event operations are performed directly by the orchestrator:
 * it builds the kernel ABI structs from the configuration objects, issues
 * the ioctls, and manages event file descriptors through modern
 * modules::event_rule objects.
 *
 * Channel creation still maintains a legacy ltt_kernel_channel struct for
 * downstream code that has not been migrated yet (consumer communication,
 * kernel thread stream opening, notification thread).
 *
 * Session-level operations (start/stop, snapshot) still delegate to the
 * existing kernel_* functions during the transition. Consumer-only
 * operations (rotate, clear, open_packets) are performed directly by
 * iterating the orchestrator's channel map.
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
 * Build a lttng_kernel_abi_event struct directly from an event rule.
 *
 * This follows the same mapping as trace_kernel_init_event_notifier_from_event_rule()
 * but targets recording events (which use lttng_kernel_abi_event) rather than
 * event notifiers (which use lttng_kernel_abi_event_notifier).
 */
lttng_kernel_abi_event make_kernel_abi_event_from_event_rule(const struct lttng_event_rule *rule)
{
	lttng_kernel_abi_event abi_event = {};
	const char *name;

	switch (lttng_event_rule_get_type(rule)) {
	case LTTNG_EVENT_RULE_TYPE_KERNEL_KPROBE:
	{
		uint64_t address = 0, offset = 0;
		const char *symbol_name = nullptr;
		const struct lttng_kernel_probe_location *location = nullptr;

		const auto status = lttng_event_rule_kernel_kprobe_get_location(rule, &location);
		if (status != LTTNG_EVENT_RULE_STATUS_OK) {
			LTTNG_THROW_INVALID_ARGUMENT_ERROR("Failed to get kprobe location");
		}

		switch (lttng_kernel_probe_location_get_type(location)) {
		case LTTNG_KERNEL_PROBE_LOCATION_TYPE_ADDRESS:
		{
			const auto k_status =
				lttng_kernel_probe_location_address_get_address(location, &address);
			LTTNG_ASSERT(k_status == LTTNG_KERNEL_PROBE_LOCATION_STATUS_OK);
			break;
		}
		case LTTNG_KERNEL_PROBE_LOCATION_TYPE_SYMBOL_OFFSET:
		{
			const auto k_status =
				lttng_kernel_probe_location_symbol_get_offset(location, &offset);
			LTTNG_ASSERT(k_status == LTTNG_KERNEL_PROBE_LOCATION_STATUS_OK);
			symbol_name = lttng_kernel_probe_location_symbol_get_name(location);
			break;
		}
		default:
			LTTNG_THROW_INVALID_ARGUMENT_ERROR("Unknown kernel probe location type");
		}

		const auto *kprobe =
			lttng::utils::container_of(rule, &lttng_event_rule_kernel_kprobe::parent);
		switch (kprobe->instrumentation_site) {
		case LTTNG_EVENT_RULE_KERNEL_KPROBE_INSTRUMENTATION_SITE_ENTRY_EXIT:
			abi_event.instrumentation = LTTNG_KERNEL_ABI_KRETPROBE;

			abi_event.u.kretprobe.addr = address;
			abi_event.u.kretprobe.offset = offset;
			if (symbol_name) {
				if (lttng_strncpy(abi_event.u.kretprobe.symbol_name,
						  symbol_name,
						  sizeof(abi_event.u.kretprobe.symbol_name))) {
					LTTNG_THROW_INVALID_ARGUMENT_ERROR(
						"kretprobe symbol name exceeds maximal length");
				}
			}

			break;
		case LTTNG_EVENT_RULE_KERNEL_KPROBE_INSTRUMENTATION_SITE_LOCATION:
			abi_event.instrumentation = LTTNG_KERNEL_ABI_KPROBE;

			abi_event.u.kprobe.addr = address;
			abi_event.u.kprobe.offset = offset;
			if (symbol_name) {
				if (lttng_strncpy(abi_event.u.kprobe.symbol_name,
						  symbol_name,
						  sizeof(abi_event.u.kprobe.symbol_name))) {
					LTTNG_THROW_INVALID_ARGUMENT_ERROR(
						"kprobe symbol name exceeds maximal length");
				}
			}

			break;
		default:
			LTTNG_THROW_INVALID_ARGUMENT_ERROR(
				"Unknown kprobe instrumentation site type");
		}

		const auto event_name_status =
			lttng_event_rule_kernel_kprobe_get_event_name(rule, &name);
		LTTNG_ASSERT(event_name_status == LTTNG_EVENT_RULE_STATUS_OK);
		break;
	}
	case LTTNG_EVENT_RULE_TYPE_KERNEL_UPROBE:
	{
		const struct lttng_userspace_probe_location *location = nullptr;
		const struct lttng_userspace_probe_location_lookup_method *lookup = nullptr;

		const auto status = lttng_event_rule_kernel_uprobe_get_location(rule, &location);
		if (status != LTTNG_EVENT_RULE_STATUS_OK) {
			LTTNG_THROW_INVALID_ARGUMENT_ERROR("Failed to get uprobe location");
		}

		abi_event.instrumentation = LTTNG_KERNEL_ABI_UPROBE;

		lookup = lttng_userspace_probe_location_get_lookup_method(location);
		if (!lookup) {
			LTTNG_THROW_INVALID_ARGUMENT_ERROR("Missing uprobe lookup method");
		}

		switch (lttng_userspace_probe_location_lookup_method_get_type(lookup)) {
		case LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_FUNCTION_ELF:
			abi_event.u.uprobe.fd =
				lttng_userspace_probe_location_function_get_binary_fd(location);
			break;
		case LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_TRACEPOINT_SDT:
			abi_event.u.uprobe.fd =
				lttng_userspace_probe_location_tracepoint_get_binary_fd(location);
			break;
		default:
			LTTNG_THROW_INVALID_ARGUMENT_ERROR("Unsupported uprobe lookup method");
		}

		const auto event_name_status =
			lttng_event_rule_kernel_uprobe_get_event_name(rule, &name);
		LTTNG_ASSERT(event_name_status == LTTNG_EVENT_RULE_STATUS_OK);
		break;
	}
	case LTTNG_EVENT_RULE_TYPE_KERNEL_TRACEPOINT:
	{
		const auto status =
			lttng_event_rule_kernel_tracepoint_get_name_pattern(rule, &name);
		LTTNG_ASSERT(status == LTTNG_EVENT_RULE_STATUS_OK);
		abi_event.instrumentation = LTTNG_KERNEL_ABI_TRACEPOINT;
		break;
	}
	case LTTNG_EVENT_RULE_TYPE_KERNEL_SYSCALL:
	{
		const auto status = lttng_event_rule_kernel_syscall_get_name_pattern(rule, &name);
		LTTNG_ASSERT(status == LTTNG_EVENT_RULE_STATUS_OK);

		const auto emission_site = lttng_event_rule_kernel_syscall_get_emission_site(rule);
		LTTNG_ASSERT(emission_site !=
			     LTTNG_EVENT_RULE_KERNEL_SYSCALL_EMISSION_SITE_UNKNOWN);

		enum lttng_kernel_abi_syscall_entryexit entryexit;
		switch (emission_site) {
		case LTTNG_EVENT_RULE_KERNEL_SYSCALL_EMISSION_SITE_ENTRY:
			entryexit = LTTNG_KERNEL_ABI_SYSCALL_ENTRY;
			break;
		case LTTNG_EVENT_RULE_KERNEL_SYSCALL_EMISSION_SITE_EXIT:
			entryexit = LTTNG_KERNEL_ABI_SYSCALL_EXIT;
			break;
		case LTTNG_EVENT_RULE_KERNEL_SYSCALL_EMISSION_SITE_ENTRY_EXIT:
			entryexit = LTTNG_KERNEL_ABI_SYSCALL_ENTRYEXIT;
			break;
		default:
			LTTNG_THROW_INVALID_ARGUMENT_ERROR("Unknown syscall emission site");
		}

		abi_event.instrumentation = LTTNG_KERNEL_ABI_SYSCALL;
		abi_event.u.syscall.abi = LTTNG_KERNEL_ABI_SYSCALL_ABI_ALL;
		abi_event.u.syscall.entryexit = entryexit;
		abi_event.u.syscall.match = LTTNG_KERNEL_ABI_SYSCALL_MATCH_NAME;
		break;
	}
	default:
		LTTNG_THROW_INVALID_ARGUMENT_ERROR(
			fmt::format("Unsupported event rule type for kernel tracer: type={}",
				    static_cast<int>(lttng_event_rule_get_type(rule))));
	}

	if (lttng_strncpy(abi_event.name, name, sizeof(abi_event.name))) {
		LTTNG_THROW_INVALID_ARGUMENT_ERROR("Event rule name too long");
	}

	return abi_event;
}
} /* namespace */

ls::modules::domain_orchestrator::~domain_orchestrator()
{
	/*
	 * Unregister all channels from the hotplug handler thread so their
	 * fds are removed from the poller before being closed.
	 */
	for (auto& channel_entry : _channels) {
		auto& channel = *channel_entry.second;

		if (!channel.is_sent_to_consumer()) {
			/* Channel was never registered for hotplug monitoring. */
			continue;
		}

		hotplug_handler::command cmd(
			hotplug_handler::command_type::REMOVE_CHANNEL, channel, _session_id);
		_hotplug_queue.send_and_wait(std::move(cmd));
	}

	/*
	 * Destroy stream groups on the consumer daemon.
	 *
	 * When the streams are in no-monitor mode (flight recorder), the
	 * consumer daemon doesn't track their lifecycle, so it must be
	 * explicitly told to destroy them or they will leak. In monitor
	 * mode, the consumer handles cleanup on its own.
	 */
	if (!_legacy_kernel_session->output_traces) {
		try {
			auto& socket = _get_consumer_socket();
			const lttng::pthread::lock_guard socket_lock(*socket.lock);

			for (const auto& channel_entry : _channels) {
				const auto& channel = *channel_entry.second;

				if (!channel.is_sent_to_consumer()) {
					continue;
				}

				_destroy_consumer_stream_group(socket, channel.consumer_key());
			}

			if (_metadata && _metadata->is_sent_to_consumer()) {
				_destroy_consumer_stream_group(socket, _metadata->consumer_key());
			}
		} catch (const std::exception& ex) {
			ERR_FMT("Failed to destroy consumer stream groups during orchestrator teardown: {}",
				ex.what());
		}
	}

	/*
	 * Unregister all channels that were published to the notification
	 * thread. This mirrors the add performed by _send_channel_to_consumer()
	 * and ensures the notification thread doesn't hold stale references to
	 * destroyed channels.
	 */
	for (const auto& channel_entry : _channels) {
		const auto& channel = *channel_entry.second;

		if (!channel.is_published_to_notification_thread()) {
			continue;
		}

		if (!the_notification_thread_handle) {
			continue;
		}

		const auto status =
			notification_thread_command_remove_channel(the_notification_thread_handle,
								   channel.consumer_key(),
								   LTTNG_DOMAIN_KERNEL);
		if (status != LTTNG_OK) {
			ERR_FMT("Failed to remove kernel channel from notification thread: key={}",
				channel.consumer_key());
		}
	}
}

void ls::modules::domain_orchestrator::create_channel(
	const lsc::recording_channel_configuration& channel_config)
{
	LTTNG_ASSERT(_legacy_kernel_session);

	DBG_FMT("Creating kernel channel from configuration: config={}", channel_config);

	auto kernel_abi_channel = make_kernel_abi_channel(channel_config);

	/* Enforce mmap output for snapshot sessions. */
	if (_legacy_kernel_session->snapshot_mode) {
		LTTNG_ASSERT(kernel_abi_channel.output == LTTNG_EVENT_MMAP);
	}

	/* Create the stream group in the kernel tracer via ioctl. */
	auto modules_stream_group_fd = [&]() {
		const auto raw_channel_fd =
			kernctl_create_channel(_tracer_session_fd.fd(), kernel_abi_channel);
		if (raw_channel_fd < 0) {
			LTTNG_THROW_POSIX("Failed to create kernel channel", -raw_channel_fd);
		}

		return lttng::file_descriptor(raw_channel_fd);
	}();

	/* Prevent the fd from leaking across exec. */
	if (fcntl(modules_stream_group_fd.fd(), F_SETFD, FD_CLOEXEC) < 0) {
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
	auto legacy_channel_attr = ls::make_lttng_channel(channel_config);

	auto lkc = lttng::make_unique_wrapper<ltt_kernel_channel, trace_kernel_destroy_channel>(
		trace_kernel_create_channel(legacy_channel_attr.get()));
	if (!lkc) {
		LTTNG_THROW_ALLOCATION_FAILURE_ERROR(
			"Failed to allocate legacy ltt_kernel_channel");
	}

	const auto stream_group_key = allocate_next_kernel_stream_group_key();
	lkc->fd = modules_stream_group_fd.fd();
	lkc->key = stream_group_key;
	lkc->session = _legacy_kernel_session;
	cds_list_add(&lkc->list, &_legacy_kernel_session->channel_list.head);
	/* ownership transferred to legacy struct. NOLINTNEXTLINE(bugprone-unused-return-value) */
	lkc.release();
	_legacy_kernel_session->channel_count++;

	if (channel_config.name != DEFAULT_CHANNEL_NAME) {
		_legacy_kernel_session->has_non_default_channel = 1;
	}

	/* Register the modern channel object, keyed by config identity. */
	_channels.emplace(
		&channel_config,
		lttng::make_unique<modules::stream_group>(
			std::move(modules_stream_group_fd), stream_group_key, channel_config));

	kernel_wait_quiescent();
}

void ls::modules::domain_orchestrator::enable_channel(
	const lsc::recording_channel_configuration& channel_config)
{
	auto& runtime_channel = _get_channel(channel_config);

	DBG_FMT("Enabling kernel channel: name=`{}`", channel_config.name);
	const auto ret = kernctl_enable(runtime_channel.tracer_handle().fd());
	if (ret < 0) {
		LTTNG_THROW_POSIX("Failed to enable kernel channel", -ret);
	}

	/* Keep the legacy struct in sync for downstream code. */
	auto& kchan = find_legacy_channel(*_legacy_kernel_session, channel_config);
	kchan.enabled = true;

	kernel_wait_quiescent();
}

void ls::modules::domain_orchestrator::disable_channel(
	const lsc::recording_channel_configuration& channel_config)
{
	auto& runtime_channel = _get_channel(channel_config);

	DBG_FMT("Disabling kernel channel: name=`{}`", channel_config.name);
	const auto ret = kernctl_disable(runtime_channel.tracer_handle().fd());
	if (ret < 0 && ret != -EEXIST) {
		LTTNG_THROW_POSIX("Failed to disable kernel channel", -ret);
	}

	/* Keep the legacy struct in sync for downstream code. */
	auto& kchan = find_legacy_channel(*_legacy_kernel_session, channel_config);
	kchan.enabled = false;

	kernel_wait_quiescent();
}

namespace {

/*
 * Convert a context_configuration to the lttng_kernel_abi_context struct
 * expected by the kernel tracer's add-context ioctl.
 */
lttng_kernel_abi_context make_kernel_abi_context(const lsc::context_configuration& context_config)
{
	struct lttng_kernel_abi_context abi_ctx = {};

	switch (context_config.context_type) {
	case lsc::context_configuration::type::PID:
		abi_ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_PID;
		break;
	case lsc::context_configuration::type::PROCNAME:
		abi_ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_PROCNAME;
		break;
	case lsc::context_configuration::type::PRIO:
		abi_ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_PRIO;
		break;
	case lsc::context_configuration::type::NICE:
		abi_ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_NICE;
		break;
	case lsc::context_configuration::type::VPID:
		abi_ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_VPID;
		break;
	case lsc::context_configuration::type::TID:
		abi_ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_TID;
		break;
	case lsc::context_configuration::type::VTID:
		abi_ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_VTID;
		break;
	case lsc::context_configuration::type::PPID:
		abi_ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_PPID;
		break;
	case lsc::context_configuration::type::VPPID:
		abi_ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_VPPID;
		break;
	case lsc::context_configuration::type::HOSTNAME:
		abi_ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_HOSTNAME;
		break;
	case lsc::context_configuration::type::INTERRUPTIBLE:
		abi_ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_INTERRUPTIBLE;
		break;
	case lsc::context_configuration::type::PREEMPTIBLE:
		abi_ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_PREEMPTIBLE;
		break;
	case lsc::context_configuration::type::NEED_RESCHEDULE:
		abi_ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_NEED_RESCHEDULE;
		break;
	case lsc::context_configuration::type::MIGRATABLE:
		abi_ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_MIGRATABLE;
		break;
	case lsc::context_configuration::type::CALLSTACK_KERNEL:
		abi_ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_CALLSTACK_KERNEL;
		break;
	case lsc::context_configuration::type::CALLSTACK_USER:
		abi_ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_CALLSTACK_USER;
		break;
	case lsc::context_configuration::type::CGROUP_NS:
		abi_ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_CGROUP_NS;
		break;
	case lsc::context_configuration::type::IPC_NS:
		abi_ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_IPC_NS;
		break;
	case lsc::context_configuration::type::MNT_NS:
		abi_ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_MNT_NS;
		break;
	case lsc::context_configuration::type::NET_NS:
		abi_ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_NET_NS;
		break;
	case lsc::context_configuration::type::PID_NS:
		abi_ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_PID_NS;
		break;
	case lsc::context_configuration::type::TIME_NS:
		abi_ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_TIME_NS;
		break;
	case lsc::context_configuration::type::USER_NS:
		abi_ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_USER_NS;
		break;
	case lsc::context_configuration::type::UTS_NS:
		abi_ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_UTS_NS;
		break;
	case lsc::context_configuration::type::UID:
		abi_ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_UID;
		break;
	case lsc::context_configuration::type::EUID:
		abi_ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_EUID;
		break;
	case lsc::context_configuration::type::SUID:
		abi_ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_SUID;
		break;
	case lsc::context_configuration::type::GID:
		abi_ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_GID;
		break;
	case lsc::context_configuration::type::EGID:
		abi_ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_EGID;
		break;
	case lsc::context_configuration::type::SGID:
		abi_ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_SGID;
		break;
	case lsc::context_configuration::type::VUID:
		abi_ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_VUID;
		break;
	case lsc::context_configuration::type::VEUID:
		abi_ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_VEUID;
		break;
	case lsc::context_configuration::type::VSUID:
		abi_ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_VSUID;
		break;
	case lsc::context_configuration::type::VGID:
		abi_ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_VGID;
		break;
	case lsc::context_configuration::type::VEGID:
		abi_ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_VEGID;
		break;
	case lsc::context_configuration::type::VSGID:
		abi_ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_VSGID;
		break;
	case lsc::context_configuration::type::PERF_CPU_COUNTER:
	{
		abi_ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_PERF_CPU_COUNTER;
		const auto& perf_config =
			static_cast<const lsc::perf_counter_context_configuration&>(context_config);

		abi_ctx.u.perf_counter.type = static_cast<uint32_t>(perf_config.perf_type);
		abi_ctx.u.perf_counter.config = perf_config.perf_config;
		if (lttng_strncpy(abi_ctx.u.perf_counter.name,
				  perf_config.name.c_str(),
				  sizeof(abi_ctx.u.perf_counter.name))) {
			LTTNG_THROW_INVALID_ARGUMENT_ERROR("Perf counter name too long");
		}
		break;
	}
	case lsc::context_configuration::type::PTHREAD_ID:
	case lsc::context_configuration::type::CPU_ID:
	case lsc::context_configuration::type::IP:
	case lsc::context_configuration::type::PERF_THREAD_COUNTER:
	case lsc::context_configuration::type::APP_CONTEXT:
		LTTNG_THROW_INVALID_ARGUMENT_ERROR(
			fmt::format("Context type not supported by the kernel tracer: context={}",
				    context_config));
	default:
		LTTNG_THROW_INVALID_ARGUMENT_ERROR(fmt::format(
			"Unknown context configuration type: context={}", context_config));
	}

	return abi_ctx;
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

} /* namespace */

void ls::modules::domain_orchestrator::enable_event(
	const lsc::recording_channel_configuration& channel_config,
	const lsc::event_rule_configuration& event_rule_config)
{
	auto& runtime_channel = _get_channel(channel_config);

	/* Check if this event rule already has a runtime handle (re-enable case). */
	auto *existing_event = runtime_channel.find_event_rule(event_rule_config);
	if (existing_event) {
		const auto ret = kernctl_enable(existing_event->tracer_handle().fd());
		if (ret < 0) {
			LTTNG_THROW_POSIX("Failed to re-enable kernel event", -ret);
		}

		kernel_wait_quiescent();
		return;
	}

	/* New event: build the kernel ABI struct and create via ioctl. */
	const auto *rule = event_rule_config.event_rule.get();
	auto abi_event = make_kernel_abi_event_from_event_rule(rule);

	const auto raw_event_fd =
		kernctl_create_event(runtime_channel.tracer_handle().fd(), abi_event);
	if (raw_event_fd < 0) {
		switch (-raw_event_fd) {
		case EEXIST:
			LTTNG_THROW_KERNEL_EVENT_ALREADY_EXISTS();
		case ENOSYS:
			LTTNG_THROW_KERNEL_EVENT_TYPE_UNSUPPORTED();
		case ENOENT:
			LTTNG_THROW_KERNEL_EVENT_ENABLE_FAILURE(
				fmt::format("Kernel event not found: `{}`", abi_event.name));
		default:
			LTTNG_THROW_POSIX("Failed to create kernel event", -raw_event_fd);
		}
	}

	lttng::file_descriptor event_fd(raw_event_fd);

	if (fcntl(event_fd.fd(), F_SETFD, FD_CLOEXEC) < 0) {
		LTTNG_THROW_POSIX("Failed to set FD_CLOEXEC on kernel event fd", errno);
	}

	/* Apply filter bytecode if present. */
	const auto *filter_bytecode = lttng_event_rule_get_filter_bytecode(rule);
	if (filter_bytecode) {
		const auto filter_ret = kernctl_filter(event_fd.fd(), filter_bytecode);
		if (filter_ret < 0) {
			switch (-filter_ret) {
			case ENOMEM:
				LTTNG_THROW_KERNEL_FILTER_OUT_OF_MEMORY();
			default:
				LTTNG_THROW_KERNEL_FILTER_INVALID();
			}
		}
	}

	/* Add callsites for userspace probe events. */
	if (lttng_event_rule_get_type(rule) == LTTNG_EVENT_RULE_TYPE_KERNEL_UPROBE) {
		LTTNG_ASSERT(_legacy_kernel_session);
		lttng_credentials creds = {};
		LTTNG_OPTIONAL_SET(&creds.uid, _legacy_kernel_session->uid);
		LTTNG_OPTIONAL_SET(&creds.gid, _legacy_kernel_session->gid);

		const auto callsite_ret =
			userspace_probe_event_rule_add_callsites(rule, &creds, event_fd.fd());
		if (callsite_ret) {
			LTTNG_THROW_KERNEL_EVENT_ENABLE_FAILURE(
				"Failed to add callsites to userspace probe event");
		}
	}

	/* Enable the event in the kernel tracer. */
	{
		const auto enable_ret = kernctl_enable(event_fd.fd());
		if (enable_ret < 0) {
			LTTNG_THROW_POSIX("Failed to enable kernel event", -enable_ret);
		}
	}

	DBG("Kernel event `%s` created (fd: %d) on channel `%s`",
	    abi_event.name,
	    event_fd.fd(),
	    channel_config.name.c_str());

	runtime_channel.add_event_rule(event_rule_config, std::move(event_fd));

	kernel_wait_quiescent();
}

void ls::modules::domain_orchestrator::disable_event(
	const lsc::recording_channel_configuration& channel_config,
	const lsc::event_rule_configuration& event_rule_config)
{
	auto& runtime_channel = _get_channel(channel_config);
	auto *runtime_event = runtime_channel.find_event_rule(event_rule_config);
	if (!runtime_event) {
		LTTNG_THROW_CTL("Failed to disable kernel event: no runtime event found for rule",
				LTTNG_ERR_KERN_DISABLE_FAIL);
	}

	const auto ret = kernctl_disable(runtime_event->tracer_handle().fd());
	if (ret < 0 && ret != -EEXIST) {
		LTTNG_THROW_POSIX("Failed to disable kernel event", -ret);
	}

	kernel_wait_quiescent();
}

void ls::modules::domain_orchestrator::add_context(
	const lsc::recording_channel_configuration& channel_config,
	const lsc::context_configuration& context_config)
{
	LTTNG_ASSERT(_legacy_kernel_session);

	auto& runtime_channel = _get_channel(channel_config);
	auto abi_ctx = make_kernel_abi_context(context_config);

	const auto ret = kernctl_add_context(runtime_channel.tracer_handle().fd(), abi_ctx);
	if (ret < 0) {
		if (ret == -ENOSYS) {
			LTTNG_THROW_CTL(
				fmt::format(
					"Failed to add context to kernel channel: context={}, channel=`{}`",
					context_config,
					channel_config.name),
				LTTNG_ERR_KERN_CONTEXT_UNAVAILABLE);
		} else if (ret == -EEXIST) {
			/* Context already exists on this channel; silently ignore. */
			return;
		}

		LTTNG_THROW_POSIX(
			fmt::format(
				"Failed to add context to kernel channel: context={}, channel=`{}`",
				context_config,
				channel_config.name),
			-ret);
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

unsigned int ls::modules::domain_orchestrator::_open_channel_streams(stream_group& channel)
{
	unsigned int streams_opened = 0;

	while (true) {
		const auto raw_stream_fd = kernctl_create_stream(channel.tracer_handle().fd());
		if (raw_stream_fd < 0) {
			/*
			 * ENOENT means all streams have been created for this
			 * channel (one per CPU, or one in per-channel mode).
			 */
			if (raw_stream_fd == -ENOENT) {
				break;
			}

			LTTNG_THROW_POSIX("Failed to create kernel stream", -raw_stream_fd);
		}

		lttng::file_descriptor stream_fd(raw_stream_fd);

		if (fcntl(stream_fd.fd(), F_SETFD, FD_CLOEXEC) < 0) {
			LTTNG_THROW_POSIX(
				"Failed to set FD_CLOEXEC on kernel stream file descriptor", errno);
		}

		const auto cpu = channel.stream_count();
		DBG_FMT("Kernel stream created: channel=`{}`, fd={}, cpu={}",
			channel.configuration().name,
			stream_fd.fd(),
			cpu);

		/*
		 * Also add the stream to the legacy struct for downstream code that
		 * still iterates ltt_kernel_channel::stream_list (hotplug handler
		 * thread, consumer send code).
		 */
		auto& legacy_channel =
			find_legacy_channel(*_legacy_kernel_session, channel.configuration());
		auto lks =
			lttng::make_unique_wrapper<ltt_kernel_stream, trace_kernel_destroy_stream>(
				trace_kernel_create_stream(channel.configuration().name.c_str(),
							   legacy_channel.stream_count));
		if (!lks) {
			LTTNG_THROW_ALLOCATION_FAILURE_ERROR(
				"Failed to allocate legacy ltt_kernel_stream");
		}

		lks->tracefile_size =
			channel.configuration().trace_file_size_limit_bytes.value_or(0);
		lks->tracefile_count = channel.configuration().trace_file_count_limit.value_or(0);
		/* Ownership transferred to the legacy channel list. */
		cds_list_add(&lks->list, &legacy_channel.stream_list.head);
		/* NOLINTNEXTLINE */
		lks.release();
		legacy_channel.stream_count++;

		channel.add_stream(cpu, std::move(stream_fd));
		streams_opened++;
	}

	return streams_opened;
}

void ls::modules::domain_orchestrator::_flush_channel_streams(const stream_group& channel) const
{
	DBG_FMT("Flushing kernel channel streams: channel=`{}`", channel.configuration().name);

	for (const auto& stream : channel.streams()) {
		DBG_FMT("Flushing kernel stream: fd={}", stream->handle.fd());

		const auto ret = kernctl_buffer_flush(stream->handle.fd());
		if (ret < 0) {
			WARN_FMT("Failed to flush kernel stream buffer: fd={}, ret={}",
				 stream->handle.fd(),
				 ret);
		}
	}
}

void ls::modules::domain_orchestrator::_open_metadata()
{
	LTTNG_ASSERT(!_metadata);

	const auto& metadata_config = _domain_configuration.metadata_channel();

	DBG("Opening kernel metadata channel");

	const auto kernel_channel = make_kernel_abi_channel(metadata_config);
	const auto raw_metadata_fd = kernctl_open_metadata(_tracer_session_fd.fd(), kernel_channel);
	if (raw_metadata_fd < 0) {
		LTTNG_THROW_POSIX("Failed to open kernel metadata channel", -raw_metadata_fd);
	}

	lttng::file_descriptor metadata_fd(raw_metadata_fd);

	if (fcntl(metadata_fd.fd(), F_SETFD, FD_CLOEXEC) < 0) {
		LTTNG_THROW_POSIX("Failed to set FD_CLOEXEC on kernel metadata channel fd", errno);
	}

	const auto consumer_key = allocate_next_kernel_stream_group_key();

	DBG_FMT("Kernel metadata channel opened: fd={}, consumer_key={}",
		metadata_fd.fd(),
		consumer_key);

	_metadata = lttng::make_unique<modules::metadata_stream_group>(
		std::move(metadata_fd), consumer_key, metadata_config);
}

void ls::modules::domain_orchestrator::_open_metadata_stream()
{
	LTTNG_ASSERT(_metadata);
	LTTNG_ASSERT(_metadata->stream_count() == 0);

	const auto raw_stream_fd = kernctl_create_stream(_metadata->tracer_handle().fd());
	if (raw_stream_fd < 0) {
		LTTNG_THROW_POSIX("Failed to create kernel metadata stream", -raw_stream_fd);
	}

	lttng::file_descriptor stream_fd(raw_stream_fd);

	if (fcntl(stream_fd.fd(), F_SETFD, FD_CLOEXEC) < 0) {
		LTTNG_THROW_POSIX("Failed to set FD_CLOEXEC on kernel metadata stream fd", errno);
	}

	DBG_FMT("Kernel metadata stream created: fd={}", stream_fd.fd());

	_metadata->add_stream(0 /* cpu: always 0 for metadata */, std::move(stream_fd));
}

void ls::modules::domain_orchestrator::_destroy_consumer_stream_group(consumer_socket& socket,
								      uint64_t consumer_key)
{
	DBG_FMT("Sending kernel consumer destroy stream group: key={}", consumer_key);

	struct lttcomm_consumer_msg msg = {};
	msg.cmd_type = LTTNG_CONSUMER_DESTROY_CHANNEL;
	msg.u.destroy_channel.key = consumer_key;

	const auto ret = consumer_send_msg(&socket, &msg);
	if (ret < 0) {
		WARN_FMT("Failed to send stream group destroy to consumer: key={}, ret={}",
			 consumer_key,
			 ret);
	}
}

void ls::modules::domain_orchestrator::_send_metadata_to_consumer(
	consumer_socket& socket, const consumer_output& consumer_output, bool monitor)
{
	LTTNG_ASSERT(_metadata);
	LTTNG_ASSERT(_metadata->stream_count() > 0);

	const auto& metadata_config = _metadata->configuration();

	auto metadata_stream_fd = _metadata->streams().front()->handle.fd();

	DBG_FMT("Sending metadata to kernel consumer: metadata_stream_fd={}", metadata_stream_fd);

	const auto output = metadata_config.buffer_consumption_backend ==
			lsc::channel_configuration::buffer_consumption_backend_t::MMAP ?
		LTTNG_EVENT_MMAP :
		LTTNG_EVENT_SPLICE;

	struct lttcomm_consumer_msg lkm = {};

	consumer_init_add_channel_comm_msg(&lkm,
					   _metadata->consumer_key(),
					   _legacy_kernel_session->id,
					   "",
					   consumer_output.net_seq_index,
					   metadata_config.name.c_str(),
					   1,
					   output,
					   CONSUMER_CHANNEL_TYPE_METADATA,
					   0,
					   0,
					   monitor,
					   0,
					   _legacy_kernel_session->is_live_session,
					   0,
					   _legacy_kernel_session->current_trace_chunk,
					   _legacy_kernel_session->trace_format);

	health_code_update();

	auto ret = consumer_send_channel(&socket, &lkm);
	if (ret < 0) {
		LTTNG_THROW_KERNEL_CONSUMER_SEND_FAILURE(
			"Failed to send kernel metadata channel to consumer");
	}

	health_code_update();

	/* Send the metadata stream. */
	consumer_init_add_stream_comm_msg(
		&lkm, _metadata->consumer_key(), metadata_stream_fd, 0 /* CPU: 0 for metadata. */);

	ret = consumer_send_stream(&socket, &lkm, &metadata_stream_fd, 1);
	if (ret < 0) {
		LTTNG_THROW_KERNEL_CONSUMER_SEND_FAILURE(
			"Failed to send kernel metadata stream to consumer");
	}

	_metadata->mark_sent_to_consumer();
	health_code_update();
}

void ls::modules::domain_orchestrator::_send_channel_to_consumer(consumer_socket& socket,
								 stream_group& channel,
								 bool monitor)
{
	LTTNG_ASSERT(_legacy_kernel_session);
	LTTNG_ASSERT(!channel.is_sent_to_consumer());

	const auto& channel_config = channel.configuration();

	DBG_FMT("Sending kernel channel to consumer: channel=`{}`", channel_config.name);

	const auto output = channel_config.buffer_consumption_backend ==
			lsc::channel_configuration::buffer_consumption_backend_t::MMAP ?
		LTTNG_EVENT_MMAP :
		LTTNG_EVENT_SPLICE;

	const auto is_local_trace = _consumer.net_seq_index == (uint64_t) -1ULL;

	std::size_t consumer_path_offset;
	auto pathname = lttng::make_unique_wrapper<char, lttng::memory::free>(
		setup_channel_trace_path(&_consumer, "", &consumer_path_offset));
	if (!pathname) {
		LTTNG_THROW_ALLOCATION_FAILURE_ERROR("Failed to allocate channel trace path");
	}

	if (is_local_trace && _legacy_kernel_session->current_trace_chunk) {
		std::string pathname_index = fmt::format("{}" DEFAULT_INDEX_DIR, pathname.get());

		/*
		 * Create the index subdirectory which will take care
		 * of implicitly creating the channel's path.
		 */
		const auto chunk_status = lttng_trace_chunk_create_subdirectory(
			_legacy_kernel_session->current_trace_chunk, pathname_index.c_str());
		if (chunk_status != LTTNG_TRACE_CHUNK_STATUS_OK) {
			LTTNG_THROW_ERROR(lttng::format(
				"Failed to create index subdirectory for channel `{}`",
				channel_config.name));
		}
	}

	lttcomm_consumer_msg lkm = {};
	consumer_init_add_channel_comm_msg(&lkm,
					   channel.consumer_key(),
					   _legacy_kernel_session->id,
					   &pathname.get()[consumer_path_offset],
					   _consumer.net_seq_index,
					   channel_config.name.c_str(),
					   channel.stream_count(),
					   output,
					   CONSUMER_CHANNEL_TYPE_DATA_PER_CPU,
					   channel_config.trace_file_size_limit_bytes.value_or(0),
					   channel_config.trace_file_count_limit.value_or(0),
					   monitor,
					   channel_config.live_timer_period_us.value_or(0),
					   _legacy_kernel_session->is_live_session,
					   channel_config.monitor_timer_period_us.value_or(0),
					   _legacy_kernel_session->current_trace_chunk,
					   _legacy_kernel_session->trace_format);

	health_code_update();

	auto ret = consumer_send_channel(&socket, &lkm);
	if (ret < 0) {
		LTTNG_THROW_KERNEL_CONSUMER_SEND_FAILURE(lttng::format(
			"Failed to send kernel channel `{}` to consumer", channel_config.name));
	}

	channel.mark_sent_to_consumer();
	health_code_update();

	/* Notify the notification thread of the new channel. */
	try {
		const auto session = ltt_session::find_session(_legacy_kernel_session->id);

		ASSERT_SESSION_LIST_LOCKED();

		const auto status = notification_thread_command_add_channel(
			the_notification_thread_handle,
			session->id,
			const_cast<char *>(channel_config.name.c_str()),
			channel.consumer_key(),
			LTTNG_DOMAIN_KERNEL,
			channel_config.subbuffer_size_bytes * channel_config.subbuffer_count);
		if (status != LTTNG_OK) {
			LTTNG_THROW_ERROR(lttng::format(
				"Failed to register channel `{}` with notification thread",
				channel_config.name));
		}
	} catch (const lttng::sessiond::exceptions::session_not_found_error& ex) {
		ERR_FMT("Fatal error during the creation of a kernel channel: {}, location='{}'",
			ex.what(),
			ex.source_location);
		abort();
	}

	channel.mark_published_to_notification_thread();

	/* Send all streams that have not been sent yet. */
	for (const auto& stream : channel.streams()) {
		auto& kstream = static_cast<stream_group::kernel_stream&>(*stream);

		LTTNG_ASSERT(!kstream.sent_to_consumer);

		DBG_FMT("Sending kernel stream to consumer: channel=`{}`, fd={}, cpu={}",
			channel_config.name,
			kstream.handle.fd(),
			kstream.cpu);

		std::memset(&lkm, 0, sizeof(lkm));
		consumer_init_add_stream_comm_msg(
			&lkm, channel.consumer_key(), kstream.handle.fd(), kstream.cpu);

		auto stream_fd = kstream.handle.fd();
		const auto send_ret = consumer_send_stream(&socket, &lkm, &stream_fd, 1);
		if (send_ret < 0) {
			LTTNG_THROW_KERNEL_CONSUMER_SEND_FAILURE(lttng::format(
				"Failed to send kernel stream to consumer: channel=`{}`, cpu={}",
				channel_config.name,
				kstream.cpu));
		}

		kstream.sent_to_consumer = true;

		health_code_update();
	}
}

void ls::modules::domain_orchestrator::_send_channels_to_consumer(consumer_socket& socket)
{
	LTTNG_ASSERT(_legacy_kernel_session);

	if (!_consumer.enabled) {
		return;
	}

	/* Don't monitor the streams on the consumer if in flight recorder. */
	const unsigned int monitor = _legacy_kernel_session->output_traces ? 1 : 0;

	DBG("Sending session stream to kernel consumer");

	if (_metadata && _metadata->stream_count() > 0) {
		_send_metadata_to_consumer(socket, _consumer, monitor);
	}

	/* Send channels and their streams. */
	for (auto& channel_entry : _channels) {
		auto& channel = *channel_entry.second;

		_send_channel_to_consumer(socket, channel, monitor);

		if (monitor) {
			/*
			 * Inform the relay that all the streams for the
			 * channel were sent.
			 */
			struct lttcomm_consumer_msg lkm = {};
			consumer_init_streams_sent_comm_msg(&lkm,
							    LTTNG_CONSUMER_STREAMS_SENT,
							    channel.consumer_key(),
							    _consumer.net_seq_index);

			health_code_update();

			const auto ret = consumer_send_msg(&socket, &lkm);
			if (ret < 0) {
				LTTNG_THROW_KERNEL_CONSUMER_SEND_FAILURE(lttng::format(
					"Failed to send streams_sent for channel `{}`",
					channel.configuration().name));
			}
		}
	}

	DBG("Kernel consumer FDs of metadata and channel streams sent");
	_legacy_kernel_session->consumer_fds_sent = 1;
}

void ls::modules::domain_orchestrator::start()
{
	LTTNG_ASSERT(_legacy_kernel_session);
	if (_active) {
		return;
	}

	DBG("Starting kernel tracing");

	/* Open kernel metadata if needed. */
	if (!_metadata && _legacy_kernel_session->output_traces) {
		_open_metadata();
	}

	/* Open kernel metadata stream if needed. */
	if (_metadata && _metadata->stream_count() == 0) {
		_open_metadata_stream();
	}

	/* Open streams for each channel that hasn't had streams created yet. */
	for (auto& channel_entry : _channels) {
		auto& channel = *channel_entry.second;

		if (channel.stream_count() == 0) {
			const auto new_streams = _open_channel_streams(channel);
			_legacy_kernel_session->stream_count_global += new_streams;
		}
	}

	/* Send session data (metadata, channels, streams) to the consumer daemon. */
	if (_legacy_kernel_session->consumer_fds_sent == 0 &&
	    _legacy_kernel_session->consumer != nullptr) {
		auto& kconsumer_socket = _get_consumer_socket();
		/* NOLINTNEXTLINE */
		const lttng::pthread::lock_guard socket_lock(*kconsumer_socket.lock);

		_send_channels_to_consumer(kconsumer_socket);
	}

	_legacy_kernel_session->active = true;
	_active = true;

	/* Register the channels for hotplug monitoring. */
	for (auto& channel_entry : _channels) {
		auto& channel = *channel_entry.second;

		if (channel.is_monitored_for_hotplug()) {
			continue;
		}

		hotplug_handler::command cmd(
			hotplug_handler::command_type::ADD_CHANNEL, channel, _session_id);
		_hotplug_queue.send_and_wait(std::move(cmd));

		channel.mark_monitored_for_hotplug();
	}

	/* Start kernel tracing. */
	const auto start_ret = kernel_start_session(_legacy_kernel_session);
	if (start_ret < 0) {
		LTTNG_THROW_KERNEL_START_FAILURE("Failed to start kernel tracing");
	}

	kernel_wait_quiescent();
}

void ls::modules::domain_orchestrator::stop()
{
	LTTNG_ASSERT(_legacy_kernel_session);

	if (!_active) {
		return;
	}

	DBG("Stopping kernel tracing");

	const auto stop_ret = kernel_stop_session(_legacy_kernel_session);
	if (stop_ret < 0) {
		LTTNG_THROW_KERNEL_STOP_FAILURE("Failed to stop kernel tracing");
	}

	kernel_wait_quiescent();

	/* Flush metadata buffer after stopping (if exists). */
	if (_metadata) {
		const auto ret = kernctl_buffer_flush((_metadata->streams().front())->handle.fd());
		if (ret < 0) {
			WARN("Failed to flush metadata stream");
		}
	}

	/* Flush all channel buffers after stopping. */
	for (const auto& channel_entry : _channels) {
		_flush_channel_streams(*channel_entry.second);
	}

	_legacy_kernel_session->active = false;
	_active = false;
}

consumer_socket& ls::modules::domain_orchestrator::_get_consumer_socket()
{
	lttng_ht_iter iter = {};
	lttng_ht_get_first(_consumer.socks, &iter);
	auto *node = cds_lfht_iter_get_node(&iter.iter);

	LTTNG_ASSERT(node);

	return *lttng::urcu::details::get_element_from_node<consumer_socket,
							    decltype(consumer_socket::node),
							    &consumer_socket::node>(*node);
}

void ls::modules::domain_orchestrator::rotate()
{
	LTTNG_ASSERT(_legacy_kernel_session);

	DBG("Rotate kernel session started");

	const lttng::urcu::read_lock_guard read_lock;
	auto& kconsumer_socket = _get_consumer_socket();

	/* For each channel, ask the consumer to rotate it. */
	for (const auto& channel_entry : _channels) {
		const auto stream_group_key = channel_entry.second->consumer_key();

		DBG_FMT("Rotate kernel channel: key={}", stream_group_key);
		const auto ret = consumer_rotate_channel(
			&kconsumer_socket, stream_group_key, &_consumer, false);
		if (ret < 0) {
			LTTNG_THROW_ROTATION_FAILURE("Failed to rotate kernel channel");
		}
	}

	/* Rotate the metadata channel. */
	LTTNG_ASSERT(_metadata);
	const auto ret = consumer_rotate_channel(
		&kconsumer_socket, _metadata->consumer_key(), &_consumer, true);
	if (ret < 0) {
		LTTNG_THROW_ROTATION_FAILURE("Failed to rotate kernel metadata channel");
	}
}

void ls::modules::domain_orchestrator::clear()
{
	LTTNG_ASSERT(_legacy_kernel_session);
	LTTNG_ASSERT(!_legacy_kernel_session->active);

	DBG("Clear kernel session started");

	const lttng::urcu::read_lock_guard read_lock;
	auto& kconsumer_socket = _get_consumer_socket();

	/* For each channel, ask the consumer to clear it. */
	for (const auto& channel_entry : _channels) {
		const auto stream_group_key = channel_entry.second->consumer_key();

		DBG_FMT("Clear kernel channel: key={}", stream_group_key);
		const auto ret = consumer_clear_channel(&kconsumer_socket, stream_group_key);
		if (ret < 0) {
			switch (-ret) {
			case LTTCOMM_CONSUMERD_RELAYD_CLEAR_DISALLOWED:
				LTTNG_THROW_CLEAR_RELAY_DISALLOWED(
					"Failed to clear kernel channel: relay daemon disallowed clear");
			default:
				LTTNG_THROW_CLEAR_FAILURE("Failed to clear kernel channel");
			}
		}
	}

	if (!_metadata) {
		/*
		 * Nothing to do for the metadata since this is a snapshot session;
		 * the metadata is generated on the fly.
		 */
		return;
	}

	/*
	 * Clear the metadata channel.
	 *
	 * Metadata channel is not cleared per se but we still need to perform a rotation operation
	 * on it behind the scene.
	 */
	const auto ret = consumer_clear_channel(&kconsumer_socket, _metadata->consumer_key());
	if (ret < 0) {
		switch (-ret) {
		case LTTCOMM_CONSUMERD_RELAYD_CLEAR_DISALLOWED:
			LTTNG_THROW_CLEAR_RELAY_DISALLOWED(
				"Failed to clear kernel metadata channel: relay daemon disallowed clear");
		default:
			LTTNG_THROW_CLEAR_FAILURE("Failed to clear kernel metadata channel");
		}
	}
}

void ls::modules::domain_orchestrator::open_packets()
{
	const lttng::urcu::read_lock_guard read_lock;
	auto& kconsumer_socket = _get_consumer_socket();

	for (const auto& channel_entry : _channels) {
		const auto channel_key = channel_entry.second->consumer_key();

		DBG_FMT("Open packet of kernel channel: key={}", channel_key);
		const auto open_ret = consumer_open_channel_packets(&kconsumer_socket, channel_key);
		if (open_ret < 0) {
			LTTNG_THROW_OPEN_PACKETS_FAILURE("Failed to open kernel channel packets");
		}
	}
}

void ls::modules::domain_orchestrator::record_snapshot(
	const struct consumer_output& snapshot_consumer, std::uint64_t nb_packets_per_stream)
{
	LTTNG_ASSERT(_legacy_kernel_session);
	LTTNG_ASSERT(_legacy_kernel_session->consumer);

	DBG("Kernel snapshot record started");

	_open_metadata();
	_open_metadata_stream();

	auto destroy_metadata_on_exit =
		lttng::make_scope_exit([&]() noexcept { _metadata.reset(); });

	std::size_t consumer_path_offset;
	auto trace_path =
		lttng::make_unique_wrapper<char, lttng::memory::free>(setup_channel_trace_path(
			_legacy_kernel_session->consumer, "", &consumer_path_offset));
	if (!trace_path) {
		LTTNG_THROW_ALLOCATION_FAILURE_ERROR("Failed to allocate trace path");
	}

	auto& kconsumer_socket = _get_consumer_socket();
	const auto snapshot_metadata_key = _metadata->consumer_key();

	{
		const lttng::pthread::lock_guard socket_lock(*kconsumer_socket.lock);

		/* This stream must not be monitored by the consumer. */
		_send_metadata_to_consumer(kconsumer_socket, snapshot_consumer, false);
	}

	const auto destroy_consumer_metadata_on_exit = lttng::make_scope_exit([&]() noexcept {
		const lttng::pthread::lock_guard socket_lock(*kconsumer_socket.lock);
		_destroy_consumer_stream_group(_get_consumer_socket(), snapshot_metadata_key);
	});

	/* For each channel, ask the consumer to snapshot it. */
	for (const auto& channel_entry : _channels) {
		const auto status =
			consumer_snapshot_channel(&kconsumer_socket,
						  channel_entry.second->consumer_key(),
						  &snapshot_consumer,
						  0,
						  &trace_path.get()[consumer_path_offset],
						  nb_packets_per_stream);
		if (status != LTTNG_OK) {
			LTTNG_THROW_SNAPSHOT_FAILURE("Failed to record kernel channel snapshot");
		}
	}

	/* Snapshot metadata. */
	const auto status = consumer_snapshot_channel(&kconsumer_socket,
						      snapshot_metadata_key,
						      &snapshot_consumer,
						      1,
						      &trace_path.get()[consumer_path_offset],
						      0);
	if (status != LTTNG_OK) {
		LTTNG_THROW_SNAPSHOT_FAILURE("Failed to record kernel metadata snapshot");
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

ls::recording_channel_runtime_stats
ls::modules::domain_orchestrator::get_recording_channel_runtime_stats(
	const lsc::recording_channel_configuration& channel_config) const
{
	const auto it = _channels.find(&channel_config);
	LTTNG_ASSERT(it != _channels.end());

	const auto channel_key = it->second->consumer_key();
	const auto session_id = _legacy_kernel_session->id;
	recording_channel_runtime_stats stats = {};
	int ret;

	ret = consumer_get_discarded_events(
		session_id, channel_key, _legacy_kernel_session->consumer, &stats.discarded_events);
	if (ret < 0) {
		LTTNG_THROW_ERROR(lttng::format(
			"Failed to get discarded events count from consumer for channel '{}'",
			channel_config.name));
	}

	ret = consumer_get_lost_packets(
		session_id, channel_key, _legacy_kernel_session->consumer, &stats.lost_packets);
	if (ret < 0) {
		LTTNG_THROW_ERROR(lttng::format(
			"Failed to get lost packets count from consumer for channel '{}'",
			channel_config.name));
	}

	return stats;
}

unsigned int ls::modules::domain_orchestrator::get_stream_count_for_channel(
	const lsc::recording_channel_configuration& channel_config) const
{
	const auto it = _channels.find(&channel_config);
	LTTNG_ASSERT(it != _channels.end());

	return it->second->stream_count();
}

void ls::modules::domain_orchestrator::handle_channel_hotplug(stream_group& channel)
{
	LTTNG_ASSERT(_legacy_kernel_session);

	const auto new_stream_count = _open_channel_streams(channel);
	if (new_stream_count == 0) {
		WARN_FMT(
			"Kernel channel hotplug event, but no new streams opened for channel: channel_name=`{}`",
			channel.configuration().name);
		return;
	}

	DBG_FMT("Kernel channel hotplug opened new streams: channel_name=`{}`, additional_streams_count={}, total_stream_count={}",
		channel.configuration().name,
		new_stream_count,
		channel.stream_count());

	_legacy_kernel_session->stream_count_global += new_stream_count;

	LTTNG_ASSERT(channel.is_sent_to_consumer());

	/* Send only the newly-opened (unsent) streams to the consumer daemon. */
	auto& kconsumer_socket = _get_consumer_socket();
	const lttng::pthread::lock_guard socket_lock(*kconsumer_socket.lock);
	const auto& channel_config = channel.configuration();

	for (const auto& stream : channel.streams()) {
		auto& kstream = static_cast<stream_group::kernel_stream&>(*stream);

		if (kstream.sent_to_consumer) {
			continue;
		}

		DBG_FMT("Sending hotplug kernel stream to consumer: channel=`{}`, fd={}, cpu={}",
			channel_config.name,
			kstream.handle.fd(),
			kstream.cpu);

		lttcomm_consumer_msg lkm = {};
		consumer_init_add_stream_comm_msg(
			&lkm, channel.consumer_key(), kstream.handle.fd(), kstream.cpu);

		auto stream_fd = kstream.handle.fd();
		const auto monitor = _legacy_kernel_session->output_traces ? 1 : 0;
		const auto send_ret =
			consumer_send_stream(&kconsumer_socket, &lkm, &stream_fd, monitor);
		if (send_ret < 0) {
			LTTNG_THROW_KERNEL_CONSUMER_SEND_FAILURE(lttng::format(
				"Failed to send hotplug kernel stream to consumer: channel=`{}`, cpu={}",
				channel_config.name,
				kstream.cpu));
		}

		kstream.sent_to_consumer = true;
	}
}
