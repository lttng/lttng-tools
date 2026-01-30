/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "context-configuration.hpp"

#include <common/make-unique.hpp>

#include <utility>

namespace lttng {
namespace sessiond {

namespace {
context_configuration::type
event_context_type_to_context_configuration_type(lttng_event_context_type ctx_type)
{
	switch (ctx_type) {
	case LTTNG_EVENT_CONTEXT_PID:
		return context_configuration::type::PID;
	case LTTNG_EVENT_CONTEXT_VPID:
		return context_configuration::type::VPID;
	case LTTNG_EVENT_CONTEXT_TID:
		return context_configuration::type::TID;
	case LTTNG_EVENT_CONTEXT_VTID:
		return context_configuration::type::VTID;
	case LTTNG_EVENT_CONTEXT_PPID:
		return context_configuration::type::PPID;
	case LTTNG_EVENT_CONTEXT_VPPID:
		return context_configuration::type::VPPID;
	case LTTNG_EVENT_CONTEXT_PTHREAD_ID:
		return context_configuration::type::PTHREAD_ID;
	case LTTNG_EVENT_CONTEXT_PROCNAME:
		return context_configuration::type::PROCNAME;
	case LTTNG_EVENT_CONTEXT_PRIO:
		return context_configuration::type::PRIO;
	case LTTNG_EVENT_CONTEXT_NICE:
		return context_configuration::type::NICE;
	case LTTNG_EVENT_CONTEXT_INTERRUPTIBLE:
		return context_configuration::type::INTERRUPTIBLE;
	case LTTNG_EVENT_CONTEXT_PREEMPTIBLE:
		return context_configuration::type::PREEMPTIBLE;
	case LTTNG_EVENT_CONTEXT_NEED_RESCHEDULE:
		return context_configuration::type::NEED_RESCHEDULE;
	case LTTNG_EVENT_CONTEXT_MIGRATABLE:
		return context_configuration::type::MIGRATABLE;
	case LTTNG_EVENT_CONTEXT_HOSTNAME:
		return context_configuration::type::HOSTNAME;
	case LTTNG_EVENT_CONTEXT_CPU_ID:
		return context_configuration::type::CPU_ID;
	case LTTNG_EVENT_CONTEXT_CGROUP_NS:
		return context_configuration::type::CGROUP_NS;
	case LTTNG_EVENT_CONTEXT_IPC_NS:
		return context_configuration::type::IPC_NS;
	case LTTNG_EVENT_CONTEXT_MNT_NS:
		return context_configuration::type::MNT_NS;
	case LTTNG_EVENT_CONTEXT_NET_NS:
		return context_configuration::type::NET_NS;
	case LTTNG_EVENT_CONTEXT_PID_NS:
		return context_configuration::type::PID_NS;
	case LTTNG_EVENT_CONTEXT_USER_NS:
		return context_configuration::type::USER_NS;
	case LTTNG_EVENT_CONTEXT_UTS_NS:
		return context_configuration::type::UTS_NS;
	case LTTNG_EVENT_CONTEXT_TIME_NS:
		return context_configuration::type::TIME_NS;
	case LTTNG_EVENT_CONTEXT_UID:
		return context_configuration::type::UID;
	case LTTNG_EVENT_CONTEXT_EUID:
		return context_configuration::type::EUID;
	case LTTNG_EVENT_CONTEXT_SUID:
		return context_configuration::type::SUID;
	case LTTNG_EVENT_CONTEXT_GID:
		return context_configuration::type::GID;
	case LTTNG_EVENT_CONTEXT_EGID:
		return context_configuration::type::EGID;
	case LTTNG_EVENT_CONTEXT_SGID:
		return context_configuration::type::SGID;
	case LTTNG_EVENT_CONTEXT_VUID:
		return context_configuration::type::VUID;
	case LTTNG_EVENT_CONTEXT_VEUID:
		return context_configuration::type::VEUID;
	case LTTNG_EVENT_CONTEXT_VSUID:
		return context_configuration::type::VSUID;
	case LTTNG_EVENT_CONTEXT_VGID:
		return context_configuration::type::VGID;
	case LTTNG_EVENT_CONTEXT_VEGID:
		return context_configuration::type::VEGID;
	case LTTNG_EVENT_CONTEXT_VSGID:
		return context_configuration::type::VSGID;
	case LTTNG_EVENT_CONTEXT_CALLSTACK_KERNEL:
		return context_configuration::type::CALLSTACK_KERNEL;
	case LTTNG_EVENT_CONTEXT_CALLSTACK_USER:
		return context_configuration::type::CALLSTACK_USER;
	case LTTNG_EVENT_CONTEXT_IP:
		return context_configuration::type::IP;
	case LTTNG_EVENT_CONTEXT_PERF_CPU_COUNTER:
		return context_configuration::type::PERF_CPU_COUNTER;
	case LTTNG_EVENT_CONTEXT_PERF_THREAD_COUNTER:
		return context_configuration::type::PERF_THREAD_COUNTER;
	case LTTNG_EVENT_CONTEXT_APP_CONTEXT:
		return context_configuration::type::APP_CONTEXT;
	case LTTNG_EVENT_CONTEXT_PERF_COUNTER:
		/* Legacy, treated as per-CPU counter. */
		return context_configuration::type::PERF_CPU_COUNTER;
	default:
		LTTNG_THROW_INVALID_ARGUMENT_ERROR("Unknown context type");
	}
}
} /* anonymous namespace */

context_configuration::context_configuration(type context_type_) : context_type(context_type_)
{
}

simple_context_configuration::simple_context_configuration(type context_type_) :
	context_configuration(context_type_)
{
}

perf_counter_context_configuration::perf_counter_context_configuration(
	type context_type_,
	perf_counter_context_configuration::perf_counter_type perf_type_,
	std::uint64_t perf_config_,
	std::string name_) :
	context_configuration(context_type_),
	perf_type(perf_type_),
	perf_config(perf_config_),
	name(std::move(name_))
{
}

app_context_configuration::app_context_configuration(std::string provider_name_,
						     std::string context_name_) :
	context_configuration(type::APP_CONTEXT),
	provider_name(std::move(provider_name_)),
	context_name(std::move(context_name_))
{
}

context_configuration::uptr
make_context_configuration_from_event_context(const lttng_event_context& event_context)
{
	const auto ctx_type = event_context_type_to_context_configuration_type(event_context.ctx);

	switch (event_context.ctx) {
	case LTTNG_EVENT_CONTEXT_PERF_COUNTER:
	case LTTNG_EVENT_CONTEXT_PERF_CPU_COUNTER:
	case LTTNG_EVENT_CONTEXT_PERF_THREAD_COUNTER:
	{
		const auto& perf_ctx = event_context.u.perf_counter;
		const auto perf_type =
			static_cast<perf_counter_context_configuration::perf_counter_type>(
				perf_ctx.type);

		return lttng::make_unique<perf_counter_context_configuration>(
			ctx_type, perf_type, perf_ctx.config, perf_ctx.name);
	}
	case LTTNG_EVENT_CONTEXT_APP_CONTEXT:
	{
		const auto& app_ctx = event_context.u.app_ctx;

		return lttng::make_unique<app_context_configuration>(
			app_ctx.provider_name ? app_ctx.provider_name : "",
			app_ctx.ctx_name ? app_ctx.ctx_name : "");
	}
	default:
		/* Simple context - no extra data needed. */
		return lttng::make_unique<simple_context_configuration>(ctx_type);
	}
}

} /* namespace sessiond */
} /* namespace lttng */
