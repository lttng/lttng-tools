/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_CONTEXT_CONFIGURATION_HPP
#define LTTNG_SESSIOND_CONTEXT_CONFIGURATION_HPP

#include <common/exception.hpp>

#include <lttng/event.h>

#include <vendor/optional.hpp>

#include <cstdint>
#include <memory>
#include <string>

namespace lttng {
namespace sessiond {

/*
 * Base class for context configurations attached to a recording channel.
 *
 * Contexts add supplementary information to each event record in a channel,
 * such as process ID, thread ID, or performance counters.
 */
class context_configuration {
public:
	using uptr = std::unique_ptr<context_configuration>;

	enum class type {
		/* Process/thread identification */
		PID,
		VPID,
		TID,
		VTID,
		PPID,
		VPPID,
		PTHREAD_ID,
		PROCNAME,

		/* Scheduling */
		PRIO,
		NICE,
		INTERRUPTIBLE,
		PREEMPTIBLE,
		NEED_RESCHEDULE,
		MIGRATABLE,

		/* System */
		HOSTNAME,
		CPU_ID,

		/* Namespaces */
		CGROUP_NS,
		IPC_NS,
		MNT_NS,
		NET_NS,
		PID_NS,
		USER_NS,
		UTS_NS,
		TIME_NS,

		/* User/group IDs */
		UID,
		EUID,
		SUID,
		GID,
		EGID,
		SGID,
		VUID,
		VEUID,
		VSUID,
		VGID,
		VEGID,
		VSGID,

		/* Execution context */
		CALLSTACK_KERNEL,
		CALLSTACK_USER,
		IP,

		/* Perf counters */
		PERF_CPU_COUNTER,
		PERF_THREAD_COUNTER,

		/* Application context */
		APP_CONTEXT,
	};

	virtual ~context_configuration() = default;
	context_configuration(const context_configuration&) = delete;
	context_configuration(context_configuration&&) = delete;
	context_configuration& operator=(const context_configuration&) = delete;
	context_configuration& operator=(context_configuration&&) = delete;

	const type context_type;

protected:
	explicit context_configuration(type context_type_);
};

/*
 * Simple context configuration for contexts that only require a type identifier.
 *
 * This covers most built-in contexts: process/thread IDs, namespaces, user/group IDs, etc.
 * No additional data beyond the type is needed.
 */
class simple_context_configuration final : public context_configuration {
public:
	explicit simple_context_configuration(type context_type_);
};

/*
 * Perf counter context configuration.
 *
 * Adds a Linux perf counter value to each event record. The base class's
 * context_type indicates whether this is per-CPU (type::PERF_CPU_COUNTER)
 * or per-thread (type::PERF_THREAD_COUNTER).
 */
class perf_counter_context_configuration final : public context_configuration {
public:
	/*
	 * Linux perf counter type.
	 */
	enum class perf_counter_type {
		HARDWARE = 0,
		SOFTWARE = 1,
		HARDWARE_CACHE = 3,
		PMU = 4,
	};

	perf_counter_context_configuration(type context_type_,
					   perf_counter_type perf_type_,
					   std::uint64_t perf_config_,
					   std::string name_);

	/*
	 * Type of perf counter (hardware, software, cache, or PMU).
	 */
	const perf_counter_type perf_type;
	/*
	 * perf counter configuration, interpretation depends on perf_type.
	 */
	const std::uint64_t perf_config;
	/*
	 * Name of the context field as it will appear in the trace.
	 */
	const std::string name;
};

/*
 * Application-specific context configuration.
 *
 * Allows applications to provide custom context values through the
 * lttng-ust context provider mechanism.
 */
class app_context_configuration final : public context_configuration {
public:
	app_context_configuration(std::string provider_name_, std::string context_name_);

	/*
	 * Name of the context provider (application or library providing the context).
	 */
	const std::string provider_name;
	/*
	 * Name of the context within the provider's namespace.
	 */
	const std::string context_name;
};

/*
 * Create a context_configuration from an lttng_event_context.
 *
 * Throws lttng::invalid_argument_error if the context type is unknown or invalid.
 */
context_configuration::uptr
make_context_configuration_from_event_context(const lttng_event_context& event_context);

} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_SESSIOND_CONTEXT_CONFIGURATION_HPP */
