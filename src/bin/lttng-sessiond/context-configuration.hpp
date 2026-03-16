/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_CONTEXT_CONFIGURATION_HPP
#define LTTNG_SESSIOND_CONTEXT_CONFIGURATION_HPP

#include <common/exception.hpp>
#include <common/format.hpp>

#include <lttng/event.h>

#include <vendor/optional.hpp>

#include <cstdint>
#include <memory>
#include <string>

namespace lttng {
namespace sessiond {
namespace config {

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

	bool operator==(const context_configuration& other) const noexcept;
	bool operator!=(const context_configuration& other) const noexcept;

	const type context_type;

protected:
	explicit context_configuration(type context_type_);
	virtual bool is_equal(const context_configuration& other) const noexcept = 0;
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

private:
	bool is_equal(const context_configuration& other) const noexcept override;
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

	bool operator==(const perf_counter_context_configuration& other) const noexcept;
	bool operator!=(const perf_counter_context_configuration& other) const noexcept;

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

private:
	bool is_equal(const context_configuration& other) const noexcept override;
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

	bool operator==(const app_context_configuration& other) const noexcept;
	bool operator!=(const app_context_configuration& other) const noexcept;

	/*
	 * Name of the context provider (application or library providing the context).
	 */
	const std::string provider_name;
	/*
	 * Name of the context within the provider's namespace.
	 */
	const std::string context_name;

private:
	bool is_equal(const context_configuration& other) const noexcept override;
};

/*
 * Create a context_configuration from an lttng_event_context.
 *
 * Throws lttng::invalid_argument_error if the context type is unknown or invalid.
 */
context_configuration::uptr
make_context_configuration_from_event_context(const lttng_event_context& event_context);

} /* namespace config */
} /* namespace sessiond */
} /* namespace lttng */

/*
 * Specialize fmt::formatter for context_configuration::type.
 *
 * Due to a bug in g++ < 7.1, this specialization must be enclosed in the fmt namespace,
 * see https://gcc.gnu.org/bugzilla/show_bug.cgi?id=56480.
 */
namespace fmt {
template <>
struct formatter<lttng::sessiond::config::context_configuration::type> : formatter<std::string> {
	template <typename FormatContextType>
	typename FormatContextType::iterator
	format(lttng::sessiond::config::context_configuration::type context_type,
	       FormatContextType& ctx) const
	{
		const char *name;

		switch (context_type) {
		case lttng::sessiond::config::context_configuration::type::PID:
			name = "PID";
			break;
		case lttng::sessiond::config::context_configuration::type::VPID:
			name = "VPID";
			break;
		case lttng::sessiond::config::context_configuration::type::TID:
			name = "TID";
			break;
		case lttng::sessiond::config::context_configuration::type::VTID:
			name = "VTID";
			break;
		case lttng::sessiond::config::context_configuration::type::PPID:
			name = "PPID";
			break;
		case lttng::sessiond::config::context_configuration::type::VPPID:
			name = "VPPID";
			break;
		case lttng::sessiond::config::context_configuration::type::PTHREAD_ID:
			name = "PTHREAD_ID";
			break;
		case lttng::sessiond::config::context_configuration::type::PROCNAME:
			name = "PROCNAME";
			break;
		case lttng::sessiond::config::context_configuration::type::PRIO:
			name = "PRIO";
			break;
		case lttng::sessiond::config::context_configuration::type::NICE:
			name = "NICE";
			break;
		case lttng::sessiond::config::context_configuration::type::INTERRUPTIBLE:
			name = "INTERRUPTIBLE";
			break;
		case lttng::sessiond::config::context_configuration::type::PREEMPTIBLE:
			name = "PREEMPTIBLE";
			break;
		case lttng::sessiond::config::context_configuration::type::NEED_RESCHEDULE:
			name = "NEED_RESCHEDULE";
			break;
		case lttng::sessiond::config::context_configuration::type::MIGRATABLE:
			name = "MIGRATABLE";
			break;
		case lttng::sessiond::config::context_configuration::type::HOSTNAME:
			name = "HOSTNAME";
			break;
		case lttng::sessiond::config::context_configuration::type::CPU_ID:
			name = "CPU_ID";
			break;
		case lttng::sessiond::config::context_configuration::type::CGROUP_NS:
			name = "CGROUP_NS";
			break;
		case lttng::sessiond::config::context_configuration::type::IPC_NS:
			name = "IPC_NS";
			break;
		case lttng::sessiond::config::context_configuration::type::MNT_NS:
			name = "MNT_NS";
			break;
		case lttng::sessiond::config::context_configuration::type::NET_NS:
			name = "NET_NS";
			break;
		case lttng::sessiond::config::context_configuration::type::PID_NS:
			name = "PID_NS";
			break;
		case lttng::sessiond::config::context_configuration::type::USER_NS:
			name = "USER_NS";
			break;
		case lttng::sessiond::config::context_configuration::type::UTS_NS:
			name = "UTS_NS";
			break;
		case lttng::sessiond::config::context_configuration::type::TIME_NS:
			name = "TIME_NS";
			break;
		case lttng::sessiond::config::context_configuration::type::UID:
			name = "UID";
			break;
		case lttng::sessiond::config::context_configuration::type::EUID:
			name = "EUID";
			break;
		case lttng::sessiond::config::context_configuration::type::SUID:
			name = "SUID";
			break;
		case lttng::sessiond::config::context_configuration::type::GID:
			name = "GID";
			break;
		case lttng::sessiond::config::context_configuration::type::EGID:
			name = "EGID";
			break;
		case lttng::sessiond::config::context_configuration::type::SGID:
			name = "SGID";
			break;
		case lttng::sessiond::config::context_configuration::type::VUID:
			name = "VUID";
			break;
		case lttng::sessiond::config::context_configuration::type::VEUID:
			name = "VEUID";
			break;
		case lttng::sessiond::config::context_configuration::type::VSUID:
			name = "VSUID";
			break;
		case lttng::sessiond::config::context_configuration::type::VGID:
			name = "VGID";
			break;
		case lttng::sessiond::config::context_configuration::type::VEGID:
			name = "VEGID";
			break;
		case lttng::sessiond::config::context_configuration::type::VSGID:
			name = "VSGID";
			break;
		case lttng::sessiond::config::context_configuration::type::CALLSTACK_KERNEL:
			name = "CALLSTACK_KERNEL";
			break;
		case lttng::sessiond::config::context_configuration::type::CALLSTACK_USER:
			name = "CALLSTACK_USER";
			break;
		case lttng::sessiond::config::context_configuration::type::IP:
			name = "IP";
			break;
		case lttng::sessiond::config::context_configuration::type::PERF_CPU_COUNTER:
			name = "PERF_CPU_COUNTER";
			break;
		case lttng::sessiond::config::context_configuration::type::PERF_THREAD_COUNTER:
			name = "PERF_THREAD_COUNTER";
			break;
		case lttng::sessiond::config::context_configuration::type::APP_CONTEXT:
			name = "APP_CONTEXT";
			break;
		default:
			name = "UNKNOWN";
			break;
		}

		return format_to(ctx.out(), name);
	}
};
template <>
struct formatter<lttng::sessiond::config::context_configuration> : formatter<std::string> {
	template <typename FormatContextType>
	typename FormatContextType::iterator
	format(const lttng::sessiond::config::context_configuration& config,
	       FormatContextType& ctx) const
	{
		namespace lsc = lttng::sessiond::config;

		const auto *perf =
			dynamic_cast<const lsc::perf_counter_context_configuration *>(&config);
		if (perf) {
			return format_to(ctx.out(),
					 "{}(name=`{}`, perf_type={}, perf_config={})",
					 config.context_type,
					 perf->name,
					 static_cast<unsigned int>(perf->perf_type),
					 perf->perf_config);
		}

		const auto *app = dynamic_cast<const lsc::app_context_configuration *>(&config);
		if (app) {
			return format_to(ctx.out(),
					 "{}(provider=`{}`, context=`{}`)",
					 config.context_type,
					 app->provider_name,
					 app->context_name);
		}

		return format_to(ctx.out(), "{}", config.context_type);
	}
};
} /* namespace fmt */

#endif /* LTTNG_SESSIOND_CONTEXT_CONFIGURATION_HPP */
