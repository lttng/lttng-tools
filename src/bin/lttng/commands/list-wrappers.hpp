/*
 * SPDX-FileCopyrightText: 2025 EfficiOS Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef _LTTNG_LIST_WRAPPERS_HPP
#define _LTTNG_LIST_WRAPPERS_HPP

#include "list-common.hpp"

#include <common/exception.hpp>
#include <common/make-unique-wrapper.hpp>
#include <common/string-utils/c-string-view.hpp>

#include <lttng/lttng.h>

#include <vendor/optional.hpp>

#include <cstdint>
#include <cstring>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace lttng {
namespace cli {
namespace internal {

/*
 * Compares two C string views, like std::strcmp(), but also considering
 * one or both could be `nullptr`.
 */
inline int compare_c_string_views(const c_string_view lhs, const c_string_view rhs) noexcept
{
	if (lhs.data() == nullptr && rhs.data() == nullptr) {
		return 0;
	} else if (lhs.data() == nullptr) {
		return -1;
	} else if (rhs.data() == nullptr) {
		return 1;
	}

	return std::strcmp(lhs.data(), rhs.data());
}

} /* namespace internal */

class kernel_tracepoint;
class kernel_syscall;
class ust_tracepoint;
class java_python_logger;

/*
 * Holds information about an instrumentation point.
 *
 * Doesn't own the wrapped library pointer.
 */
class instrumentation_point {
public:
	explicit instrumentation_point(const lttng_event& lib_event) : _lib_event(&lib_event)
	{
	}

	c_string_view name() const noexcept
	{
		return _lib_event->name;
	}

	const lttng_event& lib() const noexcept
	{
		return *_lib_event;
	}

	bool operator<(const instrumentation_point& other) const noexcept
	{
		return internal::compare_c_string_views(name(), other.name()) < 0;
	}

private:
	const lttng_event *_lib_event;
};

/*
 * Holds information about a Linux kernel tracepoint.
 *
 * Doesn't own the wrapped library pointer.
 */
class kernel_tracepoint final : public instrumentation_point {
public:
	explicit kernel_tracepoint(const lttng_event& lib_event) : instrumentation_point(lib_event)
	{
	}
};

/*
 * Holds information about a Linux kernel system call.
 *
 * Doesn't own the wrapped library pointer.
 */
class kernel_syscall final : public instrumentation_point {
public:
	explicit kernel_syscall(const lttng_event& lib_event) : instrumentation_point(lib_event)
	{
	}

	bool is_32_bit() const noexcept
	{
		return (lib().flags & LTTNG_EVENT_FLAG_SYSCALL_32) != 0;
	}

	bool is_64_bit() const noexcept
	{
		return (lib().flags & LTTNG_EVENT_FLAG_SYSCALL_64) != 0;
	}

	bool operator<(const kernel_syscall& other) const noexcept
	{
		/* Compare names first */
		{
			const auto name_cmp =
				internal::compare_c_string_views(name(), other.name());

			if (name_cmp != 0) {
				return name_cmp < 0;
			}
		}

		/* Compare bitness */
		if (is_32_bit() != other.is_32_bit()) {
			return is_32_bit();
		} else if (is_64_bit() != other.is_64_bit()) {
			return is_64_bit();
		}

		return false;
	}
};

/*
 * Holds information about a tracepoint field.
 *
 * Doesn't own the wrapped library pointer.
 */
class tracepoint_field final {
public:
	explicit tracepoint_field(const lttng_event_field& lib_field) : _lib_field(&lib_field)
	{
	}

	c_string_view name() const noexcept
	{
		return _lib_field->field_name;
	}

	lttng_event_field_type type() const noexcept
	{
		return _lib_field->type;
	}

	bool is_no_write() const noexcept
	{
		return _lib_field->nowrite != 0;
	}

	const lttng_event_field& lib() const noexcept
	{
		return *_lib_field;
	}

	bool operator<(const tracepoint_field& other) const noexcept
	{
		return internal::compare_c_string_views(name(), other.name()) < 0;
	}

private:
	const lttng_event_field *_lib_field;
};

namespace internal {

/*
 * Wraps get_cmdline_by_pid().
 */
inline nonstd::optional<std::string> pid_cmdline(const pid_t pid)
{
	const auto raw = get_cmdline_by_pid(pid);

	if (raw) {
		std::string result(raw);
		std::free(raw);
		return result;
	}

	return nonstd::nullopt;
}

} /* namespace internal */

using tracepoint_field_set = std::set<tracepoint_field>;

/*
 * Holds information about a UST tracepoint.
 *
 * Doesn't own the wrapped library pointer.
 */
class ust_tracepoint final : public instrumentation_point {
public:
	explicit ust_tracepoint(const lttng_event& lib_event, tracepoint_field_set fields) :
		instrumentation_point(lib_event), _fields(std::move(fields))
	{
	}

	int log_level() const noexcept
	{
		return lib().loglevel;
	}

	pid_t pid() const noexcept
	{
		return lib().pid;
	}

	nonstd::optional<std::string> cmdline() const
	{
		return internal::pid_cmdline(pid());
	}

	const tracepoint_field_set& fields() const noexcept
	{
		return _fields;
	}

	bool operator<(const ust_tracepoint& other) const noexcept
	{
		if (pid() != other.pid()) {
			return pid() < other.pid();
		}

		return internal::compare_c_string_views(name(), other.name()) < 0;
	}

private:
	tracepoint_field_set _fields;
};

/*
 * Holds information about a Java/Python logger (`java.util.logging`,
 * log4j 1.x, Log4j 2, Python).
 */
class java_python_logger final : public instrumentation_point {
public:
	explicit java_python_logger(const lttng_event& lib_event) : instrumentation_point(lib_event)
	{
	}

	pid_t pid() const noexcept
	{
		return lib().pid;
	}

	nonstd::optional<std::string> cmdline() const
	{
		return internal::pid_cmdline(pid());
	}
};

/*
 * Base class template for instrumentation point sets.
 *
 * Manages an `lttng_event` array and provides common
 * container operations.
 */
template <typename ElementType>
class instrumentation_point_set {
public:
	instrumentation_point_set(const instrumentation_point_set&) = delete;
	instrumentation_point_set& operator=(const instrumentation_point_set&) = delete;

	const std::set<ElementType>& set() const noexcept
	{
		return _set;
	}

	typename std::set<ElementType>::const_iterator begin() const noexcept
	{
		return _set.begin();
	}

	typename std::set<ElementType>::const_iterator end() const noexcept
	{
		return _set.end();
	}

	std::size_t size() const noexcept
	{
		return _set.size();
	}

	bool is_empty() const noexcept
	{
		return _set.empty();
	}

protected:
	instrumentation_point_set() = default;

	instrumentation_point_set(instrumentation_point_set&& other) noexcept :
		_set(std::move(other._set)), _lib_events(other._lib_events)
	{
		other._lib_events = nullptr;
	}

	instrumentation_point_set& operator=(instrumentation_point_set&& other) noexcept
	{
		if (this != &other) {
			std::free(_lib_events);
			_set = std::move(other._set);
			_lib_events = other._lib_events;
			other._lib_events = nullptr;
		}

		return *this;
	}

	~instrumentation_point_set()
	{
		std::free(_lib_events);
	}

	std::set<ElementType> _set;
	lttng_event *_lib_events = nullptr;
};

/*
 * Holds information about Linux kernel tracepoints.
 *
 * Upon construction, the instance takes a snapshot of the available
 * Linux kernel tracepoints.
 */
class kernel_tracepoint_set final : public instrumentation_point_set<kernel_tracepoint> {
public:
	kernel_tracepoint_set()
	{
		lttng_domain lib_domain;

		std::memset(&lib_domain, 0, sizeof(lib_domain));
		lib_domain.type = LTTNG_DOMAIN_KERNEL;

		const auto lib_handle = lttng_create_handle(nullptr, &lib_domain);

		if (!lib_handle) {
			LTTNG_THROW_ERROR("Failed to create handle for Linux kernel domain");
		}

		const auto count = lttng_list_tracepoints(lib_handle, &_lib_events);

		lttng_destroy_handle(lib_handle);

		if (count < 0) {
			LTTNG_THROW_ERROR("Failed to list Linux kernel tracepoints");
		}

		LTTNG_ASSERT(count == 0 || _lib_events);

		for (auto i = 0U; i < static_cast<unsigned int>(count); ++i) {
			_set.emplace(_lib_events[i]);
		}
	}

	kernel_tracepoint_set(const kernel_tracepoint_set&) = delete;
	kernel_tracepoint_set& operator=(const kernel_tracepoint_set&) = delete;
	kernel_tracepoint_set(kernel_tracepoint_set&&) noexcept = default;
	kernel_tracepoint_set& operator=(kernel_tracepoint_set&&) noexcept = default;
	~kernel_tracepoint_set() = default;
};

/*
 * Holds information about Linux kernel system calls.
 *
 * Upon construction, the instance takes a snapshot of the available
 * Linux system calls.
 */
class kernel_syscall_set final : public instrumentation_point_set<kernel_syscall> {
public:
	kernel_syscall_set(const kernel_syscall_set&) = delete;
	kernel_syscall_set& operator=(const kernel_syscall_set&) = delete;

	kernel_syscall_set()
	{
		const auto count = lttng_list_syscalls(&_lib_events);

		if (count < 0) {
			LTTNG_THROW_ERROR("Failed to list Linux kernel syscalls");
		}

		LTTNG_ASSERT(count == 0 || _lib_events);

		for (auto i = 0U; i < static_cast<unsigned int>(count); ++i) {
			_set.emplace(_lib_events[i]);
		}
	}

	kernel_syscall_set(kernel_syscall_set&&) noexcept = default;
	kernel_syscall_set& operator=(kernel_syscall_set&&) noexcept = default;
	~kernel_syscall_set() = default;
};

/*
 * Holds information about Java/Python loggers.
 *
 * Upon construction, the instance takes a snapshot of the available
 * Java/Python loggers.
 */
class java_python_logger_set final : public instrumentation_point_set<java_python_logger> {
public:
	java_python_logger_set(const java_python_logger_set&) = delete;
	java_python_logger_set& operator=(const java_python_logger_set&) = delete;
	~java_python_logger_set() = default;

	explicit java_python_logger_set(const lttng_domain_type domain_type)
	{
		lttng_domain lib_domain;

		std::memset(&lib_domain, 0, sizeof(lib_domain));
		lib_domain.type = domain_type;

		const auto lib_handle = lttng_create_handle(nullptr, &lib_domain);

		if (!lib_handle) {
			LTTNG_THROW_ERROR("Failed to create handle for an agent domain");
		}

		const auto count = lttng_list_tracepoints(lib_handle, &_lib_events);

		lttng_destroy_handle(lib_handle);

		if (count < 0) {
			LTTNG_THROW_ERROR("Failed to list agent loggers");
		}

		LTTNG_ASSERT(count == 0 || _lib_events);

		for (auto i = 0U; i < static_cast<unsigned int>(count); ++i) {
			_set.emplace(_lib_events[i]);
		}
	}

	java_python_logger_set(java_python_logger_set&&) noexcept = default;
	java_python_logger_set& operator=(java_python_logger_set&&) noexcept = default;
};

/*
 * Holds information about UST tracepoints.
 *
 * Upon construction, the instance takes a snapshot of the available
 * UST tracepoints.
 */
class ust_tracepoint_set final : public instrumentation_point_set<ust_tracepoint> {
public:
	ust_tracepoint_set()
	{
		const auto event_count = _list_lib_events();
		const auto field_count = _list_lib_fields();

		LTTNG_ASSERT(event_count == 0 || _lib_events);
		LTTNG_ASSERT(field_count == 0 || _lib_fields);
		_build_tracepoints(event_count, field_count);
	}

	ust_tracepoint_set(const ust_tracepoint_set&) = delete;
	ust_tracepoint_set& operator=(const ust_tracepoint_set&) = delete;

	ust_tracepoint_set(ust_tracepoint_set&& other) noexcept :
		instrumentation_point_set(std::move(other)), _lib_fields(other._lib_fields)
	{
		other._lib_fields = nullptr;
	}

	ust_tracepoint_set& operator=(ust_tracepoint_set&& other) noexcept
	{
		if (this != &other) {
			instrumentation_point_set::operator=(std::move(other));
			std::free(_lib_fields);
			_lib_fields = other._lib_fields;
			other._lib_fields = nullptr;
		}

		return *this;
	}

	~ust_tracepoint_set()
	{
		std::free(_lib_fields);
	}

private:
	using _event_key_t = std::pair<pid_t, std::string>;

	static lttng_handle *_create_ust_handle()
	{
		lttng_domain lib_domain;

		std::memset(&lib_domain, 0, sizeof(lib_domain));
		lib_domain.type = LTTNG_DOMAIN_UST;

		const auto lib_handle = lttng_create_handle(nullptr, &lib_domain);

		if (!lib_handle) {
			LTTNG_THROW_ERROR("Failed to create handle for UST domain");
		}

		return lib_handle;
	}

	int _list_lib_events()
	{
		const auto lib_handle = _create_ust_handle();
		const auto count = lttng_list_tracepoints(lib_handle, &_lib_events);

		lttng_destroy_handle(lib_handle);

		if (count < 0) {
			LTTNG_THROW_ERROR("Failed to list UST tracepoints");
		}

		return count;
	}

	int _list_lib_fields()
	{
		const auto lib_handle = _create_ust_handle();
		const auto count = lttng_list_tracepoint_fields(lib_handle, &_lib_fields);

		lttng_destroy_handle(lib_handle);

		if (count < 0) {
			LTTNG_THROW_ERROR("Failed to list UST tracepoint fields");
		}

		return count;
	}

	void _build_tracepoints(int event_count, int field_count)
	{
		auto event_map = _build_event_map(event_count);
		auto field_map = _build_field_map(field_count);

		for (const auto& event_entry : event_map) {
			auto& key = event_entry.first;
			const auto event_ptr = event_entry.second;
			tracepoint_field_set fields;
			auto field_it = field_map.find(key);

			if (field_it != field_map.end()) {
				/* Safe to move because both maps are temporary */
				fields = std::move(field_it->second);
			}

			_set.emplace(*event_ptr, std::move(fields));
		}
	}

	static _event_key_t _make_event_key(const lttng_event& lib_event)
	{
		return std::make_pair(lib_event.pid, std::string(lib_event.name));
	}

	std::map<_event_key_t, const lttng_event *> _build_event_map(const int event_count) const
	{
		std::map<_event_key_t, const lttng_event *> event_map;

		for (auto i = 0U; i < static_cast<unsigned int>(event_count); ++i) {
			const auto& lib_event = _lib_events[i];

			event_map[_make_event_key(lib_event)] = &lib_event;
		}

		return event_map;
	}

	std::map<_event_key_t, tracepoint_field_set> _build_field_map(const int field_count) const
	{
		std::map<_event_key_t, tracepoint_field_set> field_map;

		for (auto i = 0U; i < static_cast<unsigned int>(field_count); ++i) {
			const auto& lib_field = _lib_fields[i];
			auto& lib_event = lib_field.event;

			field_map[_make_event_key(lib_event)].emplace(lib_field);
		}

		return field_map;
	}

	lttng_event_field *_lib_fields = nullptr;
};

class kernel_tracepoint_event_rule;
class ust_tracepoint_event_rule;
class java_python_logger_event_rule;
class linux_kprobe_event_rule;
class linux_syscall_event_rule;
class linux_uprobe_event_rule;

/*
 * Holds information about a recording event rule.
 *
 * Get a specific wrapper with as_kernel_tracepoint(),
 * as_ust_tracepoint(), as_java_python_logger(), as_linux_kprobe(),
 * as_linux_kretprobe(), as_linux_syscall(), or as_linux_uprobe()
 * depending on type() and domain.
 *
 * Doesn't own the wrapped library pointer.
 */
class event_rule {
public:
	explicit event_rule(const lttng_event& lib_event) : _lib_event(&lib_event)
	{
	}

	lttng_event_type type() const noexcept
	{
		return _lib_event->type;
	}

	c_string_view name() const noexcept
	{
		return _lib_event->name;
	}

	bool is_enabled() const noexcept
	{
		return _lib_event->enabled != 0;
	}

	c_string_view filter_expression() const
	{
		if (!lib().filter) {
			return c_string_view();
		}

		const char *filter_expr = nullptr;

		if (lttng_event_get_filter_expression(&lib(), &filter_expr) != 0) {
			LTTNG_THROW_ERROR("Failed to get recording event rule filter expression");
		}

		LTTNG_ASSERT(filter_expr);
		return c_string_view(filter_expr);
	}

	kernel_tracepoint_event_rule as_kernel_tracepoint() const noexcept;
	ust_tracepoint_event_rule as_ust_tracepoint() const noexcept;
	java_python_logger_event_rule as_java_python_logger() const noexcept;
	linux_kprobe_event_rule as_linux_kprobe() const noexcept;
	linux_syscall_event_rule as_linux_syscall() const noexcept;
	linux_uprobe_event_rule as_linux_uprobe() const noexcept;

	const lttng_event& lib() const noexcept
	{
		return *_lib_event;
	}

	bool operator<(const event_rule& other) const noexcept;

private:
	const lttng_event *_lib_event;
};

/*
 * Holds information about a Linux kernel tracepoint recording
 * event rule.
 *
 * Doesn't own the wrapped library pointer.
 */
class kernel_tracepoint_event_rule final : public event_rule {
public:
	explicit kernel_tracepoint_event_rule(const lttng_event& lib_event) : event_rule(lib_event)
	{
		LTTNG_ASSERT(type() == LTTNG_EVENT_TRACEPOINT);
	}
};

/*
 * Common base class for UST tracepoint and Java/Python logger recording
 * event rules.
 *
 * Doesn't own the wrapped library pointer.
 */
class ust_tracepoint_or_java_python_logger_event_rule : public event_rule {
public:
	explicit ust_tracepoint_or_java_python_logger_event_rule(const lttng_event& lib_event) :
		event_rule(lib_event)
	{
		LTTNG_ASSERT(type() == LTTNG_EVENT_TRACEPOINT);
	}

	lttng_loglevel_type log_level_type() const noexcept
	{
		return lib().loglevel_type;
	}

	int log_level() const noexcept
	{
		return lib().loglevel;
	}
};

/*
 * Holds information about a UST tracepoint recording event rule.
 *
 * Doesn't own the wrapped library pointer.
 */
class ust_tracepoint_event_rule final : public ust_tracepoint_or_java_python_logger_event_rule {
public:
	explicit ust_tracepoint_event_rule(const lttng_event& lib_event) :
		ust_tracepoint_or_java_python_logger_event_rule(lib_event)
	{
		LTTNG_ASSERT(type() == LTTNG_EVENT_TRACEPOINT);
	}

	std::set<c_string_view, bool (*)(const c_string_view&, const c_string_view&)>
	exclusions() const
	{
		std::set<c_string_view, bool (*)(const c_string_view&, const c_string_view&)> result(
			[](const c_string_view& lhs, const c_string_view& rhs) {
				return internal::compare_c_string_views(lhs, rhs) < 0;
			});

		if (!lib().exclusion) {
			return result;
		}

		const auto count = lttng_event_get_exclusion_name_count(&lib());

		if (count < 0) {
			LTTNG_THROW_ERROR(
				"Failed to get recording event rule name exclusion count");
		}

		for (auto i = 0U; i < static_cast<unsigned int>(count); ++i) {
			const char *exclusion = nullptr;

			if (lttng_event_get_exclusion_name(&lib(), i, &exclusion) != 0) {
				LTTNG_THROW_ERROR(
					"Failed to get recording event rule exclusion name");
			}

			LTTNG_ASSERT(exclusion);
			result.emplace(exclusion);
		}

		return result;
	}
};

/*
 * Holds information about a Java/Python logger recording event rule
 * (`java.util.logging`, log4j 1.x, Log4j 2, or Python).
 *
 * Doesn't own the wrapped library pointer.
 */
class java_python_logger_event_rule final : public ust_tracepoint_or_java_python_logger_event_rule {
public:
	explicit java_python_logger_event_rule(const lttng_event& lib_event) :
		ust_tracepoint_or_java_python_logger_event_rule(lib_event)
	{
		LTTNG_ASSERT(type() == LTTNG_EVENT_TRACEPOINT);
	}
};

/*
 * Holds information about a Linux kprobe/kretprobe recording
 * event rule.
 *
 * Doesn't own the wrapped library pointer.
 */
class linux_kprobe_event_rule final : public event_rule {
public:
	explicit linux_kprobe_event_rule(const lttng_event& lib_event) : event_rule(lib_event)
	{
		LTTNG_ASSERT(type() == LTTNG_EVENT_PROBE || type() == LTTNG_EVENT_FUNCTION);
	}

	std::uint64_t address() const noexcept
	{
		return lib().attr.probe.addr;
	}

	std::uint64_t offset() const noexcept
	{
		return lib().attr.probe.offset;
	}

	c_string_view symbol_name() const noexcept
	{
		return lib().attr.probe.symbol_name;
	}
};

/*
 * Holds information about a Linux kernel syscall recording event rule.
 *
 * Doesn't own the wrapped library pointer.
 */
class linux_syscall_event_rule final : public event_rule {
public:
	explicit linux_syscall_event_rule(const lttng_event& lib_event) : event_rule(lib_event)
	{
		LTTNG_ASSERT(type() == LTTNG_EVENT_SYSCALL);
	}
};

class uprobe_function_location;
class uprobe_tracepoint_location;

/*
 * Holds information about a Linux user space probe location.
 *
 * Get a specific wrapper with as_function() or as_tracepoint(),
 * depending on type().
 *
 * Doesn't own the wrapped library pointer.
 */
class uprobe_location {
public:
	explicit uprobe_location(const lttng_userspace_probe_location& lib_location) :
		_lib_location(&lib_location)
	{
	}

	lttng_userspace_probe_location_type type() const noexcept
	{
		return lttng_userspace_probe_location_get_type(_lib_location);
	}

	lttng_userspace_probe_location_lookup_method_type lookup_method_type() const noexcept
	{
		const auto lookup_method =
			lttng_userspace_probe_location_get_lookup_method(_lib_location);

		LTTNG_ASSERT(lookup_method);
		return lttng_userspace_probe_location_lookup_method_get_type(lookup_method);
	}

	c_string_view binary_path() const noexcept;
	int binary_fd() const noexcept;
	uprobe_function_location as_function() const noexcept;
	uprobe_tracepoint_location as_tracepoint() const noexcept;

	const lttng_userspace_probe_location& lib() const noexcept
	{
		return *_lib_location;
	}

	bool operator<(const uprobe_location& other) const noexcept;

private:
	const lttng_userspace_probe_location *_lib_location;
};

/*
 * Holds information about a Linux user space probe function location.
 *
 * Doesn't own the wrapped library pointer.
 */
class uprobe_function_location final : public uprobe_location {
public:
	explicit uprobe_function_location(const lttng_userspace_probe_location& lib_location) :
		uprobe_location(lib_location)
	{
		LTTNG_ASSERT(type() == LTTNG_USERSPACE_PROBE_LOCATION_TYPE_FUNCTION);
	}

	c_string_view binary_path() const noexcept
	{
		return lttng_userspace_probe_location_function_get_binary_path(&lib());
	}

	c_string_view function_name() const noexcept
	{
		return lttng_userspace_probe_location_function_get_function_name(&lib());
	}

	int binary_fd() const noexcept
	{
		return lttng_userspace_probe_location_function_get_binary_fd(&lib());
	}

	lttng_userspace_probe_location_function_instrumentation_type
	instrumentation_type() const noexcept
	{
		return lttng_userspace_probe_location_function_get_instrumentation_type(&lib());
	}
};

/*
 * Holds information about a Linux user space probe USDT
 * tracepoint location.
 *
 * Doesn't own the wrapped library pointer.
 */
class uprobe_tracepoint_location final : public uprobe_location {
public:
	explicit uprobe_tracepoint_location(const lttng_userspace_probe_location& lib_location) :
		uprobe_location(lib_location)
	{
		LTTNG_ASSERT(type() == LTTNG_USERSPACE_PROBE_LOCATION_TYPE_TRACEPOINT);
	}

	c_string_view binary_path() const noexcept
	{
		return lttng_userspace_probe_location_tracepoint_get_binary_path(&lib());
	}

	c_string_view probe_name() const noexcept
	{
		return lttng_userspace_probe_location_tracepoint_get_probe_name(&lib());
	}

	c_string_view provider_name() const noexcept
	{
		return lttng_userspace_probe_location_tracepoint_get_provider_name(&lib());
	}

	int binary_fd() const noexcept
	{
		return lttng_userspace_probe_location_tracepoint_get_binary_fd(&lib());
	}
};

inline c_string_view uprobe_location::binary_path() const noexcept
{
	switch (type()) {
	case LTTNG_USERSPACE_PROBE_LOCATION_TYPE_FUNCTION:
		return as_function().binary_path();
	case LTTNG_USERSPACE_PROBE_LOCATION_TYPE_TRACEPOINT:
		return as_tracepoint().binary_path();
	default:
		return c_string_view();
	}
}

inline int uprobe_location::binary_fd() const noexcept
{
	switch (type()) {
	case LTTNG_USERSPACE_PROBE_LOCATION_TYPE_FUNCTION:
		return as_function().binary_fd();
	case LTTNG_USERSPACE_PROBE_LOCATION_TYPE_TRACEPOINT:
		return as_tracepoint().binary_fd();
	default:
		return -1;
	}
}

inline uprobe_function_location uprobe_location::as_function() const noexcept
{
	return uprobe_function_location(*_lib_location);
}

inline uprobe_tracepoint_location uprobe_location::as_tracepoint() const noexcept
{
	return uprobe_tracepoint_location(*_lib_location);
}

inline bool uprobe_location::operator<(const uprobe_location& other) const noexcept
{
	/* Compare location types */
	if (type() != other.type()) {
		return type() < other.type();
	}

	/* Compare binary paths */
	{
		const auto binary_cmp =
			internal::compare_c_string_views(binary_path(), other.binary_path());

		if (binary_cmp != 0) {
			return binary_cmp < 0;
		}
	}

	/* Compare binary FDs */
	if (binary_fd() != other.binary_fd()) {
		return binary_fd() < other.binary_fd();
	}

	/* Compare lookup method types */
	if (lookup_method_type() != other.lookup_method_type()) {
		return lookup_method_type() < other.lookup_method_type();
	}

	/* Compare type-specific properties */
	if (type() == LTTNG_USERSPACE_PROBE_LOCATION_TYPE_FUNCTION) {
		const auto lhs = as_function();
		const auto rhs = other.as_function();

		{
			const auto func_cmp = internal::compare_c_string_views(lhs.function_name(),
									       rhs.function_name());

			if (func_cmp != 0) {
				return func_cmp < 0;
			}
		}

		if (lhs.instrumentation_type() != rhs.instrumentation_type()) {
			return lhs.instrumentation_type() < rhs.instrumentation_type();
		}
	} else if (type() == LTTNG_USERSPACE_PROBE_LOCATION_TYPE_TRACEPOINT) {
		const auto lhs = as_tracepoint();
		const auto rhs = other.as_tracepoint();

		{
			const auto prov_cmp = internal::compare_c_string_views(lhs.provider_name(),
									       rhs.provider_name());

			if (prov_cmp != 0) {
				return prov_cmp < 0;
			}
		}

		const auto probe_cmp =
			internal::compare_c_string_views(lhs.probe_name(), rhs.probe_name());

		if (probe_cmp != 0) {
			return probe_cmp < 0;
		}
	}

	return false;
}

/*
 * Holds information about a Linux user space probe recording
 * event rule.
 *
 * Doesn't own the wrapped library pointer.
 */
class linux_uprobe_event_rule final : public event_rule {
public:
	explicit linux_uprobe_event_rule(const lttng_event& lib_event) : event_rule(lib_event)
	{
		LTTNG_ASSERT(type() == LTTNG_EVENT_USERSPACE_PROBE);
	}

	nonstd::optional<uprobe_location> location() const noexcept
	{
		const auto loc = lttng_event_get_userspace_probe_location(&lib());

		if (!loc) {
			return nonstd::nullopt;
		}

		return uprobe_location(*loc);
	}
};

inline kernel_tracepoint_event_rule event_rule::as_kernel_tracepoint() const noexcept
{
	return kernel_tracepoint_event_rule(*_lib_event);
}

inline ust_tracepoint_event_rule event_rule::as_ust_tracepoint() const noexcept
{
	return ust_tracepoint_event_rule(*_lib_event);
}

inline java_python_logger_event_rule event_rule::as_java_python_logger() const noexcept
{
	return java_python_logger_event_rule(*_lib_event);
}

inline linux_kprobe_event_rule event_rule::as_linux_kprobe() const noexcept
{
	return linux_kprobe_event_rule(*_lib_event);
}

inline linux_syscall_event_rule event_rule::as_linux_syscall() const noexcept
{
	return linux_syscall_event_rule(*_lib_event);
}

inline linux_uprobe_event_rule event_rule::as_linux_uprobe() const noexcept
{
	return linux_uprobe_event_rule(*_lib_event);
}

inline bool event_rule::operator<(const event_rule& other) const noexcept
{
	/* Compare types */
	if (type() != other.type()) {
		return type() < other.type();
	}

	/* Compare names */
	{
		const auto name_cmp = internal::compare_c_string_views(name(), other.name());

		if (name_cmp != 0) {
			return name_cmp < 0;
		}
	}

	/* Compare type-specific properties */
	switch (type()) {
	case LTTNG_EVENT_PROBE:
	case LTTNG_EVENT_FUNCTION:
	{
		/* Compare symbol names, addresses, and offsets */
		const auto lhs = as_linux_kprobe();
		const auto rhs = other.as_linux_kprobe();

		{
			const auto symbol_cmp = internal::compare_c_string_views(lhs.symbol_name(),
										 rhs.symbol_name());

			if (symbol_cmp != 0) {
				return symbol_cmp < 0;
			}
		}

		if (lhs.address() != rhs.address()) {
			return lhs.address() < rhs.address();
		}

		if (lhs.offset() != rhs.offset()) {
			return lhs.offset() < rhs.offset();
		}

		break;
	}
	case LTTNG_EVENT_TRACEPOINT:
	{
		/* Compare log level types, log levels, and filter expressions */
		const auto lhs = as_ust_tracepoint();
		const auto rhs = other.as_ust_tracepoint();

		if (lhs.log_level_type() != rhs.log_level_type()) {
			return lhs.log_level_type() < rhs.log_level_type();
		}

		if (lhs.log_level() != rhs.log_level()) {
			return lhs.log_level() < rhs.log_level();
		}

		const auto filter_cmp = internal::compare_c_string_views(filter_expression(),
									 rhs.filter_expression());

		if (filter_cmp != 0) {
			return filter_cmp < 0;
		}

		break;
	}
	case LTTNG_EVENT_SYSCALL:
	{
		/* Compare filter expressions */
		const auto filter_cmp = internal::compare_c_string_views(filter_expression(),
									 other.filter_expression());

		if (filter_cmp != 0) {
			return filter_cmp < 0;
		}

		break;
	}
	case LTTNG_EVENT_USERSPACE_PROBE:
	{
		/* Compare uprobe locations */
		return as_linux_uprobe().location() < other.as_linux_uprobe().location();
	}
	default:
		break;
	}

	return false;
}

/*
 * Holds information about recording event rules.
 *
 * Owns the wrapped library event array pointer.
 */
template <typename EventRuleType>
class event_rule_set final {
public:
	explicit event_rule_set(lttng_event *const lib_events, const unsigned int count) :
		_lib_events(lib_events)
	{
		LTTNG_ASSERT(count == 0 || _lib_events);

		for (auto i = 0U; i < count; ++i) {
			_set.emplace(lib_events[i]);
		}
	}

	event_rule_set(const event_rule_set&) = delete;

	event_rule_set(event_rule_set&& other) noexcept :
		_lib_events(other._lib_events), _set(std::move(other._set))
	{
		other._lib_events = nullptr;
	}

	event_rule_set& operator=(const event_rule_set&) = delete;

	event_rule_set& operator=(event_rule_set&& other) noexcept
	{
		if (this != &other) {
			std::free(_lib_events);
			_lib_events = other._lib_events;
			_set = std::move(other._set);
			other._lib_events = nullptr;
		}

		return *this;
	}

	~event_rule_set()
	{
		std::free(_lib_events);
	}

	const std::set<EventRuleType>& set() const noexcept
	{
		return _set;
	}

	typename std::set<EventRuleType>::const_iterator begin() const noexcept
	{
		return _set.begin();
	}

	typename std::set<EventRuleType>::const_iterator end() const noexcept
	{
		return _set.end();
	}

	std::size_t size() const noexcept
	{
		return _set.size();
	}

	bool is_empty() const noexcept
	{
		return _set.empty();
	}

private:
	lttng_event *_lib_events;
	std::set<EventRuleType> _set;
};

/*
 * Holds information about a data stream.
 *
 * Doesn't own the wrapped library pointer.
 */
class data_stream_info final {
public:
	explicit data_stream_info(const lttng_data_stream_info& lib_ds_info) :
		_lib_stream_info(&lib_ds_info)
	{
	}

	nonstd::optional<unsigned int> cpu_id() const
	{
		unsigned int cpu_id;
		const auto status = lttng_data_stream_info_get_cpu_id(_lib_stream_info, &cpu_id);

		if (status == LTTNG_DATA_STREAM_INFO_STATUS_OK) {
			return cpu_id;
		} else if (status == LTTNG_DATA_STREAM_INFO_STATUS_NONE) {
			return nonstd::nullopt;
		}

		LTTNG_THROW_ERROR("Failed to get data stream info CPU ID");
	}

	std::uint64_t memory_usage_bytes() const
	{
		std::uint64_t memory_usage;

		if (lttng_data_stream_info_get_memory_usage(_lib_stream_info, &memory_usage) !=
		    LTTNG_DATA_STREAM_INFO_STATUS_OK) {
			LTTNG_THROW_ERROR("Failed to get data stream info memory usage");
		}

		return memory_usage;
	}

	std::uint64_t max_memory_usage_bytes() const
	{
		std::uint64_t max_memory_usage;

		if (lttng_data_stream_info_get_max_memory_usage(_lib_stream_info,
								&max_memory_usage) !=
		    LTTNG_DATA_STREAM_INFO_STATUS_OK) {
			LTTNG_THROW_ERROR("Failed to get data stream info max memory usage");
		}

		return max_memory_usage;
	}

	const lttng_data_stream_info& lib() const noexcept
	{
		return *_lib_stream_info;
	}

	bool operator<(const data_stream_info& other) const noexcept
	{
		return cpu_id() < other.cpu_id();
	}

private:
	const lttng_data_stream_info *_lib_stream_info;
};

/*
 * Holds information about a set of data streams for a specific Unix
 * user or process.
 *
 * Doesn't own the wrapped library pointer.
 */
class data_stream_info_set final {
public:
	explicit data_stream_info_set(const lttng_data_stream_info_set& lib_ds_info_set) :
		_lib_set(&lib_ds_info_set)
	{
		unsigned int count;

		if (lttng_data_stream_info_set_get_count(_lib_set, &count) !=
		    LTTNG_DATA_STREAM_INFO_STATUS_OK) {
			LTTNG_THROW_ERROR("Failed to get data stream info set count");
		}

		for (auto i = 0U; i < count; ++i) {
			const lttng_data_stream_info *lib_stream_info = nullptr;

			if (lttng_data_stream_info_set_get_at_index(_lib_set, i, &lib_stream_info) !=
			    LTTNG_DATA_STREAM_INFO_STATUS_OK) {
				LTTNG_THROW_ERROR("Failed to get data stream info at index");
			}

			LTTNG_ASSERT(lib_stream_info);
			_infos.emplace(*lib_stream_info);
		}
	}

	nonstd::optional<uid_t> uid() const
	{
		uid_t uid;
		const auto status = lttng_data_stream_info_set_get_uid(_lib_set, &uid);

		if (status == LTTNG_DATA_STREAM_INFO_STATUS_OK) {
			return uid;
		} else if (status == LTTNG_DATA_STREAM_INFO_STATUS_NONE) {
			return nonstd::nullopt;
		}

		LTTNG_THROW_ERROR("Failed to get data stream info set UID");
	}

	nonstd::optional<pid_t> pid() const
	{
		pid_t pid;
		const auto status = lttng_data_stream_info_set_get_pid(_lib_set, &pid);

		if (status == LTTNG_DATA_STREAM_INFO_STATUS_OK) {
			return pid;
		} else if (status == LTTNG_DATA_STREAM_INFO_STATUS_NONE) {
			return nonstd::nullopt;
		}

		LTTNG_THROW_ERROR("Failed to get data stream info set PID");
	}

	nonstd::optional<lttng_app_bitness> app_bitness() const
	{
		lttng_app_bitness lib_bitness;
		const auto status =
			lttng_data_stream_info_set_get_app_bitness(_lib_set, &lib_bitness);

		if (status == LTTNG_DATA_STREAM_INFO_STATUS_OK) {
			return lib_bitness;
		} else if (status == LTTNG_DATA_STREAM_INFO_STATUS_NONE) {
			return nonstd::nullopt;
		}

		LTTNG_THROW_ERROR("Failed to get data stream info set app bitness");
	}

	const std::set<data_stream_info>& set() const noexcept
	{
		return _infos;
	}

	std::set<data_stream_info>::const_iterator begin() const noexcept
	{
		return _infos.begin();
	}

	std::set<data_stream_info>::const_iterator end() const noexcept
	{
		return _infos.end();
	}

	std::size_t size() const noexcept
	{
		return _infos.size();
	}

	bool is_empty() const noexcept
	{
		return _infos.empty();
	}

	std::uint64_t memory_usage_bytes() const
	{
		std::uint64_t total = 0;

		for (const auto& stream_info : _infos) {
			total += stream_info.memory_usage_bytes();
		}

		return total;
	}

	std::uint64_t max_memory_usage_bytes() const
	{
		std::uint64_t total = 0;

		for (const auto& stream_info : _infos) {
			total += stream_info.max_memory_usage_bytes();
		}

		return total;
	}

	const lttng_data_stream_info_set& lib() const noexcept
	{
		return *_lib_set;
	}

	bool operator<(const data_stream_info_set& other) const noexcept
	{
		if (uid() != other.uid()) {
			return uid() < other.uid();
		}

		return pid() < other.pid();
	}

private:
	const lttng_data_stream_info_set *_lib_set;
	std::set<data_stream_info> _infos;
};

/*
 * Holds information about multiple sets of data streams.
 *
 * Owns the wrapped library pointer.
 */
class data_stream_info_sets final {
public:
	explicit data_stream_info_sets(const lttng_data_stream_info_sets& lib_ds_info_sets) :
		_lib_sets(&lib_ds_info_sets)
	{
		unsigned int count;

		if (lttng_data_stream_info_sets_get_count(_lib_sets, &count) !=
		    LTTNG_DATA_STREAM_INFO_STATUS_OK) {
			LTTNG_THROW_ERROR("Failed to get data stream info sets count");
		}

		for (auto i = 0U; i < count; ++i) {
			const lttng_data_stream_info_set *lib_ds_info_set = nullptr;

			if (lttng_data_stream_info_sets_get_at_index(
				    _lib_sets, i, &lib_ds_info_set) !=
			    LTTNG_DATA_STREAM_INFO_STATUS_OK) {
				LTTNG_THROW_ERROR("Failed to get data stream info set at index");
			}

			LTTNG_ASSERT(lib_ds_info_set);
			_infos.emplace(*lib_ds_info_set);
		}
	}

	data_stream_info_sets(const data_stream_info_sets&) = delete;

	data_stream_info_sets(data_stream_info_sets&& other) noexcept :
		_lib_sets(other._lib_sets), _infos(std::move(other._infos))
	{
		other._lib_sets = nullptr;
	}

	data_stream_info_sets& operator=(const data_stream_info_sets&) = delete;

	data_stream_info_sets& operator=(data_stream_info_sets&& other) noexcept
	{
		if (this != &other) {
			lttng_data_stream_info_sets_destroy(_lib_sets);
			_lib_sets = other._lib_sets;
			_infos = std::move(other._infos);
			other._lib_sets = nullptr;
		}

		return *this;
	}

	~data_stream_info_sets()
	{
		lttng_data_stream_info_sets_destroy(_lib_sets);
	}

	const std::set<data_stream_info_set>& set() const noexcept
	{
		return _infos;
	}

	std::set<data_stream_info_set>::const_iterator begin() const noexcept
	{
		return _infos.begin();
	}

	std::set<data_stream_info_set>::const_iterator end() const noexcept
	{
		return _infos.end();
	}

	std::size_t size() const noexcept
	{
		return _infos.size();
	}

	bool is_empty() const noexcept
	{
		return _infos.empty();
	}

	std::uint64_t memory_usage_bytes() const
	{
		std::uint64_t total = 0;

		for (const auto& set : _infos) {
			total += set.memory_usage_bytes();
		}

		return total;
	}

	std::uint64_t max_memory_usage_bytes() const
	{
		std::uint64_t total = 0;

		for (const auto& set : _infos) {
			total += set.max_memory_usage_bytes();
		}

		return total;
	}

	const lttng_data_stream_info_sets& lib() const noexcept
	{
		return *_lib_sets;
	}

private:
	const lttng_data_stream_info_sets *_lib_sets;
	std::set<data_stream_info_set> _infos;
};

class kernel_channel;
class ust_channel;
class ust_or_java_python_channel;
class java_python_channel;

/*
 * Holds information about a channel.
 *
 * Get a specific wrapper with as_kernel(), as_ust(), or
 * as_java_python(), depending on domain_type().
 *
 * Doesn't own the wrapped library pointer.
 */
class channel {
public:
	explicit channel(const lttng_handle& lib_handle, const lttng_channel& lib_channel) :
		_lib_handle(lib_handle), _lib_channel(&lib_channel)
	{
	}

	c_string_view session_name() const noexcept
	{
		return _lib_handle.session_name;
	}

	lttng_domain_type domain_type() const noexcept
	{
		return _lib_handle.domain.type;
	}

	lttng_buffer_type buffer_ownership_model() const noexcept
	{
		return _lib_handle.domain.buf_type;
	}

	const lttng_handle& lib_handle() const noexcept
	{
		return _lib_handle;
	}

	c_string_view name() const noexcept
	{
		return _lib_channel->name;
	}

	bool is_enabled() const noexcept
	{
		return _lib_channel->enabled != 0;
	}

	bool is_discard_mode() const noexcept
	{
		return _lib_channel->attr.overwrite == 0;
	}

	std::uint64_t sub_buf_size() const noexcept
	{
		return _lib_channel->attr.subbuf_size;
	}

	std::uint64_t sub_buf_count() const noexcept
	{
		return _lib_channel->attr.num_subbuf;
	}

	unsigned int switch_timer_period_us() const noexcept
	{
		return _lib_channel->attr.switch_timer_interval;
	}

	unsigned int read_timer_period_us() const noexcept
	{
		return _lib_channel->attr.read_timer_interval;
	}

	std::uint64_t max_trace_file_size() const noexcept
	{
		return _lib_channel->attr.tracefile_size;
	}

	std::uint64_t max_trace_file_count() const noexcept
	{
		return _lib_channel->attr.tracefile_count;
	}

	unsigned int live_timer_period_us() const noexcept
	{
		return _lib_channel->attr.live_timer_interval;
	}

	std::uint64_t monitor_timer_period_us() const
	{
		std::uint64_t period = 0;

		if (lttng_channel_get_monitor_timer_interval(_lib_channel, &period) != 0) {
			LTTNG_THROW_ERROR("Failed to get monitor timer period");
		}

		return period;
	}

	/*
	 * Returns a snapshot of the discarded event record counter
	 * of this channel.
	 */
	std::uint64_t discarded_event_record_count() const
	{
		std::uint64_t count = 0;

		if (lttng_channel_get_discarded_event_count(_lib_channel, &count) != 0) {
			LTTNG_THROW_ERROR("Failed to get discarded event record count");
		}

		return count;
	}

	/*
	 * Returns a snapshot of the discarded packet counter of
	 * this channel.
	 */
	std::uint64_t discarded_packet_count() const
	{
		std::uint64_t count = 0;

		if (lttng_channel_get_lost_packet_count(_lib_channel, &count) != 0) {
			LTTNG_THROW_ERROR("Failed to get discarded packet count");
		}

		return count;
	}

	/*
	 * Returns a snapshot of the available recording event rules of
	 * this channel.
	 */
	event_rule_set<event_rule> event_rules() const
	{
		return _event_rules<event_rule>();
	}

	kernel_channel as_kernel() const noexcept;
	ust_channel as_ust() const noexcept;
	ust_or_java_python_channel as_ust_or_java_python() const noexcept;
	java_python_channel as_java_python() const noexcept;

	const lttng_channel& lib() const noexcept
	{
		return *_lib_channel;
	}

	bool operator<(const channel& other) const noexcept
	{
		return internal::compare_c_string_views(name(), other.name()) < 0;
	}

protected:
	template <typename EventRuleType>
	event_rule_set<EventRuleType> _event_rules() const
	{
		lttng_event *lib_events = nullptr;
		const auto count = lttng_list_events(&lib_handle(), name().data(), &lib_events);

		if (count < 0) {
			LTTNG_THROW_ERROR("Failed to list recording event rules");
		}

		LTTNG_ASSERT(count == 0 || lib_events);
		return event_rule_set<EventRuleType>(lib_events, static_cast<unsigned int>(count));
	}

private:
	lttng_handle _lib_handle;
	const lttng_channel *_lib_channel;
};

/*
 * Holds information about a Linux kernel channel.
 *
 * Doesn't own the wrapped library pointer.
 */
class kernel_channel final : public channel {
public:
	explicit kernel_channel(const lttng_handle& lib_handle, const lttng_channel& lib_channel) :
		channel(lib_handle, lib_channel)
	{
		LTTNG_ASSERT(domain_type() == LTTNG_DOMAIN_KERNEL);
	}

	lttng_event_output output_type() const noexcept
	{
		return lib().attr.output;
	}
};

/*
 * Common base class for UST and Java/Python channels.
 *
 * Doesn't own the wrapped library pointer.
 */
class ust_or_java_python_channel : public channel {
public:
	explicit ust_or_java_python_channel(const lttng_handle& lib_handle,
					    const lttng_channel& lib_channel) :
		channel(lib_handle, lib_channel)
	{
		LTTNG_ASSERT(domain_type() == LTTNG_DOMAIN_UST ||
			     domain_type() == LTTNG_DOMAIN_JUL ||
			     domain_type() == LTTNG_DOMAIN_LOG4J ||
			     domain_type() == LTTNG_DOMAIN_LOG4J2 ||
			     domain_type() == LTTNG_DOMAIN_PYTHON);
	}

	/*
	 * `nonstd::nullopt` means infinite.
	 */
	nonstd::optional<std::uint64_t> blocking_timeout_us() const
	{
		std::int64_t timeout;

		if (lttng_channel_get_blocking_timeout(&lib(), &timeout) != 0) {
			LTTNG_THROW_ERROR("Failed to get blocking timeout");
		}

		if (timeout <= 0) {
			return nonstd::nullopt;
		}

		return static_cast<std::uint64_t>(timeout);
	}

	lttng_channel_allocation_policy allocation_policy() const
	{
		lttng_channel_allocation_policy lib_policy;

		if (lttng_channel_get_allocation_policy(&lib(), &lib_policy) != LTTNG_OK) {
			LTTNG_THROW_ERROR("Failed to get allocation policy");
		}

		return lib_policy;
	}

	nonstd::optional<std::uint64_t> watchdog_timer_period_us() const noexcept
	{
		std::uint64_t period;

		if (lttng_channel_get_watchdog_timer_interval(&lib(), &period) ==
		    LTTNG_CHANNEL_GET_WATCHDOG_TIMER_INTERVAL_STATUS_OK) {
			return period;
		}

		return nonstd::nullopt;
	}

	lttng_channel_preallocation_policy preallocation_policy() const
	{
		lttng_channel_preallocation_policy lib_policy;

		if (lttng_channel_get_preallocation_policy(&lib(), &lib_policy) !=
		    LTTNG_CHANNEL_STATUS_OK) {
			LTTNG_THROW_ERROR("Failed to get preallocation policy");
		}

		return lib_policy;
	}

	nonstd::optional<std::uint64_t> automatic_memory_reclaim_maximal_age_us() const noexcept
	{
		std::uint64_t maximal_age_us;

		if (lttng_channel_get_automatic_memory_reclamation_policy(
			    &lib(), &maximal_age_us) == LTTNG_CHANNEL_STATUS_OK) {
			return maximal_age_us;
		}

		return nonstd::nullopt;
	}

	/*
	 * Returns a snapshot of the available data stream infos of
	 * this channel.
	 */
	data_stream_info_sets data_stream_infos() const
	{
		const lttng_data_stream_info_sets *lib_ds_info_sets;

		if (lttng_channel_get_data_stream_info_sets(session_name().data(),
							    name().data(),
							    domain_type(),
							    &lib_ds_info_sets) !=
		    LTTNG_CHANNEL_GET_DATA_STREAM_INFO_SETS_STATUS_OK) {
			LTTNG_THROW_ERROR("Failed to get data stream info sets");
		}

		LTTNG_ASSERT(lib_ds_info_sets);
		return data_stream_info_sets(*lib_ds_info_sets);
	}
};

/*
 * Holds information about a UST channel.
 *
 * Doesn't own the wrapped library pointer.
 */
class ust_channel final : public ust_or_java_python_channel {
public:
	explicit ust_channel(const lttng_handle& lib_handle, const lttng_channel& lib_channel) :
		ust_or_java_python_channel(lib_handle, lib_channel)
	{
		LTTNG_ASSERT(domain_type() == LTTNG_DOMAIN_UST);
	}

	/*
	 * Returns a snapshot of the available recording event rules of
	 * this channel.
	 */
	event_rule_set<ust_tracepoint_event_rule> event_rules() const
	{
		return _event_rules<ust_tracepoint_event_rule>();
	}
};

/*
 * Holds information about a Java/Python channel.
 *
 * Doesn't own the wrapped library pointer.
 */
class java_python_channel final : public ust_or_java_python_channel {
public:
	explicit java_python_channel(const lttng_handle& lib_handle,
				     const lttng_channel& lib_channel) :
		ust_or_java_python_channel(lib_handle, lib_channel)
	{
		LTTNG_ASSERT(domain_type() == LTTNG_DOMAIN_JUL ||
			     domain_type() == LTTNG_DOMAIN_LOG4J ||
			     domain_type() == LTTNG_DOMAIN_LOG4J2 ||
			     domain_type() == LTTNG_DOMAIN_PYTHON);
	}

	/*
	 * Returns a snapshot of the available recording event rules of
	 * this channel.
	 */
	event_rule_set<java_python_logger_event_rule> event_rules() const
	{
		return _event_rules<java_python_logger_event_rule>();
	}
};

inline kernel_channel channel::as_kernel() const noexcept
{
	return kernel_channel(_lib_handle, *_lib_channel);
}

inline ust_channel channel::as_ust() const noexcept
{
	return ust_channel(_lib_handle, *_lib_channel);
}

inline ust_or_java_python_channel channel::as_ust_or_java_python() const noexcept
{
	return ust_or_java_python_channel(_lib_handle, *_lib_channel);
}

inline java_python_channel channel::as_java_python() const noexcept
{
	return java_python_channel(_lib_handle, *_lib_channel);
}

/*
 * Holds information about channels for a specific recording session
 * and domain.
 *
 * Owns the wrapped library channel array pointer.
 */
template <typename ChannelType>
class channel_set final {
public:
	explicit channel_set(const lttng_handle& lib_handle,
			     lttng_channel *const lib_channels,
			     const unsigned int count) :
		_lib_channels(lib_channels)
	{
		LTTNG_ASSERT(count == 0 || lib_channels);

		for (auto i = 0U; i < count; ++i) {
			_set.emplace(lib_handle, lib_channels[i]);
		}
	}

	channel_set(const channel_set&) = delete;

	channel_set(channel_set&& other) noexcept :
		_lib_channels(other._lib_channels), _set(std::move(other._set))
	{
		other._lib_channels = nullptr;
	}

	channel_set& operator=(const channel_set&) = delete;

	channel_set& operator=(channel_set&& other) noexcept
	{
		if (this != &other) {
			std::free(_lib_channels);
			_lib_channels = other._lib_channels;
			_set = std::move(other._set);
			other._lib_channels = nullptr;
		}

		return *this;
	}

	~channel_set()
	{
		std::free(_lib_channels);
	}

	const std::set<ChannelType>& set() const noexcept
	{
		return _set;
	}

	typename std::set<ChannelType>::const_iterator begin() const noexcept
	{
		return _set.begin();
	}

	typename std::set<ChannelType>::const_iterator end() const noexcept
	{
		return _set.end();
	}

	std::size_t size() const noexcept
	{
		return _set.size();
	}

	bool is_empty() const noexcept
	{
		return _set.empty();
	}

	nonstd::optional<ChannelType> find_by_name(const char *const name) const noexcept
	{
		LTTNG_ASSERT(name);

		for (const auto& channel : _set) {
			if (channel.name() == name) {
				return channel;
			}
		}

		return nonstd::nullopt;
	}

private:
	lttng_channel *_lib_channels;
	std::set<ChannelType> _set;
};

/*
 * Holds information about a recording session snapshot output.
 *
 * Owns the wrapped library snapshot output list.
 */
class snapshot_output final {
public:
	explicit snapshot_output(lttng_snapshot_output_list& lib_list,
				 const lttng_snapshot_output& lib_output) :
		_lib_list(&lib_list), _lib_output(&lib_output)
	{
	}

	snapshot_output(const snapshot_output&) = delete;

	snapshot_output(snapshot_output&& other) noexcept :
		_lib_list(other._lib_list), _lib_output(other._lib_output)
	{
		other._lib_list = nullptr;
		other._lib_output = nullptr;
	}

	snapshot_output& operator=(const snapshot_output&) = delete;

	snapshot_output& operator=(snapshot_output&& other) noexcept
	{
		if (this != &other) {
			lttng_snapshot_output_list_destroy(_lib_list);
			_lib_list = other._lib_list;
			_lib_output = other._lib_output;
			other._lib_list = nullptr;
			other._lib_output = nullptr;
		}

		return *this;
	}

	~snapshot_output()
	{
		lttng_snapshot_output_list_destroy(_lib_list);
	}

	std::uint32_t id() const noexcept
	{
		return lttng_snapshot_output_get_id(_lib_output);
	}

	c_string_view name() const noexcept
	{
		return lttng_snapshot_output_get_name(_lib_output);
	}

	std::uint64_t max_size_bytes() const noexcept
	{
		return lttng_snapshot_output_get_maxsize(_lib_output);
	}

	c_string_view control_url() const noexcept
	{
		return lttng_snapshot_output_get_ctrl_url(_lib_output);
	}

	c_string_view data_url() const noexcept
	{
		return lttng_snapshot_output_get_data_url(_lib_output);
	}

	const lttng_snapshot_output& lib() const noexcept
	{
		return *_lib_output;
	}

private:
	lttng_snapshot_output_list *_lib_list;
	const lttng_snapshot_output *_lib_output;
};

/*
 * Holds information about a process attribute value in a tracker.
 *
 * Doesn't own the wrapped library pointers.
 */
class process_attr_value final {
public:
	process_attr_value(const lttng_process_attr_values *const lib_values,
			   const unsigned int index) :
		_lib_values(lib_values), _index(index)
	{
		LTTNG_ASSERT(lib_values);
	}

	lttng_process_attr_value_type type() const noexcept
	{
		return lttng_process_attr_values_get_type_at_index(_lib_values, _index);
	}

	nonstd::optional<pid_t> pid() const noexcept
	{
		pid_t pid;

		if (lttng_process_attr_values_get_pid_at_index(_lib_values, _index, &pid) ==
		    LTTNG_PROCESS_ATTR_VALUES_STATUS_OK) {
			return pid;
		}

		return nonstd::nullopt;
	}

	nonstd::optional<uid_t> uid() const noexcept
	{
		uid_t uid;

		if (lttng_process_attr_values_get_uid_at_index(_lib_values, _index, &uid) ==
		    LTTNG_PROCESS_ATTR_VALUES_STATUS_OK) {
			return uid;
		}

		return nonstd::nullopt;
	}

	c_string_view user_name() const noexcept
	{
		const char *user_name;

		if (lttng_process_attr_values_get_user_name_at_index(
			    _lib_values, _index, &user_name) ==
		    LTTNG_PROCESS_ATTR_VALUES_STATUS_OK) {
			return c_string_view(user_name);
		}

		return c_string_view(nullptr);
	}

	nonstd::optional<gid_t> gid() const noexcept
	{
		gid_t gid;

		if (lttng_process_attr_values_get_gid_at_index(_lib_values, _index, &gid) ==
		    LTTNG_PROCESS_ATTR_VALUES_STATUS_OK) {
			return gid;
		}

		return nonstd::nullopt;
	}

	c_string_view group_name() const noexcept
	{
		const char *group_name;

		if (lttng_process_attr_values_get_group_name_at_index(
			    _lib_values, _index, &group_name) ==
		    LTTNG_PROCESS_ATTR_VALUES_STATUS_OK) {
			return c_string_view(group_name);
		}

		return c_string_view(nullptr);
	}

	pid_t pid_value() const noexcept
	{
		LTTNG_ASSERT(type() == LTTNG_PROCESS_ATTR_VALUE_TYPE_PID);

		pid_t pid;
		const auto status =
			lttng_process_attr_values_get_pid_at_index(_lib_values, _index, &pid);

		LTTNG_ASSERT(status == LTTNG_PROCESS_ATTR_VALUES_STATUS_OK);
		return pid;
	}

	uid_t uid_value() const noexcept
	{
		LTTNG_ASSERT(type() == LTTNG_PROCESS_ATTR_VALUE_TYPE_UID);

		uid_t uid;
		const auto status =
			lttng_process_attr_values_get_uid_at_index(_lib_values, _index, &uid);

		LTTNG_ASSERT(status == LTTNG_PROCESS_ATTR_VALUES_STATUS_OK);
		return uid;
	}

	gid_t gid_value() const noexcept
	{
		LTTNG_ASSERT(type() == LTTNG_PROCESS_ATTR_VALUE_TYPE_GID);

		gid_t gid;
		const auto status =
			lttng_process_attr_values_get_gid_at_index(_lib_values, _index, &gid);

		LTTNG_ASSERT(status == LTTNG_PROCESS_ATTR_VALUES_STATUS_OK);
		return gid;
	}

	c_string_view user_name_value() const noexcept
	{
		LTTNG_ASSERT(type() == LTTNG_PROCESS_ATTR_VALUE_TYPE_USER_NAME);
		const char *user_name;
		const auto status = lttng_process_attr_values_get_user_name_at_index(
			_lib_values, _index, &user_name);
		LTTNG_ASSERT(status == LTTNG_PROCESS_ATTR_VALUES_STATUS_OK);
		return c_string_view(user_name);
	}

	c_string_view group_name_value() const noexcept
	{
		LTTNG_ASSERT(type() == LTTNG_PROCESS_ATTR_VALUE_TYPE_GROUP_NAME);

		const char *group_name;
		const auto status = lttng_process_attr_values_get_group_name_at_index(
			_lib_values, _index, &group_name);

		LTTNG_ASSERT(status == LTTNG_PROCESS_ATTR_VALUES_STATUS_OK);
		return c_string_view(group_name);
	}

	bool operator<(const process_attr_value& other) const noexcept
	{
		if (type() != other.type()) {
			/* Types differ: order by type */
			return type() < other.type();
		}

		/* Same type, compare values */
		switch (type()) {
		case LTTNG_PROCESS_ATTR_VALUE_TYPE_PID:
			return pid_value() < other.pid_value();
		case LTTNG_PROCESS_ATTR_VALUE_TYPE_UID:
			return uid_value() < other.uid_value();
		case LTTNG_PROCESS_ATTR_VALUE_TYPE_GID:
			return gid_value() < other.gid_value();
		case LTTNG_PROCESS_ATTR_VALUE_TYPE_USER_NAME:
			return internal::compare_c_string_views(user_name_value(),
								other.user_name_value()) < 0;
		case LTTNG_PROCESS_ATTR_VALUE_TYPE_GROUP_NAME:
			return internal::compare_c_string_views(group_name_value(),
								other.group_name_value()) < 0;
		default:
			return false;
		}
	}

private:
	const lttng_process_attr_values *_lib_values;
	unsigned int _index;
};

/*
 * Holds information about a process attribute tracker.
 *
 * Owns the wrapped library tracker handle.
 */
class process_attr_tracker final {
public:
	explicit process_attr_tracker(lttng_process_attr_tracker_handle& lib_handle) :
		_lib_handle(&lib_handle)
	{
	}

	process_attr_tracker(const process_attr_tracker&) = delete;

	process_attr_tracker(process_attr_tracker&& other) noexcept : _lib_handle(other._lib_handle)
	{
		other._lib_handle = nullptr;
	}

	process_attr_tracker& operator=(const process_attr_tracker&) = delete;

	process_attr_tracker& operator=(process_attr_tracker&& other) noexcept
	{
		if (this != &other) {
			lttng_process_attr_tracker_handle_destroy(_lib_handle);
			_lib_handle = other._lib_handle;
			other._lib_handle = nullptr;
		}

		return *this;
	}

	~process_attr_tracker()
	{
		lttng_process_attr_tracker_handle_destroy(_lib_handle);
	}

	lttng_tracking_policy tracking_policy() const
	{
		lttng_tracking_policy lib_policy;

		if (lttng_process_attr_tracker_handle_get_tracking_policy(_lib_handle,
									  &lib_policy) !=
		    LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_OK) {
			LTTNG_THROW_ERROR("Failed to get tracker policy");
		}

		return lib_policy;
	}

	/*
	 * Returns a snapshot of the available process attribute values for
	 * this tracker.
	 */
	nonstd::optional<std::set<process_attr_value>> inclusion_set() const
	{
		LTTNG_ASSERT(tracking_policy() == LTTNG_TRACKING_POLICY_INCLUDE_SET);

		const lttng_process_attr_values *lib_values;

		if (lttng_process_attr_tracker_handle_get_inclusion_set(_lib_handle, &lib_values) !=
		    LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_OK) {
			LTTNG_THROW_ERROR("Failed to get tracker inclusion set");
		}

		unsigned int count;

		if (lttng_process_attr_values_get_count(lib_values, &count) !=
		    LTTNG_PROCESS_ATTR_VALUES_STATUS_OK) {
			LTTNG_THROW_ERROR("Failed to get tracker value count");
		}

		std::set<process_attr_value> result;

		for (auto i = 0U; i < count; ++i) {
			result.emplace(lib_values, i);
		}

		return result;
	}

private:
	lttng_process_attr_tracker_handle *_lib_handle;
};

namespace internal {

static int domain_type_order(const lttng_domain_type domain_type) noexcept
{
	switch (domain_type) {
	case LTTNG_DOMAIN_KERNEL:
		return 0;
	case LTTNG_DOMAIN_UST:
		return 1;
	case LTTNG_DOMAIN_JUL:
		return 2;
	case LTTNG_DOMAIN_LOG4J:
		return 3;
	case LTTNG_DOMAIN_LOG4J2:
		return 4;
	case LTTNG_DOMAIN_PYTHON:
		return 5;
	default:
		return 100;
	}
}

} /* namespace internal */

class kernel_domain;
class ust_domain;
class java_python_domain;

/*
 * Holds information about a tracing domain.
 *
 * Get a specific wrapper with as_kernel(), as_ust(), or
 * as_java_python(), depending on type().
 *
 * Doesn't own the wrapped library handle pointer.
 */
class domain {
public:
	explicit domain(const lttng_handle& lib_handle) : _lib_handle(&lib_handle)
	{
	}

	c_string_view session_name() const noexcept
	{
		return _lib_handle->session_name;
	}

	lttng_domain_type type() const noexcept
	{
		return _lib_handle->domain.type;
	}

	lttng_buffer_type buffer_ownership_model() const noexcept
	{
		return _lib_handle->domain.buf_type;
	}

	channel_set<channel> channels() const
	{
		return _channels<channel>();
	}

	kernel_domain as_kernel() const noexcept;
	ust_domain as_ust() const noexcept;
	java_python_domain as_java_python() const noexcept;

	const lttng_domain& lib() const noexcept
	{
		return _lib_handle->domain;
	}

	const lttng_handle& lib_handle() const noexcept
	{
		return *_lib_handle;
	}

	bool operator<(const domain& other) const noexcept
	{
		const auto lhs = internal::domain_type_order(type());
		const auto rhs = internal::domain_type_order(other.type());

		if (lhs != rhs) {
			return lhs < rhs;
		}

		/* Consider same-type domains equivalent for ordering purposes */
		return false;
	}

protected:
	process_attr_tracker _tracker(const lttng_process_attr lib_process_attr,
				      const char *const type_str) const
	{
		lttng_process_attr_tracker_handle *lib_handle = nullptr;

		if (lttng_session_get_tracker_handle(
			    session_name().data(), type(), lib_process_attr, &lib_handle) !=
		    LTTNG_OK) {
			LTTNG_THROW_ERROR(
				lttng::format("Failed to get {} tracker handle", type_str));
		}

		LTTNG_ASSERT(lib_handle);
		return process_attr_tracker(*lib_handle);
	}

	template <typename ChannelType>
	channel_set<ChannelType> _channels() const
	{
		lttng_channel *lib_channels = nullptr;
		const auto count = lttng_list_channels(&lib_handle(), &lib_channels);

		if (count < 0) {
			LTTNG_THROW_ERROR("Failed to list channels");
		}

		LTTNG_ASSERT(count == 0 || lib_channels);
		return channel_set<ChannelType>(
			lib_handle(), lib_channels, static_cast<unsigned int>(count));
	}

private:
	const lttng_handle *_lib_handle;
};

/*
 * Holds information about a Linux kernel tracing domain.
 */
class kernel_domain final : public domain {
public:
	explicit kernel_domain(const lttng_handle& lib_handle) : domain(lib_handle)
	{
		LTTNG_ASSERT(type() == LTTNG_DOMAIN_KERNEL);
	}

	static kernel_tracepoint_set tracepoints()
	{
		return kernel_tracepoint_set();
	}

	static kernel_syscall_set syscalls()
	{
		return kernel_syscall_set();
	}

	channel_set<kernel_channel> channels() const
	{
		return _channels<kernel_channel>();
	}

	process_attr_tracker process_id_tracker() const
	{
		return _tracker(LTTNG_PROCESS_ATTR_PROCESS_ID, "process ID");
	}

	process_attr_tracker virtual_process_id_tracker() const
	{
		return _tracker(LTTNG_PROCESS_ATTR_VIRTUAL_PROCESS_ID, "virtual process ID");
	}

	process_attr_tracker user_id_tracker() const
	{
		return _tracker(LTTNG_PROCESS_ATTR_USER_ID, "user ID");
	}

	process_attr_tracker virtual_user_id_tracker() const
	{
		return _tracker(LTTNG_PROCESS_ATTR_VIRTUAL_USER_ID, "virtual user ID");
	}

	process_attr_tracker group_id_tracker() const
	{
		return _tracker(LTTNG_PROCESS_ATTR_GROUP_ID, "group ID");
	}

	process_attr_tracker virtual_group_id_tracker() const
	{
		return _tracker(LTTNG_PROCESS_ATTR_VIRTUAL_GROUP_ID, "virtual group ID");
	}
};

/*
 * Holds information about a UST tracing domain.
 */
class ust_domain final : public domain {
public:
	explicit ust_domain(const lttng_handle& lib_handle) : domain(lib_handle)
	{
		LTTNG_ASSERT(type() == LTTNG_DOMAIN_UST);
	}

	channel_set<ust_channel> channels() const
	{
		return _channels<ust_channel>();
	}

	static ust_tracepoint_set tracepoints()
	{
		return ust_tracepoint_set();
	}

	process_attr_tracker virtual_process_id_tracker() const
	{
		return _tracker(LTTNG_PROCESS_ATTR_VIRTUAL_PROCESS_ID, "virtual process ID");
	}

	process_attr_tracker virtual_user_id_tracker() const
	{
		return _tracker(LTTNG_PROCESS_ATTR_VIRTUAL_USER_ID, "virtual user ID");
	}

	process_attr_tracker virtual_group_id_tracker() const
	{
		return _tracker(LTTNG_PROCESS_ATTR_VIRTUAL_GROUP_ID, "virtual group ID");
	}
};

/*
 * Holds information about a Java/Python tracing domain
 * (`java.util.logging`, log4j 1.x, Log4j 2, Python).
 */
class java_python_domain final : public domain {
public:
	explicit java_python_domain(const lttng_handle& lib_handle) : domain(lib_handle)
	{
		LTTNG_ASSERT(type() == LTTNG_DOMAIN_JUL || type() == LTTNG_DOMAIN_LOG4J ||
			     type() == LTTNG_DOMAIN_LOG4J2 || type() == LTTNG_DOMAIN_PYTHON);
	}

	java_python_logger_set loggers() const
	{
		return java_python_logger_set(type());
	}

	/*
	 * Returns a snapshot of the available recording event rules for
	 * this domain directly (not through a channel).
	 */
	event_rule_set<java_python_logger_event_rule> event_rules() const
	{
		lttng_event *lib_events = nullptr;
		const auto count = lttng_list_events(&lib_handle(), "", &lib_events);

		if (count < 0) {
			LTTNG_THROW_ERROR("Failed to list recording event rules");
		}

		LTTNG_ASSERT(count == 0 || lib_events);
		return event_rule_set<java_python_logger_event_rule>(
			lib_events, static_cast<unsigned int>(count));
	}
};

inline kernel_domain domain::as_kernel() const noexcept
{
	return kernel_domain(*_lib_handle);
}

inline ust_domain domain::as_ust() const noexcept
{
	return ust_domain(*_lib_handle);
}

inline java_python_domain domain::as_java_python() const noexcept
{
	return java_python_domain(*_lib_handle);
}

/*
 * Holds information about tracing domains for a specific
 * recording session.
 */
class domain_set final {
public:
	domain_set(const char *const session_name,
		   lttng_domain *const lib_domains,
		   const unsigned int count)
	{
		LTTNG_ASSERT(session_name);
		LTTNG_ASSERT(count == 0 || lib_domains);

		for (auto i = 0U; i < count; ++i) {
			/* The handle contains a copy of the domain */
			const auto handle = lttng_create_handle(session_name, &lib_domains[i]);

			if (!handle) {
				LTTNG_THROW_ERROR("Failed to create handle for domain");
			}

			_lib_handles.push_back(handle);
			_set.emplace(*handle);
		}
	}

	domain_set(const domain_set&) = delete;

	domain_set(domain_set&& other) noexcept :
		_lib_handles(std::move(other._lib_handles)), _set(std::move(other._set))
	{
	}

	domain_set& operator=(const domain_set&) = delete;

	domain_set& operator=(domain_set&& other) noexcept
	{
		if (this != &other) {
			for (const auto handle : _lib_handles) {
				lttng_destroy_handle(handle);
			}

			_lib_handles = std::move(other._lib_handles);
			_set = std::move(other._set);
		}

		return *this;
	}

	~domain_set()
	{
		for (const auto handle : _lib_handles) {
			lttng_destroy_handle(handle);
		}
	}

	const std::set<domain>& set() const noexcept
	{
		return _set;
	}

	std::set<domain>::const_iterator begin() const noexcept
	{
		return _set.begin();
	}

	std::set<domain>::const_iterator end() const noexcept
	{
		return _set.end();
	}

	std::size_t size() const noexcept
	{
		return _set.size();
	}

	bool is_empty() const noexcept
	{
		return _set.empty();
	}

	nonstd::optional<domain> find_by_type(const lttng_domain_type domain_type) const noexcept
	{
		for (const auto& domain : _set) {
			if (domain.type() == domain_type) {
				return domain;
			}
		}

		return nonstd::nullopt;
	}

private:
	std::vector<lttng_handle *> _lib_handles;
	std::set<domain> _set;
};

class rotation_schedule_size;
class rotation_schedule_periodic;

/*
 * Holds information about an automatic recording session
 * rotation schedule.
 *
 * Get a specific wrapper with as_size() or as_periodic() depending
 * on type().
 *
 * Doesn't own the wrapped library pointer.
 */
class rotation_schedule {
public:
	explicit rotation_schedule(const lttng_rotation_schedule& lib_schedule) :
		_lib_schedule(&lib_schedule)
	{
	}

	lttng_rotation_schedule_type type() const noexcept
	{
		return lttng_rotation_schedule_get_type(_lib_schedule);
	}

	rotation_schedule_size as_size() const noexcept;
	rotation_schedule_periodic as_periodic() const noexcept;

	bool operator<(const rotation_schedule& other) const noexcept
	{
		if (type() == other.type()) {
			return false;
		}

		/* Enforce: periodic comes before by-size */
		if (type() == LTTNG_ROTATION_SCHEDULE_TYPE_PERIODIC &&
		    other.type() == LTTNG_ROTATION_SCHEDULE_TYPE_SIZE_THRESHOLD) {
			return true;
		}

		if (type() == LTTNG_ROTATION_SCHEDULE_TYPE_SIZE_THRESHOLD &&
		    other.type() == LTTNG_ROTATION_SCHEDULE_TYPE_PERIODIC) {
			return false;
		}

		/* Fallback to pointer values */
		return _lib_schedule < other._lib_schedule;
	}

	const lttng_rotation_schedule& lib() const noexcept
	{
		return *_lib_schedule;
	}

private:
	const lttng_rotation_schedule *_lib_schedule;
};

/*
 * Holds information about a size-based automatic recording session
 * rotation schedule.
 */
class rotation_schedule_size final : public rotation_schedule {
public:
	explicit rotation_schedule_size(const lttng_rotation_schedule& lib_schedule) :
		rotation_schedule(lib_schedule)
	{
		LTTNG_ASSERT(type() == LTTNG_ROTATION_SCHEDULE_TYPE_SIZE_THRESHOLD);
	}

	std::uint64_t threshold() const noexcept
	{
		std::uint64_t threshold_bytes = 0;
		const auto status = lttng_rotation_schedule_size_threshold_get_threshold(
			&lib(), &threshold_bytes);

		LTTNG_ASSERT(status == LTTNG_ROTATION_STATUS_OK);
		return threshold_bytes;
	}
};

/*
 * Holds information about a periodic automatic recording session
 * rotation schedule.
 */
class rotation_schedule_periodic final : public rotation_schedule {
public:
	explicit rotation_schedule_periodic(const lttng_rotation_schedule& schedule) :
		rotation_schedule(schedule)
	{
		LTTNG_ASSERT(type() == LTTNG_ROTATION_SCHEDULE_TYPE_PERIODIC);
	}

	std::uint64_t period() const noexcept
	{
		std::uint64_t period_us = 0;
		const auto status = lttng_rotation_schedule_periodic_get_period(&lib(), &period_us);

		LTTNG_ASSERT(status == LTTNG_ROTATION_STATUS_OK);
		return period_us;
	}
};

inline rotation_schedule_size rotation_schedule::as_size() const noexcept
{
	return rotation_schedule_size(*_lib_schedule);
}

inline rotation_schedule_periodic rotation_schedule::as_periodic() const noexcept
{
	return rotation_schedule_periodic(*_lib_schedule);
}

/*
 * Holds information about automatic recording session
 * rotation schedules.
 *
 * Owns the wrapped library pointer.
 */
class rotation_schedule_set final {
public:
	explicit rotation_schedule_set(lttng_rotation_schedules& lib_schedules) :
		_lib_schedules(&lib_schedules)
	{
		unsigned int count = 0;
		const auto status = lttng_rotation_schedules_get_count(_lib_schedules, &count);

		LTTNG_ASSERT(status == LTTNG_ROTATION_STATUS_OK);

		for (auto i = 0U; i < count; i++) {
			const auto lib_schedule =
				lttng_rotation_schedules_get_at_index(_lib_schedules, i);

			LTTNG_ASSERT(lib_schedule);
			_set.emplace(*lib_schedule);
		}
	}

	rotation_schedule_set(const rotation_schedule_set&) = delete;

	rotation_schedule_set(rotation_schedule_set&& other) noexcept :
		_lib_schedules(other._lib_schedules), _set(std::move(other._set))
	{
		other._lib_schedules = nullptr;
	}

	rotation_schedule_set& operator=(const rotation_schedule_set&) = delete;

	rotation_schedule_set& operator=(rotation_schedule_set&& other) noexcept
	{
		if (this != &other) {
			lttng_rotation_schedules_destroy(_lib_schedules);
			_lib_schedules = other._lib_schedules;
			_set = std::move(other._set);
			other._lib_schedules = nullptr;
		}

		return *this;
	}

	~rotation_schedule_set()
	{
		lttng_rotation_schedules_destroy(_lib_schedules);
	}

	const std::set<rotation_schedule>& set() const noexcept
	{
		return _set;
	}

	std::set<rotation_schedule>::const_iterator begin() const noexcept
	{
		return _set.begin();
	}

	std::set<rotation_schedule>::const_iterator end() const noexcept
	{
		return _set.end();
	}

	std::size_t size() const noexcept
	{
		return _set.size();
	}

	bool is_empty() const noexcept
	{
		return _set.empty();
	}

private:
	lttng_rotation_schedules *_lib_schedules = nullptr;
	std::set<rotation_schedule> _set;
};

/*
 * Holds information about a recording session.
 *
 * Doesn't own the wrapped library pointer.
 */
class session final {
public:
	explicit session(const lttng_session& lib_session) : _lib_session(&lib_session)
	{
	}

	c_string_view name() const noexcept
	{
		return _lib_session->name;
	}

	c_string_view output() const noexcept
	{
		return _lib_session->path;
	}

	bool is_active() const noexcept
	{
		return _lib_session->enabled != 0;
	}

	std::uint64_t creation_time() const
	{
		std::uint64_t timestamp;

		if (lttng_session_get_creation_time(_lib_session, &timestamp) != LTTNG_OK) {
			LTTNG_THROW_ERROR("Failed to get recording session creation time");
		}

		return timestamp;
	}

	nonstd::optional<unsigned int> live_timer_period_us() const noexcept
	{
		const auto period = _lib_session->live_timer_interval;

		if (period != 0) {
			return period;
		}

		return nonstd::nullopt;
	}

	/*
	 * Returns a snapshot of the available automatic rotation schedules
	 * of this recording session.
	 */
	rotation_schedule_set rotation_schedules() const
	{
		lttng_rotation_schedules *lib_schedules = nullptr;

		if (lttng_session_list_rotation_schedules(name().data(), &lib_schedules) !=
		    LTTNG_OK) {
			LTTNG_THROW_ERROR("Failed to list recording session rotation schedules");
		}

		LTTNG_ASSERT(lib_schedules);
		return rotation_schedule_set(*lib_schedules);
	}

	/*
	 * Returns a snapshot of the available tracing domains of this
	 * recording session.
	 */
	domain_set domains() const
	{
		auto list_result = [this]() {
			lttng_domain *raw_lib_domains = nullptr;
			const auto count = lttng_list_domains(name().data(), &raw_lib_domains);

			if (count < 0) {
				LTTNG_THROW_ERROR(
					"Failed to list tracing domains of recording session");
			}

			return std::make_pair(
				count,
				lttng::make_unique_wrapper<lttng_domain, lttng::memory::free>(
					raw_lib_domains));
		}();
		const auto count = list_result.first;
		const auto lib_domains = std::move(list_result.second);

		LTTNG_ASSERT(count == 0 || lib_domains);
		return domain_set(name(), lib_domains.get(), static_cast<unsigned int>(count));
	}

	bool is_snapshot_mode() const noexcept
	{
		return _lib_session->snapshot_mode != 0;
	}

	/*
	 * Returns a snapshot of the default recording session
	 * snapshot output.
	 *
	 * Returns `nonstd::nullopt` if there's no default snapshot output.
	 *
	 * Only valid when is_snapshot_mode() returns true.
	 */
	nonstd::optional<snapshot_output> default_snapshot_output() const
	{
		lttng_snapshot_output_list *lib_list = nullptr;

		if (lttng_snapshot_list_output(name().data(), &lib_list) != 0) {
			LTTNG_THROW_ERROR("Failed to list recording session snapshot outputs");
		}

		LTTNG_ASSERT(lib_list);

		const auto lib_output = lttng_snapshot_output_list_get_next(lib_list);

		if (!lib_output) {
			lttng_snapshot_output_list_destroy(lib_list);
			return nonstd::nullopt;
		}

		return snapshot_output(*lib_list, *lib_output);
	}

	c_string_view shm_dir_override() const noexcept
	{
		const char *shm_dir = nullptr;

		if (lttng_get_session_shm_path_override(_lib_session, &shm_dir) ==
		    LTTNG_GET_SESSION_SHM_PATH_STATUS_OK) {
			LTTNG_ASSERT(shm_dir);
			return c_string_view(shm_dir);
		}

		return c_string_view();
	}

	const lttng_session& lib() const noexcept
	{
		return *_lib_session;
	}

private:
	const lttng_session *_lib_session;
};

/*
 * Holds a list of recording sessions.
 *
 * Upon construction, the instance takes a snapshot of the available
 * recording sessions.
 *
 * The sessions are ordered as returned by lttng_list_sessions().
 */
class session_list final {
public:
	session_list()
	{
		const auto count = lttng_list_sessions(&_lib_sessions);

		if (count < 0) {
			LTTNG_THROW_ERROR("Failed to list recording sessions");
		}

		LTTNG_ASSERT(count == 0 || _lib_sessions);
		_list.reserve(static_cast<unsigned int>(count));

		for (auto i = 0U; i < static_cast<unsigned int>(count); ++i) {
			_list.emplace_back(_lib_sessions[i]);
		}
	}

	session_list(const session_list&) = delete;
	session_list(session_list&&) = default;
	session_list& operator=(const session_list&) = delete;
	session_list& operator=(session_list&&) = default;

	~session_list()
	{
		std::free(_lib_sessions);
	}

	std::vector<session>::const_iterator begin() const noexcept
	{
		return _list.begin();
	}

	std::vector<session>::const_iterator end() const noexcept
	{
		return _list.end();
	}

	std::size_t size() const noexcept
	{
		return _list.size();
	}

	bool is_empty() const noexcept
	{
		return _list.empty();
	}

	nonstd::optional<session> find_by_name(const char *const name) const noexcept
	{
		LTTNG_ASSERT(name);

		for (const auto& session : _list) {
			if (session.name() == name) {
				return session;
			}
		}

		return nonstd::nullopt;
	}

private:
	lttng_session *_lib_sessions = nullptr;
	std::vector<session> _list;
};

} /* namespace cli */
} /* namespace lttng */

#endif /* _LTTNG_LIST_WRAPPERS_HPP */
