/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_PROCESS_ATTRIBUTE_TRACKER_HPP
#define LTTNG_SESSIOND_PROCESS_ATTRIBUTE_TRACKER_HPP

#include <common/exception.hpp>

#include <vendor/optional.hpp>

#include <set>
#include <string>
#include <sys/types.h>

namespace lttng {
namespace sessiond {
namespace config {

/* Tracking policy for a process attribute tracker. */
enum class tracking_policy {
	/* Track all processes (no filtering) (default). */
	INCLUDE_ALL,
	/* Track no processes. */
	EXCLUDE_ALL,
	/* Track only processes with attribute values in the inclusion set. */
	INCLUDE_SET
};

/*
 * A resolved process attribute value for UID/GID trackers.
 *
 * Always contains the resolved numeric ID (uid_t/gid_t). When the value was
 * originally specified by name (user name or group name), the original name
 * is also stored for display purposes.
 *
 * Comparison and hashing use only the numeric ID, so adding "root" and uid 0
 * are treated as duplicates (matching the legacy tracker behavior).
 */
template <typename IntegralType>
class resolved_process_attr_value final {
public:
	/* Construct with numeric value only. */
	explicit resolved_process_attr_value(IntegralType resolved_id) : _resolved_id(resolved_id)
	{
	}

	/* Construct with both resolved numeric value and original name. */
	resolved_process_attr_value(IntegralType resolved_id, std::string original_name) :
		_resolved_id(resolved_id), _original_name(std::move(original_name))
	{
	}

	IntegralType id() const noexcept
	{
		return _resolved_id;
	}

	bool has_name() const noexcept
	{
		return static_cast<bool>(_original_name);
	}

	const std::string& name() const
	{
		LTTNG_ASSERT(_original_name);
		return *_original_name;
	}

	/* Comparison uses only the resolved numeric ID. */
	bool operator==(const resolved_process_attr_value& other) const noexcept
	{
		return _resolved_id == other._resolved_id;
	}

	bool operator!=(const resolved_process_attr_value& other) const noexcept
	{
		return !(*this == other);
	}

	bool operator<(const resolved_process_attr_value& other) const noexcept
	{
		return _resolved_id < other._resolved_id;
	}

private:
	IntegralType _resolved_id;
	nonstd::optional<std::string> _original_name;
};

/*
 * Type-safe process attribute tracker.
 *
 * Tracks process attribute values using an inclusion set policy. Processes
 * are only traced if their attribute value is in the tracker's inclusion set
 * (when policy is INCLUDE_SET), or all/none are traced (INCLUDE_ALL/EXCLUDE_ALL).
 *
 * ValueType must support operator< for storage in std::set.
 */
template <typename ValueType>
class process_attribute_tracker final {
public:
	using value_type = ValueType;

	process_attribute_tracker() = default;
	~process_attribute_tracker() = default;

	process_attribute_tracker(process_attribute_tracker&&) noexcept = default;
	process_attribute_tracker& operator=(process_attribute_tracker&&) noexcept = default;

	process_attribute_tracker(const process_attribute_tracker&) = delete;
	process_attribute_tracker& operator=(const process_attribute_tracker&) = delete;

	tracking_policy policy() const noexcept
	{
		return _policy;
	}

	void policy(tracking_policy new_policy)
	{
		if (_policy == new_policy) {
			return;
		}

		/* Clear inclusion set when changing policy. */
		_inclusion_set.clear();
		_policy = new_policy;
	}

	/*
	 * Add a value to the inclusion set.
	 * Only valid when policy is INCLUDE_SET.
	 * Returns true if the value was added, false if it already existed.
	 */
	bool add(ValueType value)
	{
		LTTNG_ASSERT(_policy == tracking_policy::INCLUDE_SET);
		return _inclusion_set.insert(std::move(value)).second;
	}

	/*
	 * Remove a value from the inclusion set.
	 * Only valid when policy is INCLUDE_SET.
	 * Returns true if the value was removed, false if it wasn't present.
	 */
	bool remove(const ValueType& value)
	{
		LTTNG_ASSERT(_policy == tracking_policy::INCLUDE_SET);
		return _inclusion_set.erase(value) > 0;
	}

	/*
	 * Check if a value is in the inclusion set.
	 * Only valid when policy is INCLUDE_SET.
	 */
	bool contains(const ValueType& value) const
	{
		LTTNG_ASSERT(_policy == tracking_policy::INCLUDE_SET);
		return _inclusion_set.find(value) != _inclusion_set.end();
	}

	/*
	 * Get the inclusion set for iteration.
	 * Only valid when policy is INCLUDE_SET.
	 */
	const std::set<ValueType>& inclusion_set() const noexcept
	{
		LTTNG_ASSERT(_policy == tracking_policy::INCLUDE_SET);
		return _inclusion_set;
	}

	/*
	 * Check if a value should be tracked based on the current policy.
	 */
	bool is_tracked(const ValueType& value) const noexcept
	{
		switch (_policy) {
		case tracking_policy::INCLUDE_ALL:
			return true;
		case tracking_policy::EXCLUDE_ALL:
			return false;
		case tracking_policy::INCLUDE_SET:
			return _inclusion_set.find(value) != _inclusion_set.end();
		}

		return false;
	}

private:
	tracking_policy _policy = tracking_policy::INCLUDE_ALL;
	std::set<ValueType> _inclusion_set;
};

/* Concrete tracker types. */
using process_id_tracker_t = process_attribute_tracker<pid_t>;
using virtual_process_id_tracker_t = process_attribute_tracker<pid_t>;
using user_id_tracker_t = process_attribute_tracker<resolved_process_attr_value<uid_t>>;
using virtual_user_id_tracker_t = process_attribute_tracker<resolved_process_attr_value<uid_t>>;
using group_id_tracker_t = process_attribute_tracker<resolved_process_attr_value<gid_t>>;
using virtual_group_id_tracker_t = process_attribute_tracker<resolved_process_attr_value<gid_t>>;

} /* namespace config */
} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_SESSIOND_PROCESS_ATTRIBUTE_TRACKER_HPP */
