/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "ust-trace-class-index.hpp"

namespace lsu = lttng::sessiond::ust;

void lsu::trace_class_index::add_per_uid(std::uint64_t recording_session_id,
					 std::uint32_t abi_bitness,
					 uid_t app_uid,
					 const std::shared_ptr<trace_class>& tc)
{
	const std::lock_guard<std::mutex> lock(_mutex);
	const _per_uid_key key = { recording_session_id, abi_bitness, app_uid };

	_per_uid_map[key] = tc;
}

void lsu::trace_class_index::remove_per_uid(std::uint64_t recording_session_id,
					    std::uint32_t abi_bitness,
					    uid_t app_uid)
{
	const std::lock_guard<std::mutex> lock(_mutex);
	const _per_uid_key key = { recording_session_id, abi_bitness, app_uid };

	_per_uid_map.erase(key);
}

std::shared_ptr<lsu::trace_class> lsu::trace_class_index::find_per_uid(
	std::uint64_t recording_session_id, std::uint32_t abi_bitness, uid_t app_uid) const
{
	const std::lock_guard<std::mutex> lock(_mutex);
	const _per_uid_key key = { recording_session_id, abi_bitness, app_uid };

	const auto it = _per_uid_map.find(key);
	return it != _per_uid_map.end() ? it->second : nullptr;
}

void lsu::trace_class_index::add_per_pid(std::uint64_t app_session_id,
					 const std::shared_ptr<trace_class>& tc)
{
	const std::lock_guard<std::mutex> lock(_mutex);

	_per_pid_map[app_session_id] = tc;
}

void lsu::trace_class_index::remove_per_pid(std::uint64_t app_session_id)
{
	const std::lock_guard<std::mutex> lock(_mutex);

	_per_pid_map.erase(app_session_id);
}

std::shared_ptr<lsu::trace_class>
lsu::trace_class_index::find_per_pid(std::uint64_t app_session_id) const
{
	const std::lock_guard<std::mutex> lock(_mutex);

	const auto it = _per_pid_map.find(app_session_id);
	return it != _per_pid_map.end() ? it->second : nullptr;
}
