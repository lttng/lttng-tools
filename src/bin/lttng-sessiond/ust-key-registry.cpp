/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "ust-key-registry.hpp"

#include <common/exception.hpp>
#include <common/format.hpp>

namespace lttng {
namespace sessiond {
namespace ust {

key_registry::key_registry(std::uint64_t capacity) : _capacity(capacity)
{
}

nonstd::optional<std::uint64_t> key_registry::lookup(const std::string& key) const
{
	const std::lock_guard<std::mutex> guard(_lock);
	const auto it = _indexes_by_key.find(key);

	if (it == _indexes_by_key.end()) {
		return nonstd::nullopt;
	}

	return it->second;
}

nonstd::optional<lttng::c_string_view> key_registry::key_for_index(std::uint64_t index) const
{
	const std::lock_guard<std::mutex> guard(_lock);

	if (index >= _keys_by_index.size()) {
		return nonstd::nullopt;
	}

	return _keys_by_index[index];
}

void key_registry::for_each(const sessiond::map::key_registry::element_visitor& visitor) const
{
	const std::lock_guard<std::mutex> guard(_lock);

	for (const auto& kv : _indexes_by_key) {
		visitor(kv.first, kv.second);
	}
}

std::size_t key_registry::size() const noexcept
{
	const std::lock_guard<std::mutex> guard(_lock);

	return _keys_by_index.size();
}

std::uint64_t key_registry::capacity() const noexcept
{
	return _capacity;
}

std::uint64_t key_registry::resolve_or_allocate(const std::string& key)
{
	const std::lock_guard<std::mutex> guard(_lock);
	const auto it = _indexes_by_key.find(key);

	if (it != _indexes_by_key.end()) {
		return it->second;
	}

	if (_keys_by_index.size() >= _capacity) {
		LTTNG_THROW_MAP_DIMENSION_FULL_ERROR(lttng::format(
			"Sessiond-owned key registry dimension full: capacity={}, key=`{}`",
			_capacity,
			key));
	}

	const auto index = static_cast<std::uint64_t>(_keys_by_index.size());

	const auto inserted = _indexes_by_key.emplace(key, index);
	_keys_by_index.emplace_back(inserted.first->first.c_str());
	return index;
}

} /* namespace ust */
} /* namespace sessiond */
} /* namespace lttng */
