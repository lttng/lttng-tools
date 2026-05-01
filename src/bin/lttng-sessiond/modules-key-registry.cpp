/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "map-channel-configuration.hpp"
#include "modules-key-registry.hpp"

#include <common/error.hpp>
#include <common/exception.hpp>
#include <common/format.hpp>
#include <common/kernel-ctl/kernel-ctl.hpp>

#include <cstdint>
#include <vector>

namespace lttng {
namespace sessiond {
namespace modules {

key_registry::key_registry(const lttng::file_descriptor& counter_fd,
			   const config::map_channel_configuration& configuration) :
	_counter_fd(counter_fd), _configuration(configuration)
{
}

void key_registry::_refresh_cache() const
{
	std::uint64_t nr = 0;
	const auto ret = kernctl_counter_map_nr_descriptors(_counter_fd.fd(), &nr);

	if (ret != 0) {
		LTTNG_THROW_POSIX(
			lttng::format(
				"Failed to query kernel counter descriptor count: map_name=`{}`",
				_configuration.name),
			-ret);
	}

	/*
	 * Resume from where the last refresh left off: the kernel's
	 * descriptor table is append-only and indices are stable, so
	 * descriptors below `_indexes_by_key.size()` are already cached.
	 */
	for (std::uint64_t i = _indexes_by_key.size(); i < nr; i++) {
		std::string key;
		std::uint32_t dimension = 0;
		std::uint64_t user_token = 0;
		std::vector<std::uint64_t> array_indexes;

		const auto desc_ret = kernctl_counter_map_descriptor(
			_counter_fd.fd(), i, &dimension, &user_token, &key, &array_indexes);
		if (desc_ret != 0) {
			LTTNG_THROW_POSIX(
				lttng::format(
					"Failed to read kernel counter descriptor: map_name=`{}`, index={}",
					_configuration.name,
					i),
				-desc_ret);
		}

		if (array_indexes.size() != 1) {
			/* The only expected size as of this version. */
			LTTNG_THROW_UNSUPPORTED_ERROR(fmt::format(
				"Unexpected indices count encountered when enumerating modules map descriptor: map_name=`{}`, indices_count={}",
				_configuration.name,
				array_indexes.size()));
		}

		const auto flat_index = array_indexes[0];

		const auto inserted = _indexes_by_key.emplace(std::move(key), flat_index);
		_keys_by_index.emplace(flat_index, inserted.first->first.c_str());
	}
}

nonstd::optional<std::uint64_t> key_registry::lookup(const std::string& key) const
{
	const std::lock_guard<std::mutex> guard(_lock);

	const auto it = _indexes_by_key.find(key);
	if (it != _indexes_by_key.end()) {
		return it->second;
	}

	_refresh_cache();

	const auto refreshed = _indexes_by_key.find(key);
	if (refreshed == _indexes_by_key.end()) {
		return nonstd::nullopt;
	}

	return refreshed->second;
}

nonstd::optional<lttng::c_string_view> key_registry::key_for_index(std::uint64_t index) const
{
	const std::lock_guard<std::mutex> guard(_lock);
	const auto it = _keys_by_index.find(index);

	if (it != _keys_by_index.end()) {
		return it->second;
	}

	_refresh_cache();

	const auto refreshed = _keys_by_index.find(index);
	if (refreshed == _keys_by_index.end()) {
		return nonstd::nullopt;
	}

	return refreshed->second;
}

void key_registry::for_each(const sessiond::map::key_registry::element_visitor& visitor) const
{
	const std::lock_guard<std::mutex> guard(_lock);

	_refresh_cache();

	for (const auto& kv : _indexes_by_key) {
		visitor(kv.first, kv.second);
	}
}

std::size_t key_registry::size() const noexcept
{
	const std::lock_guard<std::mutex> guard(_lock);

	return _indexes_by_key.size();
}

std::uint64_t key_registry::capacity() const noexcept
{
	return _configuration.max_entry_count;
}

std::uint64_t key_registry::resolve_or_allocate(const std::string& key)
{
	LTTNG_THROW_UNSUPPORTED_ERROR(lttng::format(
		"resolve_or_allocate is not supported on a kernel-backed key registry: map_name=`{}`, key=`{}`",
		_configuration.name,
		key));
}

} /* namespace modules */
} /* namespace sessiond */
} /* namespace lttng */
