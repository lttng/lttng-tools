/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_MODULES_KEY_REGISTRY_HPP
#define LTTNG_SESSIOND_MODULES_KEY_REGISTRY_HPP

#include "key-registry.hpp"

#include <common/file-descriptor.hpp>
#include <common/string-utils/c-string-view.hpp>

#include <vendor/optional.hpp>

#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>

namespace lttng {
namespace sessiond {

namespace config {
class map_channel_configuration;
} /* namespace config */

namespace modules {

/*
 * Transparent proxy over the modules tracer's
 * COUNTER_MAP_NR_DESCRIPTORS / COUNTER_MAP_DESCRIPTOR ioctls.
 *
 * Sessiond does not allocate indices itself; the kernel tracer assigns
 * them at enabler-sync time and sessiond pulls `(key, index)`
 * tuples on demand. The registry caches every binding it has seen so
 * that subsequent lookups by index avoid re-issuing the ioctl, while
 * misses on `lookup(key)` and `for_each` refresh the cache against
 * the kernel.
 *
 * `resolve_or_allocate` is not meaningful here and throws.
 */
class key_registry final : public sessiond::map::key_registry {
public:
	key_registry(const lttng::file_descriptor& counter_fd,
		     const config::map_channel_configuration& configuration);

	~key_registry() override = default;

	key_registry(const key_registry&) = delete;
	key_registry(key_registry&&) = delete;
	key_registry& operator=(const key_registry&) = delete;
	key_registry& operator=(key_registry&&) = delete;

	nonstd::optional<std::uint64_t> lookup(const std::string& key) const override;
	nonstd::optional<lttng::c_string_view> key_for_index(std::uint64_t index) const override;
	void for_each(const sessiond::map::key_registry::element_visitor& visitor) const override;
	std::size_t size() const noexcept override;
	std::uint64_t capacity() const noexcept override;

	/* Always throws as allocation is owned by the kernel tracer. */
	[[noreturn]] std::uint64_t resolve_or_allocate(const std::string& key) override;

private:
	/*
	 * Refresh the cache by enumerating descriptors the kernel knows
	 * about. New keys may be allocated concurrently on the kernel
	 * side, so the snapshot returned by NR_DESCRIPTORS is best-effort
	 * and the cache may miss bindings that were created after the
	 * refresh started.
	 */
	void _refresh_cache() const;

	/* Owned by the channel's map_group, which outlives this registry. */
	const lttng::file_descriptor& _counter_fd;
	const config::map_channel_configuration& _configuration;
	mutable std::mutex _lock;
	/*
	 * `_indexes_by_key` owns the key strings; `_keys_by_index` views
	 * them through `lttng::c_string_view`. `std::unordered_map`
	 * guarantees that references to keys remain valid across
	 * insertions and rehashing (only erasure invalidates them), and
	 * the registry never erases.
	 */
	mutable std::unordered_map<std::string, std::uint64_t> _indexes_by_key;
	mutable std::unordered_map<std::uint64_t, lttng::c_string_view> _keys_by_index;
};

} /* namespace modules */
} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_SESSIOND_MODULES_KEY_REGISTRY_HPP */
