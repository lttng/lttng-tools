/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_UST_KEY_REGISTRY_HPP
#define LTTNG_SESSIOND_UST_KEY_REGISTRY_HPP

#include "key-registry.hpp"

#include <common/string-utils/c-string-view.hpp>

#include <vendor/optional.hpp>

#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace lttng {
namespace sessiond {
namespace ust {

/*
 * Sessiond-owned key registry. Allocates flat indices from a local
 * pool sized after the channel's `max_entry_count`.
 *
 * Used by the UST `recv_register_key` reply path: when a UST app
 * announces a new key, the orchestrator resolves or allocates an
 * index here and ships it back to the application.
 */
class key_registry final : public sessiond::map::key_registry {
public:
	explicit key_registry(std::uint64_t capacity);

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

	std::uint64_t resolve_or_allocate(const std::string& key) override;

private:
	const std::uint64_t _capacity;
	mutable std::mutex _lock;
	/*
	 * `_indexes_by_key` owns the keys and maps them to their flat index.
	 *  `_keys_by_index` is the inverse view, kept positional (vector entry
	 * N is the key allocated at index N), and stores
	 * `lttng::c_string_view`s that refer to the strings stored in
	 * `_indexes_by_key`.
	 *
	 * `std::unordered_map` keeps element references stable across
	 * insertions and rehashing (only erasure invalidates them) and the
	 * registry never forgets.
	 */
	std::unordered_map<std::string, std::uint64_t> _indexes_by_key;
	std::vector<lttng::c_string_view> _keys_by_index;
};

} /* namespace ust */
} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_SESSIOND_UST_KEY_REGISTRY_HPP */
