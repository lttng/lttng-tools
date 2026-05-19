/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_KEY_REGISTRY_HPP
#define LTTNG_SESSIOND_KEY_REGISTRY_HPP

#include <common/string-utils/c-string-view.hpp>

#include <vendor/optional.hpp>

#include <cstdint>
#include <functional>
#include <memory>
#include <string>

namespace lttng {
namespace sessiond {
namespace map {

/*
 * Per-channel `string <-> index` mapping. Used by the `map_channel`'s
 * read path (to surface `(key, value)` pairs) and by group-level write
 * paths to resolve a key to a tracer-side index.
 *
 * Two implementations exist: one where sessiond owns the index pool
 * (`ust::key_registry`, used by UST) and one where the kernel tracer
 * is the allocator and sessiond proxies it (`modules::key_registry`).
 */
class key_registry {
public:
	using uptr = std::unique_ptr<key_registry>;
	/*
	 * Shared ownership of a registry. A map_channel is the sole strong
	 * owner of its registry, but the application-notification thread
	 * needs to upgrade a weak observer to a strong reference for the
	 * duration of a key resolution (see ust::app_objd_registry's
	 * map_channel_entry), so the registry must be held through a
	 * shared_ptr.
	 */
	using sptr = std::shared_ptr<key_registry>;
	using element_visitor = std::function<void(lttng::c_string_view key, std::uint64_t index)>;

	key_registry() = default;
	virtual ~key_registry() = default;

	key_registry(const key_registry&) = delete;
	key_registry(key_registry&&) = delete;
	key_registry& operator=(const key_registry&) = delete;
	key_registry& operator=(key_registry&&) = delete;

	virtual nonstd::optional<std::uint64_t> lookup(const std::string& key) const = 0;
	/*
	 * Returns a view of the key associated with `index`, or
	 * `nonstd::nullopt` if no such binding exists. The returned view
	 * is valid for the lifetime of the registry: implementations
	 * never erase entries, and the underlying storage guarantees
	 * stable string addresses across insertions.
	 */
	virtual nonstd::optional<lttng::c_string_view> key_for_index(std::uint64_t index) const = 0;
	virtual void for_each(const element_visitor& visitor) const = 0;
	virtual std::size_t size() const noexcept = 0;
	virtual std::uint64_t capacity() const noexcept = 0;

	/*
	 * Allocate a fresh index for `key` if not yet known, or return
	 * the existing index otherwise. Throws on dimension exhaustion.
	 *
	 * Not all subclasses support sessiond-side allocation: the
	 * `modules::key_registry` proxies an allocator that lives inside
	 * the kernel tracer and throws `lttng::runtime_error` when
	 * called.
	 */
	virtual std::uint64_t resolve_or_allocate(const std::string& key) = 0;
};

} /* namespace map */
} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_SESSIOND_KEY_REGISTRY_HPP */
