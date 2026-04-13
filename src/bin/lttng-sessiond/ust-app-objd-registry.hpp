/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef LTTNG_SESSIOND_UST_APP_OBJD_REGISTRY_HPP
#define LTTNG_SESSIOND_UST_APP_OBJD_REGISTRY_HPP

#include "ust-app-session-id.hpp"

#include <vendor/optional.hpp>

#include <cstdint>
#include <mutex>
#include <unordered_map>

namespace lttng {
namespace sessiond {
namespace ust {

/*
 * Per-application registry mapping UST object descriptors (handles) to
 * the identifying information needed by the notification handling
 * thread.
 *
 * The notification thread receives objds from UST applications and
 * needs to resolve them to a trace_class (via the global
 * trace_class_index) and, for channel objds, a channel registry key.
 * It achieves this using the app_session_identifier, which contains
 * the immutable properties needed for the trace_class_index lookup
 * (app_session_id, recording_session_id, credentials, abi, buffer
 * allocation policy).
 *
 * By storing these values directly in the registry at objd creation
 * time, the notification thread can resolve an objd to a trace_class
 * without acquiring any recording session lock or touching the domain
 * orchestrator. The registry's own mutex is the only lock involved.
 *
 * Entries are inserted and removed through RAII registration tokens
 * returned by register_session_objd() and register_channel_objd().
 * The token removes its entry on destruction, so the registry stays
 * consistent with the lifetime of the objects it indexes — without
 * requiring explicit management by the orchestrator.
 *
 * Thread safety: the registry has its own mutex. Since lookups copy
 * out plain values (no pointers to external objects), no lock ordering
 * constraints exist with respect to recording session or trace_class
 * locks.
 */
class app_objd_registry {
public:
	/*
	 * Information stored for a channel objd. Provides everything
	 * the notification thread needs to reach the trace_class and
	 * the channel within it.
	 */
	struct channel_entry {
		app_session_identifier session_id;
		/*
		 * Pre-computed channel registry key: either the
		 * trace_class_stream_class_handle (per-UID) or the
		 * consumer channel key (per-PID). This avoids the
		 * notification thread having to find the ust_app_channel
		 * object to determine which key to use.
		 */
		std::uint64_t channel_registry_key;
	};

	/*
	 * Information stored for a session objd. Provides the
	 * app_session_identifier for trace_class lookup.
	 */
	struct session_entry {
		app_session_identifier session_id;
	};

	/*
	 * RAII token that holds a single objd entry in the registry.
	 * The entry is removed when the token is destroyed.
	 *
	 * Tokens are non-copyable and moveable. A moved-from token is
	 * inert (its destructor is a no-op).
	 */
	class registration_token {
	public:
		registration_token(const registration_token&) = delete;
		registration_token& operator=(const registration_token&) = delete;

		registration_token(registration_token&& other) noexcept :
			_registry(other._registry), _objd(other._objd)
		{
			other._registry = nullptr;
		}

		registration_token& operator=(registration_token&& other) noexcept
		{
			if (this != &other) {
				_remove();
				_registry = other._registry;
				_objd = other._objd;
				other._registry = nullptr;
			}

			return *this;
		}

		~registration_token()
		{
			_remove();
		}

	private:
		friend class app_objd_registry;

		registration_token(app_objd_registry& registry, int objd) noexcept :
			_registry(&registry), _objd(objd)
		{
		}

		void _remove() noexcept
		{
			if (_registry) {
				_registry->_remove(_objd);
			}
		}

		app_objd_registry *_registry;
		int _objd;
	};

	app_objd_registry() = default;
	~app_objd_registry() = default;

	app_objd_registry(const app_objd_registry&) = delete;
	app_objd_registry(app_objd_registry&&) = delete;
	app_objd_registry& operator=(const app_objd_registry&) = delete;
	app_objd_registry& operator=(app_objd_registry&&) = delete;

	/*
	 * Register a session objd. Called when an app_session's UST
	 * tracer-side handle is obtained.
	 */
	registration_token register_session_objd(int objd, const app_session_identifier& session_id)
	{
		const std::lock_guard<std::mutex> guard(_lock);

		_session_entries[objd] = session_entry{ session_id };
		return registration_token(*this, objd);
	}

	/*
	 * Register a channel objd. Called when a ust_app_channel's UST
	 * tracer-side handle is obtained.
	 */
	registration_token register_channel_objd(int objd,
						 const app_session_identifier& session_id,
						 std::uint64_t channel_registry_key)
	{
		const std::lock_guard<std::mutex> guard(_lock);

		_channel_entries[objd] = channel_entry{ session_id, channel_registry_key };
		return registration_token(*this, objd);
	}

	/*
	 * Look up a session objd. Returns the session entry if found.
	 * Used by the notification thread for enum registration.
	 */
	nonstd::optional<session_entry> lookup_session(int objd) const noexcept
	{
		const std::lock_guard<std::mutex> guard(_lock);

		const auto it = _session_entries.find(objd);
		if (it == _session_entries.end()) {
			return nonstd::nullopt;
		}

		return it->second;
	}

	/*
	 * Look up a channel objd. Returns the channel entry if found.
	 * Used by the notification thread for channel registration and
	 * event registration.
	 */
	nonstd::optional<channel_entry> lookup_channel(int objd) const noexcept
	{
		const std::lock_guard<std::mutex> guard(_lock);

		const auto it = _channel_entries.find(objd);
		if (it == _channel_entries.end()) {
			return nonstd::nullopt;
		}

		return it->second;
	}

private:
	void _remove(int objd) noexcept
	{
		const std::lock_guard<std::mutex> guard(_lock);

		/*
		 * The objd could be in either map; try both. At most one
		 * will match.
		 */
		if (_session_entries.erase(objd) == 0) {
			_channel_entries.erase(objd);
		}
	}

	mutable std::mutex _lock;
	std::unordered_map<int, session_entry> _session_entries;
	std::unordered_map<int, channel_entry> _channel_entries;
};

} /* namespace ust */
} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_SESSIOND_UST_APP_OBJD_REGISTRY_HPP */
