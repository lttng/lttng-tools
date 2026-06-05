/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_UST_MAP_CHANNEL_HPP
#define LTTNG_SESSIOND_UST_MAP_CHANNEL_HPP

#include "key-registry.hpp"
#include "map-channel.hpp"
#include "ust-app-objd-registry.hpp"
#include "ust-map-group.hpp"

#include <common/hash-combine.hpp>

#include <vendor/optional.hpp>

#include <cstdint>
#include <functional>
#include <memory>
#include <sys/types.h>
#include <unordered_map>
#include <utility>

namespace lttng {
namespace sessiond {

namespace config {
class map_channel_configuration;
} /* namespace config */

namespace ust {

struct app;

/*
 * UST-domain map channel. Owns either:
 *
 *   - per-(uid, value type) `ust::map_group`s, when the channel's
 *     `buffer_ownership` is PER_UID; or
 *   - per-app `ust::map_group`s, when the channel's
 *     `buffer_ownership` is PER_PID.
 *
 * The per-UID groups are keyed by the counter's resolved value type
 * rather than the application's ABI: a counter of a given value type is
 * shared by every application that resolves to that value type, so a uid
 * whose value type yields 32-bit counters keeps a single group for its
 * 32 and 64-bit applications alike.
 *
 * Exactly one of the two storage maps is populated. The decision is
 * fixed at construction time from the configuration.
 */
class map_channel final : public sessiond::map::map_channel {
public:
	using value_type_t = config::map_channel_configuration::value_type_t;
	using uid_value_type_key = std::pair<uid_t, value_type_t>;

	struct uid_value_type_key_hash {
		std::size_t operator()(const uid_value_type_key& key) const noexcept
		{
			auto seed =
				std::hash<std::uint32_t>{}(static_cast<std::uint32_t>(key.first));
			seed = lttng::utils::hash_combine(
				seed,
				std::hash<std::uint8_t>{}(static_cast<std::uint8_t>(key.second)));
			return seed;
		}
	};

	using per_uid_groups = std::unordered_map<uid_value_type_key,
						  std::unique_ptr<ust::map_group>,
						  uid_value_type_key_hash>;
	using per_app_groups =
		std::unordered_map<const ust::app *, std::unique_ptr<ust::map_group>>;

	using uid_group_visitor =
		std::function<void(uid_t uid, value_type_t value_type, const ust::map_group& group)>;
	using app_group_visitor =
		std::function<void(const ust::app& app, const ust::map_group& group)>;

	/*
	 * RAII handle bundling a per-app counter attachment with the
	 * objd-registry token that lets the notification thread resolve
	 * the master counter's app-side handle to this channel's key
	 * registry.
	 *
	 * Destruction releases both: the underlying map_group::app_handle
	 * tears down the duplicated counter handles on the application,
	 * and the registration_token unregisters the entry from the app's
	 * objd registry.
	 */
	class app_attachment final {
	public:
		app_attachment(ust::map_group::app_handle counter_attachment,
			       app_objd_registry::registration_token objd_token) noexcept;

		app_attachment(app_attachment&&) noexcept = default;
		app_attachment(const app_attachment&) = delete;
		app_attachment& operator=(app_attachment&&) = delete;
		app_attachment& operator=(const app_attachment&) = delete;
		~app_attachment() = default;

		/*
		 * App-side object data of the master counter backing this
		 * attachment, used as the `counter_data` when installing a
		 * counter-event rule on the application. Borrowed; owned by the
		 * underlying map_group::app_handle.
		 */
		lttng_ust_abi_object_data *master_object_data() const noexcept
		{
			return _counter_attachment.master_object_data();
		}

	private:
		ust::map_group::app_handle _counter_attachment;
		app_objd_registry::registration_token _objd_token;
	};

	map_channel(const config::map_channel_configuration& configuration,
		    sessiond::map::key_registry::uptr registry);

	~map_channel() override = default;
	map_channel(const map_channel&) = delete;
	map_channel(map_channel&&) = delete;
	map_channel& operator=(const map_channel&) = delete;
	map_channel& operator=(map_channel&&) = delete;

	/*
	 * per-UID API. `resolved_value_type` is the concrete value type of
	 * the group's counter (see `resolve_map_value_type()`) and also keys
	 * the group: the counter is created on the first call for a given
	 * (uid, resolved_value_type) and reused by subsequent calls,
	 * regardless of the calling applications' own ABIs.
	 */
	ust::map_group& add_uid_group(uid_t uid, value_type_t resolved_value_type);
	void remove_uid_group(uid_t uid, value_type_t resolved_value_type);
	void for_each_uid_group(const uid_group_visitor& visitor) const;

	/*
	 * per-PID API. The orchestrator calls `add_app_group` on first
	 * attach and `remove_app_group` on app departure; the latter
	 * applies the channel's `dead_group_policy` (DROP /
	 * SUM_INTO_SHARED) before destroying the group.
	 *
	 * Throws if the channel is not configured for per-PID buffers.
	 */
	ust::map_group& add_app_group(const ust::app& app, value_type_t resolved_value_type);
	void remove_app_group(const ust::app& app);
	void for_each_app_group(const app_group_visitor& visitor) const;

	/*
	 * Attach this channel to `app`: for per-UID channels, lazily
	 * create the (app.uid, resolved value type) group, send the master
	 * and per-CPU counter handles to the app using `session_parent_handle`
	 * as the app-side parent, and return an RAII attachment bundling
	 * the resulting counter handle with an objd-registry token. The
	 * caller stores the attachment; dropping it releases everything.
	 *
	 * `session_parent_handle` is the app-side handle for the
	 * recording session that owns this map channel (the value of
	 * `ust::app_session::handle`).
	 *
	 * Returns nullopt when the channel's value type can't be served to
	 * this application (a 64-bit value type met by a 32-bit application);
	 * the channel is then skipped for that app, which is logged here.
	 *
	 * Throws on app-side communication failure
	 * (`ust::app_communication_error`); the caller must translate
	 * to its own status semantics.
	 */
	nonstd::optional<app_attachment> attach_to_app(ust::app& app, int session_parent_handle);

	struct rule_record {
		std::uint64_t user_token;
		/*
		 * Per-app attachments live on the relevant app_session via
		 * counter_event_attachments, keyed by (channel, event_rule,
		 * action); the channel-scoped rule record itself carries only
		 * the user_token.
		 */
	};

	/*
	 * Records of the counter-event rules registered against this channel,
	 * keyed by (&event_rule, &incr_map_value_action). Owned by the channel
	 * for each rule's registered lifetime; populated and cleared by the UST
	 * orchestrator, the sole accessor.
	 */
	std::unordered_map<sessiond::map::event_rule_action_key,
			   rule_record,
			   sessiond::map::event_rule_action_key_hash>
		_rules;

private:
	per_uid_groups _per_uid_groups;
	per_app_groups _per_app_groups;
};

} /* namespace ust */
} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_SESSIOND_UST_MAP_CHANNEL_HPP */
