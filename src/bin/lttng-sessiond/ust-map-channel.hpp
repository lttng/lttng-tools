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
#include "ust-application-abi.hpp"
#include "ust-map-group.hpp"

#include <common/hash-combine.hpp>

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
 *   - per-(uid, application_abi) `ust::map_group`s, when the channel's
 *     `buffer_ownership` is PER_UID; or
 *   - per-app `ust::map_group`s, when the channel's
 *     `buffer_ownership` is PER_PID.
 *
 * Exactly one of the two storage maps is populated. The decision is
 * fixed at construction time from the configuration.
 */
class map_channel final : public sessiond::map::map_channel {
public:
	using uid_abi_key = std::pair<uid_t, application_abi>;

	struct uid_abi_key_hash {
		std::size_t operator()(const uid_abi_key& key) const noexcept
		{
			auto seed =
				std::hash<std::uint32_t>{}(static_cast<std::uint32_t>(key.first));
			seed = lttng::utils::hash_combine(
				seed,
				std::hash<std::uint8_t>{}(static_cast<std::uint8_t>(key.second)));
			return seed;
		}
	};

	using per_uid_groups =
		std::unordered_map<uid_abi_key, std::unique_ptr<ust::map_group>, uid_abi_key_hash>;
	using per_app_groups = std::unordered_map<pid_t, std::unique_ptr<ust::map_group>>;

	using uid_group_visitor =
		std::function<void(uid_t uid, application_abi abi, const ust::map_group& group)>;
	using app_group_visitor =
		std::function<void(const ust::app& app, const ust::map_group& group)>;

	map_channel(const config::map_channel_configuration& configuration,
		    sessiond::map::key_registry::uptr registry);

	~map_channel() override = default;
	map_channel(const map_channel&) = delete;
	map_channel(map_channel&&) = delete;
	map_channel& operator=(const map_channel&) = delete;
	map_channel& operator=(map_channel&&) = delete;

	/*
	 * per-UID API. Creates the (uid, abi) group on first call;
	 * subsequent calls with the same key return the existing group.
	 *
	 * Throws if the channel is not configured for per-UID buffers.
	 */
	ust::map_group& add_uid_group(uid_t uid, application_abi abi);
	void remove_uid_group(uid_t uid, application_abi abi);
	void for_each_uid_group(const uid_group_visitor& visitor) const;

	/*
	 * per-PID API. The orchestrator calls `add_app_group` on first
	 * attach and `remove_app_group` on app departure; the latter
	 * applies the channel's `dead_group_policy` (DROP /
	 * SUM_INTO_SHARED) before destroying the group.
	 *
	 * Throws if the channel is not configured for per-PID buffers.
	 */
	ust::map_group& add_app_group(const ust::app& app);
	void remove_app_group(const ust::app& app);
	void for_each_app_group(const app_group_visitor& visitor) const;

private:
	per_uid_groups _per_uid_groups;
	per_app_groups _per_app_groups;
};

} /* namespace ust */
} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_SESSIOND_UST_MAP_CHANNEL_HPP */
