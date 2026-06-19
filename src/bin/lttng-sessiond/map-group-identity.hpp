/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_MAP_GROUP_IDENTITY_HPP
#define LTTNG_SESSIOND_MAP_GROUP_IDENTITY_HPP

#include "map-channel-configuration.hpp"

#include <vendor/optional.hpp>

#include <cstdint>
#include <string>

namespace lttng {
namespace sessiond {
namespace map {

/* Kind of map group, mirroring the public lttng_map_group_type. */
enum class group_type : std::uint8_t {
	KERNEL_GLOBAL,
	USER_PER_USER,
	USER_PER_PROCESS,
	SHARED,
};

/*
 * Uniquely addresses a group within its map channel; this is the identity
 * a client supplies to sample a specific group.
 *
 *   - KERNEL_GLOBAL and SHARED: owner_id is unset.
 *   - USER_PER_USER: owner_id is the Unix user id.
 *   - USER_PER_PROCESS: owner_id is the process id.
 *
 * `value_type` is the group's effective value type (see
 * `map::group::value_type()`); for USER_PER_USER it is also a discriminator,
 * as a single owner may host both a 32-bit and a 64-bit group at once. It is
 * always a concrete width, never SIGNED_INT_MAX.
 */
struct group_identity {
	group_type type;
	nonstd::optional<std::uint64_t> owner_id;
	config::map_channel_configuration::value_type_t value_type;

	bool operator==(const group_identity& other) const noexcept
	{
		return type == other.type && owner_id == other.owner_id &&
			value_type == other.value_type;
	}

	bool operator!=(const group_identity& other) const noexcept
	{
		return !(*this == other);
	}
};

/* Identity of a group along with its display-only attributes. */
struct group_description {
	group_identity identity;

	/*
	 * Human-readable owner name when the channel knows it (the
	 * application name of a USER_PER_PROCESS group). Resolving a Unix
	 * user id to a name is left to the consumer.
	 */
	nonstd::optional<std::string> owner_name;
};

} /* namespace map */
} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_SESSIOND_MAP_GROUP_IDENTITY_HPP */
