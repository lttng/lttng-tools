/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_MAP_GROUP_IDENTITY_HPP
#define LTTNG_SESSIOND_MAP_GROUP_IDENTITY_HPP

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
 * Application bitness under which a group is reported, matching the
 * public lttng_app_bitness.
 */
enum class group_app_bitness : std::uint8_t {
	BITS_32 = 32,
	BITS_64 = 64,
};

/*
 * Uniquely addresses a group within its map channel; this is the identity
 * a client supplies to sample a specific group.
 *
 *   - KERNEL_GLOBAL and SHARED: owner_id and app_bitness are unset.
 *   - USER_PER_USER: owner_id is the Unix user id; app_bitness is the
 *     width of the counter values the owner's applications resolved to.
 *   - USER_PER_PROCESS: owner_id is the process id; app_bitness is the
 *     owning application's bitness.
 */
struct group_identity {
	group_type type;
	nonstd::optional<std::uint64_t> owner_id;
	nonstd::optional<group_app_bitness> app_bitness;

	bool operator==(const group_identity& other) const noexcept
	{
		return type == other.type && owner_id == other.owner_id &&
			app_bitness == other.app_bitness;
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
