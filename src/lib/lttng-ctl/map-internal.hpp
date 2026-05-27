/*
 * SPDX-FileCopyrightText: 2026 EfficiOS Inc.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_CTL_MAP_INTERNAL_HPP
#define LTTNG_CTL_MAP_INTERNAL_HPP

#include <common/defaults.hpp>

#include <lttng/domain.h>
#include <lttng/map/channel-buffer-ownership.h>
#include <lttng/map/channel-dead-group-policy.h>
#include <lttng/map/channel-type.h>
#include <lttng/map/channel-update-policy.h>
#include <lttng/map/group-type.h>
#include <lttng/map/key-type.h>
#include <lttng/map/value-type.h>

#include <vendor/optional.hpp>

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

/*
 * The opaque map handle types are defined here, in a single private
 * header, so that the map sources (split by API object family) all
 * share the same layouts: a map channel embeds its key set, and the
 * channel sources build the group and values sets returned by the
 * sampling API.
 */

struct lttng_map_values {
	nonstd::optional<unsigned int> partition_id;
	std::vector<int64_t> signed_values;
	std::vector<bool> has_overflow;
};

struct lttng_map_values_set {
	std::vector<std::unique_ptr<lttng_map_values>> values;
};

/*
 * A map group carries enough identity to address a SAMPLE_MAP_GROUP
 * request to the session daemon: the recording session name, the map
 * channel type and name, plus the (type, owner_id, effective_value_type)
 * group selector. The group holds no cached values:
 * lttng_map_group_get_values() samples them live.
 */
struct lttng_map_group {
	std::string session_name;
	enum lttng_map_channel_type channel_type = LTTNG_MAP_CHANNEL_TYPE_USER;
	std::string channel_name;
	enum lttng_map_group_type type = LTTNG_MAP_GROUP_TYPE_SHARED;
	uint64_t owner_id = 0;
	std::string owner_name;
	enum lttng_map_value_type effective_value_type = LTTNG_MAP_VALUE_TYPE_SIGNED_INT_64;
};

struct lttng_map_group_set {
	std::vector<std::unique_ptr<lttng_map_group>> groups;
};

struct lttng_map_key {
	enum lttng_map_key_type type = LTTNG_MAP_KEY_TYPE_STRING;
	uint64_t index = 0;
	std::string str;
};

struct lttng_map_key_set {
	enum lttng_map_key_type type = LTTNG_MAP_KEY_TYPE_STRING;
	std::vector<std::unique_ptr<lttng_map_key>> keys;
};

struct lttng_map_channel {
	/*
	 * Recording session that owns this channel. Stored so that the map
	 * groups derived from this channel can issue live sampling requests
	 * to the session daemon.
	 */
	std::string session_name;
	std::string name;
	enum lttng_map_channel_type type = LTTNG_MAP_CHANNEL_TYPE_USER;
	enum lttng_map_value_type value_type = LTTNG_MAP_VALUE_TYPE_SIGNED_INT_64;
	uint64_t max_key_count = DEFAULT_MAP_CHANNEL_MAX_KEY_COUNT;
	enum lttng_map_channel_update_policy update_policy =
		LTTNG_MAP_CHANNEL_UPDATE_POLICY_PER_EVENT;
	enum lttng_map_channel_buffer_ownership buffer_ownership =
		LTTNG_MAP_CHANNEL_BUFFER_OWNERSHIP_PER_UID;
	enum lttng_map_channel_dead_group_policy dead_group_policy =
		LTTNG_MAP_CHANNEL_DEAD_GROUP_POLICY_SUM_INTO_SHARED;
	lttng_map_key_set keys;
};

struct lttng_map_channel_set {
	std::vector<std::unique_ptr<lttng_map_channel>> channels;
};

struct lttng_map_channel_descriptor {
	std::string name;
	bool name_is_set = false;
	enum lttng_map_channel_type type = LTTNG_MAP_CHANNEL_TYPE_USER;
	enum lttng_map_key_type key_type = LTTNG_MAP_KEY_TYPE_STRING;
	enum lttng_map_value_type value_type = LTTNG_MAP_VALUE_TYPE_SIGNED_INT_64;
	uint64_t max_key_count = DEFAULT_MAP_CHANNEL_MAX_KEY_COUNT;
	enum lttng_map_channel_update_policy update_policy =
		LTTNG_MAP_CHANNEL_UPDATE_POLICY_PER_EVENT;
	enum lttng_map_channel_buffer_ownership buffer_ownership =
		LTTNG_MAP_CHANNEL_BUFFER_OWNERSHIP_PER_UID;
	enum lttng_map_channel_dead_group_policy dead_group_policy =
		LTTNG_MAP_CHANNEL_DEAD_GROUP_POLICY_SUM_INTO_SHARED;
};

namespace lttng {
namespace ctl {
namespace map {
namespace details {

inline bool value_type_is_valid(const enum lttng_map_value_type value_type)
{
	switch (value_type) {
	case LTTNG_MAP_VALUE_TYPE_SIGNED_INT_32:
	case LTTNG_MAP_VALUE_TYPE_SIGNED_INT_64:
	case LTTNG_MAP_VALUE_TYPE_SIGNED_INT_MAX:
		return true;
	default:
		return false;
	}
}

inline bool channel_type_is_valid(const enum lttng_map_channel_type type)
{
	switch (type) {
	case LTTNG_MAP_CHANNEL_TYPE_USER:
	case LTTNG_MAP_CHANNEL_TYPE_KERNEL:
		return true;
	default:
		return false;
	}
}

inline bool key_type_is_valid(const enum lttng_map_key_type type)
{
	switch (type) {
	case LTTNG_MAP_KEY_TYPE_STRING:
		return true;
	default:
		return false;
	}
}

inline bool update_policy_is_valid(const enum lttng_map_channel_update_policy policy)
{
	switch (policy) {
	case LTTNG_MAP_CHANNEL_UPDATE_POLICY_PER_EVENT:
	case LTTNG_MAP_CHANNEL_UPDATE_POLICY_PER_RULE_MATCH:
		return true;
	default:
		return false;
	}
}

inline bool buffer_ownership_is_valid(const enum lttng_map_channel_buffer_ownership ownership)
{
	switch (ownership) {
	case LTTNG_MAP_CHANNEL_BUFFER_OWNERSHIP_PER_UID:
	case LTTNG_MAP_CHANNEL_BUFFER_OWNERSHIP_PER_PID:
		return true;
	default:
		return false;
	}
}

inline bool dead_group_policy_is_valid(const enum lttng_map_channel_dead_group_policy policy)
{
	switch (policy) {
	case LTTNG_MAP_CHANNEL_DEAD_GROUP_POLICY_DROP:
	case LTTNG_MAP_CHANNEL_DEAD_GROUP_POLICY_SUM_INTO_SHARED:
		return true;
	default:
		return false;
	}
}

inline bool group_type_is_valid(const enum lttng_map_group_type type)
{
	switch (type) {
	case LTTNG_MAP_GROUP_TYPE_KERNEL_GLOBAL:
	case LTTNG_MAP_GROUP_TYPE_USER_PER_USER:
	case LTTNG_MAP_GROUP_TYPE_USER_PER_PROCESS:
	case LTTNG_MAP_GROUP_TYPE_SHARED:
		return true;
	default:
		return false;
	}
}

inline enum lttng_domain_type channel_type_to_domain_type(const enum lttng_map_channel_type type)
{
	return type == LTTNG_MAP_CHANNEL_TYPE_KERNEL ? LTTNG_DOMAIN_KERNEL : LTTNG_DOMAIN_UST;
}

} /* namespace details */
} /* namespace map */
} /* namespace ctl */
} /* namespace lttng */

#endif /* LTTNG_CTL_MAP_INTERNAL_HPP */
