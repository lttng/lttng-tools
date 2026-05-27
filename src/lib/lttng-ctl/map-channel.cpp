/*
 * SPDX-FileCopyrightText: 2026 EfficiOS Inc.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#define _LGPL_SOURCE

#include "lttng-ctl-helper.hpp"
#include "map-internal.hpp"

#include <common/compat/string.hpp>
#include <common/sessiond-comm/sessiond-comm.hpp>

#include <lttng/lttng-error.h>
#include <lttng/map/channel-set.h>
#include <lttng/map/channel-user.h>
#include <lttng/map/channel.h>
#include <lttng/map/group-set.h>
#include <lttng/map/group.h>
#include <lttng/map/key-set.h>
#include <lttng/session.h>

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <memory>
#include <new>
#include <string>
#include <utility>
#include <vector>

namespace {

namespace lcmd = lttng::ctl::map::details;

lttng_map_channel_set *create_empty_map_channel_set()
{
	return new (std::nothrow) lttng_map_channel_set();
}

std::unique_ptr<lttng_map_group> clone_map_group(const lttng_map_group& source)
{
	auto group = std::unique_ptr<lttng_map_group>(new (std::nothrow) lttng_map_group());

	if (!group) {
		return nullptr;
	}

	group->type = source.type;
	group->owner_id = source.owner_id;
	group->effective_value_type = source.effective_value_type;
	group->channel_type = source.channel_type;
	try {
		group->session_name = source.session_name;
		group->channel_name = source.channel_name;
		group->owner_name = source.owner_name;
	} catch (const std::bad_alloc&) {
		return nullptr;
	}

	return group;
}

bool populate_map_channel_from_comm(const struct lttcomm_map_channel_comm& comm_channel,
				    const char *session_name,
				    enum lttng_map_channel_type type,
				    lttng_map_channel& channel)
{
	const auto channel_name_length =
		lttng_strnlen(comm_channel.name, sizeof(comm_channel.name));

	if (channel_name_length == sizeof(comm_channel.name)) {
		return false;
	}

	channel.type = type;
	try {
		channel.session_name = session_name;
		channel.name = std::string(comm_channel.name, channel_name_length);
	} catch (const std::bad_alloc&) {
		return false;
	}

	channel.keys.type = static_cast<enum lttng_map_key_type>(comm_channel.key_type);
	channel.value_type = static_cast<enum lttng_map_value_type>(comm_channel.value_type);
	channel.max_key_count = comm_channel.max_entry_count;
	channel.update_policy =
		static_cast<enum lttng_map_channel_update_policy>(comm_channel.update_policy);
	channel.dead_group_policy = static_cast<enum lttng_map_channel_dead_group_policy>(
		comm_channel.dead_group_policy);
	channel.buffer_ownership = comm_channel.buffer_ownership == 1 ?
		LTTNG_MAP_CHANNEL_BUFFER_OWNERSHIP_PER_UID :
		LTTNG_MAP_CHANNEL_BUFFER_OWNERSHIP_PER_PID;

	if (!lcmd::key_type_is_valid(channel.keys.type) ||
	    !lcmd::value_type_is_valid(channel.value_type) ||
	    !lcmd::update_policy_is_valid(channel.update_policy) ||
	    !lcmd::buffer_ownership_is_valid(channel.buffer_ownership) ||
	    !lcmd::dead_group_policy_is_valid(channel.dead_group_policy) ||
	    channel.max_key_count == 0) {
		return false;
	}

	return true;
}

bool map_group_type_is_valid_comm(const int32_t type)
{
	return lcmd::group_type_is_valid(static_cast<enum lttng_map_group_type>(type));
}

bool map_group_value_type_is_valid_comm(const int32_t value_type)
{
	return value_type == LTTNG_MAP_VALUE_TYPE_SIGNED_INT_32 ||
		value_type == LTTNG_MAP_VALUE_TYPE_SIGNED_INT_64;
}

std::unique_ptr<lttng_map_group>
map_group_from_comm(const struct lttcomm_map_group_comm& group_comm,
		    const lttng_map_channel& channel)
{
	const auto owner_name_length =
		lttng_strnlen(group_comm.owner_name, sizeof(group_comm.owner_name));

	if (owner_name_length == sizeof(group_comm.owner_name) ||
	    !map_group_type_is_valid_comm(group_comm.type) ||
	    !map_group_value_type_is_valid_comm(group_comm.value_type)) {
		return nullptr;
	}

	auto group = std::unique_ptr<lttng_map_group>(new (std::nothrow) lttng_map_group());

	if (!group) {
		return nullptr;
	}

	group->type = static_cast<enum lttng_map_group_type>(group_comm.type);
	group->owner_id = group_comm.owner_id;
	group->effective_value_type = static_cast<enum lttng_map_value_type>(group_comm.value_type);
	group->channel_type = channel.type;

	try {
		group->session_name = channel.session_name;
		group->channel_name = channel.name;
		group->owner_name = std::string(group_comm.owner_name, owner_name_length);
	} catch (const std::bad_alloc&) {
		return nullptr;
	}

	return group;
}

/*
 * Issue a LIST_MAP_GROUPS request for `channel` and parse the reply into a
 * fresh group set.
 */
enum lttng_error_code fetch_map_groups(const lttng_map_channel& channel,
				       std::unique_ptr<lttng_map_group_set>& result)
{
	struct lttcomm_session_msg lsm = {};
	struct lttcomm_map_group_list_header list_header;
	char *reply_payload;
	const char *payload_view;
	size_t payload_size;
	size_t offset;
	int ret;

	lsm.cmd_type = LTTCOMM_SESSIOND_COMMAND_LIST_MAP_GROUPS;
	ret = lttng_strncpy(
		lsm.session.name, channel.session_name.c_str(), sizeof(lsm.session.name));
	if (ret) {
		return LTTNG_ERR_INVALID;
	}

	lsm.domain.type = lcmd::channel_type_to_domain_type(channel.type);
	lsm.u.list_map_groups.type = channel.type;
	ret = lttng_strncpy(lsm.u.list_map_groups.channel_name,
			    channel.name.c_str(),
			    sizeof(lsm.u.list_map_groups.channel_name));
	if (ret) {
		return LTTNG_ERR_INVALID;
	}

	reply_payload = nullptr;
	ret = lttng_ctl_ask_sessiond(&lsm, reinterpret_cast<void **>(&reply_payload));
	if (ret < 0) {
		return (enum lttng_error_code) - ret;
	}
	if (ret > 0 && !reply_payload) {
		return LTTNG_ERR_INVALID_PROTOCOL;
	}

	std::unique_ptr<char, void (*)(void *)> reply_payload_guard(reply_payload, std::free);

	payload_size = (size_t) ret;
	if (payload_size < sizeof(list_header)) {
		return LTTNG_ERR_INVALID_PROTOCOL;
	}

	memcpy(&list_header, reply_payload, sizeof(list_header));

	offset = sizeof(list_header);
	if (list_header.count > static_cast<uint64_t>(std::numeric_limits<size_t>::max() /
						      sizeof(struct lttcomm_map_group_comm)) ||
	    payload_size !=
		    offset + (size_t) list_header.count * sizeof(struct lttcomm_map_group_comm)) {
		return LTTNG_ERR_INVALID_PROTOCOL;
	}

	auto group_set =
		std::unique_ptr<lttng_map_group_set>(new (std::nothrow) lttng_map_group_set());
	if (!group_set) {
		return LTTNG_ERR_NOMEM;
	}

	try {
		group_set->groups.reserve((size_t) list_header.count);
	} catch (const std::bad_alloc&) {
		return LTTNG_ERR_NOMEM;
	}

	payload_view = reply_payload + offset;
	for (uint64_t i = 0; i < list_header.count; i++) {
		struct lttcomm_map_group_comm group_comm = {};

		memcpy(&group_comm, payload_view, sizeof(group_comm));
		payload_view += sizeof(group_comm);

		auto group = map_group_from_comm(group_comm, channel);
		if (!group) {
			return LTTNG_ERR_INVALID_PROTOCOL;
		}

		try {
			group_set->groups.push_back(std::move(group));
		} catch (const std::bad_alloc&) {
			return LTTNG_ERR_NOMEM;
		}
	}

	result = std::move(group_set);
	return LTTNG_OK;
}

/*
 * Issue a LIST_MAP_KEYS request for `channel` and parse the reply into a
 * fresh key set.
 *
 * The reply is a `lttcomm_map_key_list_header` followed by `count` entries,
 * each a `lttcomm_map_key_comm` immediately followed inline by `name_len`
 * bytes of the key string (map keys have no fixed maximum length).
 */
enum lttng_error_code fetch_map_keys(const lttng_map_channel& channel,
				     std::unique_ptr<lttng_map_key_set>& result)
{
	struct lttcomm_session_msg lsm = {};
	struct lttcomm_map_key_list_header list_header;
	char *reply_payload;
	size_t payload_size;
	size_t offset;
	int ret;

	lsm.cmd_type = LTTCOMM_SESSIOND_COMMAND_LIST_MAP_KEYS;
	ret = lttng_strncpy(
		lsm.session.name, channel.session_name.c_str(), sizeof(lsm.session.name));
	if (ret) {
		return LTTNG_ERR_INVALID;
	}

	lsm.domain.type = lcmd::channel_type_to_domain_type(channel.type);
	lsm.u.list_map_keys.type = channel.type;
	ret = lttng_strncpy(lsm.u.list_map_keys.channel_name,
			    channel.name.c_str(),
			    sizeof(lsm.u.list_map_keys.channel_name));
	if (ret) {
		return LTTNG_ERR_INVALID;
	}

	reply_payload = nullptr;
	ret = lttng_ctl_ask_sessiond(&lsm, reinterpret_cast<void **>(&reply_payload));
	if (ret < 0) {
		return (enum lttng_error_code) - ret;
	}
	if (ret > 0 && !reply_payload) {
		return LTTNG_ERR_INVALID_PROTOCOL;
	}

	std::unique_ptr<char, void (*)(void *)> reply_payload_guard(reply_payload, std::free);

	payload_size = (size_t) ret;
	if (payload_size < sizeof(list_header)) {
		return LTTNG_ERR_INVALID_PROTOCOL;
	}

	memcpy(&list_header, reply_payload, sizeof(list_header));
	offset = sizeof(list_header);

	auto key_set = std::unique_ptr<lttng_map_key_set>(new (std::nothrow) lttng_map_key_set());
	if (!key_set) {
		return LTTNG_ERR_NOMEM;
	}

	key_set->type = channel.keys.type;

	try {
		key_set->keys.reserve((size_t) list_header.count);
	} catch (const std::bad_alloc&) {
		return LTTNG_ERR_NOMEM;
	}

	for (uint64_t i = 0; i < list_header.count; i++) {
		struct lttcomm_map_key_comm key_comm = {};

		if (payload_size - offset < sizeof(key_comm)) {
			return LTTNG_ERR_INVALID_PROTOCOL;
		}

		memcpy(&key_comm, reply_payload + offset, sizeof(key_comm));
		offset += sizeof(key_comm);

		if (payload_size - offset < key_comm.name_len) {
			return LTTNG_ERR_INVALID_PROTOCOL;
		}

		auto key = std::unique_ptr<lttng_map_key>(new (std::nothrow) lttng_map_key());
		if (!key) {
			return LTTNG_ERR_NOMEM;
		}

		key->type = static_cast<enum lttng_map_key_type>(key_comm.type);
		key->index = key_comm.index;

		try {
			key->str = std::string(reply_payload + offset, key_comm.name_len);
			key_set->keys.push_back(std::move(key));
		} catch (const std::bad_alloc&) {
			return LTTNG_ERR_NOMEM;
		}

		offset += key_comm.name_len;
	}

	if (offset != payload_size) {
		return LTTNG_ERR_INVALID_PROTOCOL;
	}

	result = std::move(key_set);
	return LTTNG_OK;
}

/*
 * Collect into a fresh group set every map group of `channel` whose
 * type is `group_type` and whose owner ID is `owner_id`.
 *
 * A channel having the `LTTNG_MAP_VALUE_TYPE_SIGNED_INT_MAX` value type
 * can expose, for a single owner, both a 32-bit and a 64-bit group; a
 * channel having a concrete value type exposes a single group
 * per owner.
 *
 * The resulting set therefore contains zero, one, or two groups.
 */
enum lttng_map_channel_status collect_user_groups_by_owner(const lttng_map_channel& channel,
							   enum lttng_map_group_type group_type,
							   uint64_t owner_id,
							   struct lttng_map_group_set **groups)
{
	std::unique_ptr<lttng_map_group_set> fetched;

	if (fetch_map_groups(channel, fetched) != LTTNG_OK) {
		return LTTNG_MAP_CHANNEL_STATUS_ERROR;
	}

	auto result =
		std::unique_ptr<lttng_map_group_set>(new (std::nothrow) lttng_map_group_set());
	if (!result) {
		return LTTNG_MAP_CHANNEL_STATUS_ERROR;
	}

	for (const auto& candidate : fetched->groups) {
		if (candidate->type != group_type || candidate->owner_id != owner_id) {
			continue;
		}

		auto cloned = clone_map_group(*candidate);
		if (!cloned) {
			return LTTNG_MAP_CHANNEL_STATUS_ERROR;
		}

		try {
			result->groups.push_back(std::move(cloned));
		} catch (const std::bad_alloc&) {
			return LTTNG_MAP_CHANNEL_STATUS_ERROR;
		}
	}

	*groups = result.release();
	return LTTNG_MAP_CHANNEL_STATUS_OK;
}

} /* namespace */

extern "C" {

enum lttng_error_code
lttng_session_add_map_channel(const char *session_name,
			      const struct lttng_map_channel_descriptor *descriptor)
{
	struct lttcomm_session_msg lsm = {};
	int ret;

	if (!session_name || !descriptor) {
		return LTTNG_ERR_INVALID;
	}

	if (!lcmd::channel_type_is_valid(descriptor->type) ||
	    !lcmd::value_type_is_valid(descriptor->value_type) ||
	    !lcmd::update_policy_is_valid(descriptor->update_policy) ||
	    !lcmd::dead_group_policy_is_valid(descriptor->dead_group_policy) ||
	    !lcmd::buffer_ownership_is_valid(descriptor->buffer_ownership) ||
	    descriptor->key_type != LTTNG_MAP_KEY_TYPE_STRING || descriptor->max_key_count == 0) {
		return LTTNG_ERR_INVALID;
	}

	lsm.cmd_type = LTTCOMM_SESSIOND_COMMAND_ADD_MAP_CHANNEL;
	ret = lttng_strncpy(lsm.session.name, session_name, sizeof(lsm.session.name));
	if (ret) {
		return LTTNG_ERR_INVALID;
	}

	lsm.domain.type = lcmd::channel_type_to_domain_type(descriptor->type);

	/*
	 * An unset descriptor name is conveyed to the session daemon as an
	 * empty name: the daemon then generates a name for the resulting map
	 * channel, as documented for lttng_map_channel_descriptor_set_name().
	 * lsm is zero-initialized, so leaving the name field untouched already
	 * yields an empty name.
	 */
	if (descriptor->name_is_set) {
		ret = lttng_strncpy(lsm.u.add_map_channel.name,
				    descriptor->name.c_str(),
				    sizeof(lsm.u.add_map_channel.name));
		if (ret) {
			return LTTNG_ERR_INVALID;
		}
	}

	lsm.u.add_map_channel.key_type = descriptor->key_type;
	lsm.u.add_map_channel.value_type = descriptor->value_type;
	lsm.u.add_map_channel.max_entry_count = descriptor->max_key_count;
	lsm.u.add_map_channel.update_policy = descriptor->update_policy;
	lsm.u.add_map_channel.dead_group_policy = descriptor->dead_group_policy;
	lsm.u.add_map_channel.buffer_ownership =
		descriptor->buffer_ownership == LTTNG_MAP_CHANNEL_BUFFER_OWNERSHIP_PER_UID ? 1 : 0;

	ret = lttng_ctl_ask_sessiond(&lsm, nullptr);
	return ret == 0 ? LTTNG_OK : (enum lttng_error_code) - ret;
}

enum lttng_error_code lttng_session_list_map_channels(const char *session_name,
						      enum lttng_map_channel_type type,
						      struct lttng_map_channel_set **channels)
{
	struct lttcomm_session_msg lsm = {};
	struct lttcomm_map_channel_list_header list_header;
	char *reply_payload;
	const char *payload_view;
	lttng_map_channel_set *channel_set;
	size_t payload_size;
	size_t offset;
	int ret;

	if (!session_name || !channels || !lcmd::channel_type_is_valid(type)) {
		return LTTNG_ERR_INVALID;
	}

	*channels = nullptr;

	lsm.cmd_type = LTTCOMM_SESSIOND_COMMAND_LIST_MAP_CHANNELS;
	ret = lttng_strncpy(lsm.session.name, session_name, sizeof(lsm.session.name));
	if (ret) {
		return LTTNG_ERR_INVALID;
	}

	lsm.domain.type = lcmd::channel_type_to_domain_type(type);
	lsm.u.list_map_channels.type = type;

	reply_payload = nullptr;
	ret = lttng_ctl_ask_sessiond(&lsm, reinterpret_cast<void **>(&reply_payload));
	if (ret < 0) {
		const enum lttng_error_code error_code = (enum lttng_error_code) - ret;

		/*
		 * An unavailable Linux kernel tracer (the session
		 * daemon isn't running as `root`, or kernel tracing is
		 * disabled) means the recording session can't have any
		 * kernel map channel: report an empty set instead of an
		 * error so that callers listing both channel types
		 * don't have to special-case kernel unavailability.
		 */
		if (type == LTTNG_MAP_CHANNEL_TYPE_KERNEL &&
		    (error_code == LTTNG_ERR_NEED_ROOT_SESSIOND ||
		     error_code == LTTNG_ERR_KERN_NA)) {
			channel_set = create_empty_map_channel_set();
			if (!channel_set) {
				return LTTNG_ERR_NOMEM;
			}

			*channels = channel_set;
			return LTTNG_OK;
		}

		return error_code;
	}
	if (ret > 0 && !reply_payload) {
		return LTTNG_ERR_INVALID_PROTOCOL;
	}

	std::unique_ptr<char, void (*)(void *)> reply_payload_guard(reply_payload, std::free);

	payload_size = (size_t) ret;
	if (payload_size < sizeof(list_header)) {
		return LTTNG_ERR_INVALID_PROTOCOL;
	}

	memcpy(&list_header, reply_payload, sizeof(list_header));

	offset = sizeof(list_header);
	if (list_header.count > static_cast<uint64_t>(std::numeric_limits<size_t>::max() /
						      sizeof(struct lttcomm_map_channel_comm)) ||
	    payload_size !=
		    offset + (size_t) list_header.count * sizeof(struct lttcomm_map_channel_comm)) {
		return LTTNG_ERR_INVALID_PROTOCOL;
	}

	channel_set = create_empty_map_channel_set();
	if (!channel_set) {
		return LTTNG_ERR_NOMEM;
	}

	try {
		channel_set->channels.reserve((size_t) list_header.count);
	} catch (const std::bad_alloc&) {
		delete channel_set;
		return LTTNG_ERR_NOMEM;
	}

	payload_view = reply_payload + offset;
	for (uint64_t i = 0; i < list_header.count; i++) {
		struct lttcomm_map_channel_comm comm_channel = {};
		auto parsed_channel =
			std::unique_ptr<lttng_map_channel>(new (std::nothrow) lttng_map_channel());

		if (!parsed_channel) {
			delete channel_set;
			return LTTNG_ERR_NOMEM;
		}

		memcpy(&comm_channel, payload_view, sizeof(comm_channel));
		payload_view += sizeof(comm_channel);

		if (!populate_map_channel_from_comm(
			    comm_channel, session_name, type, *parsed_channel)) {
			delete channel_set;
			return LTTNG_ERR_INVALID_PROTOCOL;
		}

		try {
			channel_set->channels.push_back(std::move(parsed_channel));
		} catch (const std::bad_alloc&) {
			delete channel_set;
			return LTTNG_ERR_NOMEM;
		}
	}

	*channels = channel_set;
	return LTTNG_OK;
}

enum lttng_error_code lttng_session_get_map_channel_by_name(const char *session_name,
							    enum lttng_map_channel_type type,
							    const char *name,
							    struct lttng_map_channel **channel)
{
	struct lttcomm_session_msg lsm = {};
	struct lttcomm_map_channel_comm comm_channel;
	char *reply_payload;
	int ret;

	if (!session_name || !name || !channel || !lcmd::channel_type_is_valid(type)) {
		return LTTNG_ERR_INVALID;
	}

	*channel = nullptr;

	lsm.cmd_type = LTTCOMM_SESSIOND_COMMAND_GET_MAP_CHANNEL_BY_NAME;
	ret = lttng_strncpy(lsm.session.name, session_name, sizeof(lsm.session.name));
	if (ret) {
		return LTTNG_ERR_INVALID;
	}

	lsm.domain.type = lcmd::channel_type_to_domain_type(type);
	lsm.u.get_map_channel_by_name.type = type;

	ret = lttng_strncpy(lsm.u.get_map_channel_by_name.name,
			    name,
			    sizeof(lsm.u.get_map_channel_by_name.name));
	if (ret) {
		return LTTNG_ERR_INVALID;
	}

	reply_payload = nullptr;
	ret = lttng_ctl_ask_sessiond(&lsm, reinterpret_cast<void **>(&reply_payload));
	if (ret < 0) {
		return (enum lttng_error_code) - ret;
	}
	if (ret > 0 && !reply_payload) {
		return LTTNG_ERR_INVALID_PROTOCOL;
	}

	std::unique_ptr<char, void (*)(void *)> reply_payload_guard(reply_payload, std::free);
	if ((size_t) ret != sizeof(comm_channel)) {
		return LTTNG_ERR_INVALID_PROTOCOL;
	}

	memcpy(&comm_channel, reply_payload, sizeof(comm_channel));
	auto parsed_channel =
		std::unique_ptr<lttng_map_channel>(new (std::nothrow) lttng_map_channel());
	if (!parsed_channel) {
		return LTTNG_ERR_NOMEM;
	}

	if (!populate_map_channel_from_comm(comm_channel, session_name, type, *parsed_channel)) {
		return LTTNG_ERR_INVALID_PROTOCOL;
	}

	*channel = parsed_channel.release();
	return LTTNG_OK;
}

enum lttng_map_channel_set_status
lttng_map_channel_set_get_count(const struct lttng_map_channel_set *set, uint64_t *count)
{
	if (!set || !count) {
		return LTTNG_MAP_CHANNEL_SET_STATUS_INVALID_PARAMETER;
	}

	*count = set->channels.size();
	return LTTNG_MAP_CHANNEL_SET_STATUS_OK;
}

enum lttng_map_channel_set_status
lttng_map_channel_set_get_at_index(const struct lttng_map_channel_set *set,
				   uint64_t index,
				   const struct lttng_map_channel **channel)
{
	if (!set || !channel || index >= set->channels.size()) {
		return LTTNG_MAP_CHANNEL_SET_STATUS_INVALID_PARAMETER;
	}

	*channel = set->channels[index].get();
	return LTTNG_MAP_CHANNEL_SET_STATUS_OK;
}

void lttng_map_channel_set_destroy(struct lttng_map_channel_set *set)
{
	delete set;
}

enum lttng_map_channel_status lttng_map_channel_get_name(const struct lttng_map_channel *channel,
							 const char **name)
{
	if (!channel || !name) {
		return LTTNG_MAP_CHANNEL_STATUS_INVALID_PARAMETER;
	}

	*name = channel->name.c_str();
	return LTTNG_MAP_CHANNEL_STATUS_OK;
}

enum lttng_map_channel_status lttng_map_channel_get_type(const struct lttng_map_channel *channel,
							 enum lttng_map_channel_type *type)
{
	if (!channel || !type) {
		return LTTNG_MAP_CHANNEL_STATUS_INVALID_PARAMETER;
	}

	*type = channel->type;
	return LTTNG_MAP_CHANNEL_STATUS_OK;
}

enum lttng_map_channel_status
lttng_map_channel_get_value_type(const struct lttng_map_channel *channel,
				 enum lttng_map_value_type *value_type)
{
	if (!channel || !value_type) {
		return LTTNG_MAP_CHANNEL_STATUS_INVALID_PARAMETER;
	}

	*value_type = channel->value_type;
	return LTTNG_MAP_CHANNEL_STATUS_OK;
}

enum lttng_map_channel_status
lttng_map_channel_get_max_key_count(const struct lttng_map_channel *channel,
				    uint64_t *max_key_count)
{
	if (!channel || !max_key_count) {
		return LTTNG_MAP_CHANNEL_STATUS_INVALID_PARAMETER;
	}

	*max_key_count = channel->max_key_count;
	return LTTNG_MAP_CHANNEL_STATUS_OK;
}

enum lttng_map_channel_status
lttng_map_channel_get_update_policy(const struct lttng_map_channel *channel,
				    enum lttng_map_channel_update_policy *policy)
{
	if (!channel || !policy) {
		return LTTNG_MAP_CHANNEL_STATUS_INVALID_PARAMETER;
	}

	*policy = channel->update_policy;
	return LTTNG_MAP_CHANNEL_STATUS_OK;
}

enum lttng_map_channel_status lttng_map_channel_get_groups(const struct lttng_map_channel *channel,
							   struct lttng_map_group_set **groups)
{
	std::unique_ptr<lttng_map_group_set> group_set;

	if (!channel || !groups) {
		return LTTNG_MAP_CHANNEL_STATUS_INVALID_PARAMETER;
	}

	if (fetch_map_groups(*channel, group_set) != LTTNG_OK) {
		return LTTNG_MAP_CHANNEL_STATUS_ERROR;
	}

	*groups = group_set.release();
	return LTTNG_MAP_CHANNEL_STATUS_OK;
}

enum lttng_map_channel_status
lttng_map_channel_get_shared_group(const struct lttng_map_channel *channel,
				   struct lttng_map_group **group)
{
	std::unique_ptr<lttng_map_group_set> group_set;

	if (!channel || !group || channel->type != LTTNG_MAP_CHANNEL_TYPE_USER) {
		return LTTNG_MAP_CHANNEL_STATUS_INVALID_PARAMETER;
	}

	if (fetch_map_groups(*channel, group_set) != LTTNG_OK) {
		return LTTNG_MAP_CHANNEL_STATUS_ERROR;
	}

	const auto matching_group =
		std::find_if(group_set->groups.cbegin(),
			     group_set->groups.cend(),
			     [](const std::unique_ptr<lttng_map_group>& candidate_group) {
				     return candidate_group->type == LTTNG_MAP_GROUP_TYPE_SHARED;
			     });
	if (matching_group == group_set->groups.cend()) {
		*group = nullptr;
		return LTTNG_MAP_CHANNEL_STATUS_NOT_FOUND;
	}

	auto cloned_group = clone_map_group(*matching_group->get());
	if (!cloned_group) {
		return LTTNG_MAP_CHANNEL_STATUS_INVALID_PARAMETER;
	}

	*group = cloned_group.release();
	return LTTNG_MAP_CHANNEL_STATUS_OK;
}

enum lttng_map_channel_status lttng_map_channel_get_keys(const struct lttng_map_channel *channel,
							 struct lttng_map_key_set **keys)
{
	std::unique_ptr<lttng_map_key_set> set;

	if (!channel || !keys) {
		return LTTNG_MAP_CHANNEL_STATUS_INVALID_PARAMETER;
	}

	/*
	 * The keys of a map channel are not carried by the channel listing:
	 * they live in the session daemon's key registry and grow as triggers
	 * register new keys. Fetch a fresh snapshot from the daemon so the
	 * returned set reflects the keys (with their indices) currently known,
	 * matching what a SAMPLE_MAP_GROUP reply addresses by index.
	 */
	if (fetch_map_keys(*channel, set) != LTTNG_OK) {
		return LTTNG_MAP_CHANNEL_STATUS_ERROR;
	}

	*keys = set.release();
	return LTTNG_MAP_CHANNEL_STATUS_OK;
}

void lttng_map_channel_destroy(struct lttng_map_channel *channel)
{
	delete channel;
}

enum lttng_map_channel_status lttng_map_channel_user_get_buffer_ownership(
	const struct lttng_map_channel *channel,
	enum lttng_map_channel_buffer_ownership *ownership_model)
{
	if (!channel || !ownership_model || channel->type != LTTNG_MAP_CHANNEL_TYPE_USER) {
		return LTTNG_MAP_CHANNEL_STATUS_INVALID_PARAMETER;
	}

	*ownership_model = channel->buffer_ownership;
	return LTTNG_MAP_CHANNEL_STATUS_OK;
}

enum lttng_map_channel_status lttng_map_channel_user_get_group_by_uid(
	const struct lttng_map_channel *channel, uid_t uid, struct lttng_map_group_set **groups)
{
	if (!channel || !groups || channel->type != LTTNG_MAP_CHANNEL_TYPE_USER ||
	    channel->buffer_ownership != LTTNG_MAP_CHANNEL_BUFFER_OWNERSHIP_PER_UID) {
		return LTTNG_MAP_CHANNEL_STATUS_INVALID_PARAMETER;
	}

	return collect_user_groups_by_owner(
		*channel, LTTNG_MAP_GROUP_TYPE_USER_PER_USER, static_cast<uint64_t>(uid), groups);
}

enum lttng_map_channel_status lttng_map_channel_user_get_group_by_pid(
	const struct lttng_map_channel *channel, pid_t pid, struct lttng_map_group_set **groups)
{
	if (!channel || !groups || channel->type != LTTNG_MAP_CHANNEL_TYPE_USER ||
	    channel->buffer_ownership != LTTNG_MAP_CHANNEL_BUFFER_OWNERSHIP_PER_PID) {
		return LTTNG_MAP_CHANNEL_STATUS_INVALID_PARAMETER;
	}

	return collect_user_groups_by_owner(*channel,
					    LTTNG_MAP_GROUP_TYPE_USER_PER_PROCESS,
					    static_cast<uint64_t>(pid),
					    groups);
}

enum lttng_map_channel_status
lttng_map_channel_user_get_dead_group_policy(const struct lttng_map_channel *channel,
					     enum lttng_map_channel_dead_group_policy *policy)
{
	if (!channel || !policy || channel->type != LTTNG_MAP_CHANNEL_TYPE_USER ||
	    channel->buffer_ownership != LTTNG_MAP_CHANNEL_BUFFER_OWNERSHIP_PER_PID) {
		return LTTNG_MAP_CHANNEL_STATUS_INVALID_PARAMETER;
	}

	*policy = channel->dead_group_policy;
	return LTTNG_MAP_CHANNEL_STATUS_OK;
}

} /* extern "C" */
