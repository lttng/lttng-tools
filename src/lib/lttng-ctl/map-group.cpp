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
#include <lttng/map/group-set.h>
#include <lttng/map/group.h>
#include <lttng/map/values-set.h>

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <memory>
#include <new>
#include <utility>
#include <vector>

namespace {

namespace lcmd = lttng::ctl::map::details;

/*
 * Issue a SAMPLE_MAP_GROUP request for `group` and parse the reply into a
 * fresh values set.
 */
enum lttng_error_code sample_map_group(const lttng_map_group& group,
				       std::unique_ptr<lttng_map_values_set>& result)
{
	struct lttcomm_session_msg lsm = {};
	struct lttcomm_map_group_sample_header sample_header;
	char *reply_payload;
	const char *payload_view;
	const char *payload_end;
	size_t payload_size;
	int ret;

	lsm.cmd_type = LTTCOMM_SESSIOND_COMMAND_SAMPLE_MAP_GROUP;
	ret = lttng_strncpy(lsm.session.name, group.session_name.c_str(), sizeof(lsm.session.name));
	if (ret) {
		return LTTNG_ERR_INVALID;
	}

	lsm.domain.type = lcmd::channel_type_to_domain_type(group.channel_type);
	lsm.u.sample_map_group.type = group.channel_type;
	ret = lttng_strncpy(lsm.u.sample_map_group.channel_name,
			    group.channel_name.c_str(),
			    sizeof(lsm.u.sample_map_group.channel_name));
	if (ret) {
		return LTTNG_ERR_INVALID;
	}

	lsm.u.sample_map_group.group.type = static_cast<int32_t>(group.type);
	lsm.u.sample_map_group.group.value_type = static_cast<int32_t>(group.effective_value_type);
	lsm.u.sample_map_group.group.owner_id = group.owner_id;
	ret = lttng_strncpy(lsm.u.sample_map_group.group.owner_name,
			    group.owner_name.c_str(),
			    sizeof(lsm.u.sample_map_group.group.owner_name));
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
	if (payload_size < sizeof(sample_header)) {
		return LTTNG_ERR_INVALID_PROTOCOL;
	}

	memcpy(&sample_header, reply_payload, sizeof(sample_header));

	payload_view = reply_payload + sizeof(sample_header);
	payload_end = reply_payload + payload_size;

	auto values_set =
		std::unique_ptr<lttng_map_values_set>(new (std::nothrow) lttng_map_values_set());
	if (!values_set) {
		return LTTNG_ERR_NOMEM;
	}

	try {
		values_set->values.reserve((size_t) sample_header.partition_count);
	} catch (const std::bad_alloc&) {
		return LTTNG_ERR_NOMEM;
	}

	for (uint64_t i = 0; i < sample_header.partition_count; i++) {
		struct lttcomm_map_group_values_partition_comm partition_comm = {};

		if (static_cast<size_t>(payload_end - payload_view) < sizeof(partition_comm)) {
			return LTTNG_ERR_INVALID_PROTOCOL;
		}

		memcpy(&partition_comm, payload_view, sizeof(partition_comm));
		payload_view += sizeof(partition_comm);

		if (partition_comm.element_count >
		    static_cast<uint64_t>(std::numeric_limits<size_t>::max() /
					  sizeof(struct lttcomm_map_group_value_comm))) {
			return LTTNG_ERR_INVALID_PROTOCOL;
		}

		const auto partition_values_size = (size_t) partition_comm.element_count *
			sizeof(struct lttcomm_map_group_value_comm);
		if (static_cast<size_t>(payload_end - payload_view) < partition_values_size) {
			return LTTNG_ERR_INVALID_PROTOCOL;
		}

		auto values =
			std::unique_ptr<lttng_map_values>(new (std::nothrow) lttng_map_values());
		if (!values) {
			return LTTNG_ERR_NOMEM;
		}

		if (partition_comm.has_partition_id != 0) {
			/* Copy out of the packed field before binding it. */
			const unsigned int partition_id = partition_comm.partition_id;

			values->partition_id = partition_id;
		}

		try {
			values->signed_values.reserve((size_t) partition_comm.element_count);
			values->has_overflow.reserve((size_t) partition_comm.element_count);
		} catch (const std::bad_alloc&) {
			return LTTNG_ERR_NOMEM;
		}

		for (uint64_t j = 0; j < partition_comm.element_count; j++) {
			struct lttcomm_map_group_value_comm value_comm = {};

			memcpy(&value_comm, payload_view, sizeof(value_comm));
			payload_view += sizeof(value_comm);

			try {
				values->signed_values.push_back(value_comm.value);
				values->has_overflow.push_back(value_comm.has_overflow != 0);
			} catch (const std::bad_alloc&) {
				return LTTNG_ERR_NOMEM;
			}
		}

		try {
			values_set->values.push_back(std::move(values));
		} catch (const std::bad_alloc&) {
			return LTTNG_ERR_NOMEM;
		}
	}

	if (payload_view != payload_end) {
		return LTTNG_ERR_INVALID_PROTOCOL;
	}

	result = std::move(values_set);
	return LTTNG_OK;
}

} /* namespace */

extern "C" {

enum lttng_map_group_set_status lttng_map_group_set_get_count(const struct lttng_map_group_set *set,
							      uint64_t *count)
{
	if (!set || !count) {
		return LTTNG_MAP_GROUP_SET_STATUS_INVALID_PARAMETER;
	}

	*count = set->groups.size();
	return LTTNG_MAP_GROUP_SET_STATUS_OK;
}

enum lttng_map_group_set_status lttng_map_group_set_get_at_index(
	const struct lttng_map_group_set *set, uint64_t index, const struct lttng_map_group **group)
{
	if (!set || !group || index >= set->groups.size()) {
		return LTTNG_MAP_GROUP_SET_STATUS_INVALID_PARAMETER;
	}

	*group = set->groups[index].get();
	return LTTNG_MAP_GROUP_SET_STATUS_OK;
}

void lttng_map_group_set_destroy(struct lttng_map_group_set *set)
{
	delete set;
}

enum lttng_map_group_status lttng_map_group_get_type(const struct lttng_map_group *group,
						     enum lttng_map_group_type *type)
{
	if (!group || !type || !lcmd::group_type_is_valid(group->type)) {
		return LTTNG_MAP_GROUP_STATUS_INVALID_PARAMETER;
	}

	*type = group->type;
	return LTTNG_MAP_GROUP_STATUS_OK;
}

enum lttng_map_group_status lttng_map_group_user_get_owner_id(const struct lttng_map_group *group,
							      uint64_t *owner_id)
{
	if (!group || !owner_id ||
	    (group->type != LTTNG_MAP_GROUP_TYPE_USER_PER_USER &&
	     group->type != LTTNG_MAP_GROUP_TYPE_USER_PER_PROCESS)) {
		return LTTNG_MAP_GROUP_STATUS_INVALID_PARAMETER;
	}

	*owner_id = group->owner_id;
	return LTTNG_MAP_GROUP_STATUS_OK;
}

enum lttng_map_group_status lttng_map_group_user_get_owner_name(const struct lttng_map_group *group,
								const char **owner_name)
{
	if (!group || !owner_name ||
	    (group->type != LTTNG_MAP_GROUP_TYPE_USER_PER_USER &&
	     group->type != LTTNG_MAP_GROUP_TYPE_USER_PER_PROCESS)) {
		return LTTNG_MAP_GROUP_STATUS_INVALID_PARAMETER;
	}

	*owner_name = group->owner_name.c_str();
	return LTTNG_MAP_GROUP_STATUS_OK;
}

enum lttng_map_group_status
lttng_map_group_get_effective_value_type(const struct lttng_map_group *group,
					 enum lttng_map_value_type *value_type)
{
	if (!group || !value_type || !lcmd::group_type_is_valid(group->type)) {
		return LTTNG_MAP_GROUP_STATUS_INVALID_PARAMETER;
	}

	*value_type = group->effective_value_type;
	return LTTNG_MAP_GROUP_STATUS_OK;
}

enum lttng_map_group_status lttng_map_group_get_values(const struct lttng_map_group *group,
						       struct lttng_map_values_set **values_set)
{
	std::unique_ptr<lttng_map_values_set> set;

	if (!group || !values_set) {
		return LTTNG_MAP_GROUP_STATUS_INVALID_PARAMETER;
	}

	if (sample_map_group(*group, set) != LTTNG_OK) {
		return LTTNG_MAP_GROUP_STATUS_ERROR;
	}

	*values_set = set.release();
	return LTTNG_MAP_GROUP_STATUS_OK;
}

void lttng_map_group_destroy(struct lttng_map_group *group)
{
	delete group;
}

} /* extern "C" */
