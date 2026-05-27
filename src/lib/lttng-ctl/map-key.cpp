/*
 * SPDX-FileCopyrightText: 2026 EfficiOS Inc.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#define _LGPL_SOURCE

#include "map-internal.hpp"

#include <lttng/map/key-set-string.h>
#include <lttng/map/key-set.h>
#include <lttng/map/key-string.h>
#include <lttng/map/key.h>

#include <algorithm>
#include <cstdint>
#include <memory>
#include <vector>

extern "C" {

enum lttng_map_key_status lttng_map_key_get_type(const struct lttng_map_key *key,
						 enum lttng_map_key_type *type)
{
	if (!key || !type) {
		return LTTNG_MAP_KEY_STATUS_INVALID_PARAMETER;
	}

	*type = key->type;
	return LTTNG_MAP_KEY_STATUS_OK;
}

enum lttng_map_key_status lttng_map_key_get_index(const struct lttng_map_key *key, uint64_t *index)
{
	if (!key || !index) {
		return LTTNG_MAP_KEY_STATUS_INVALID_PARAMETER;
	}

	*index = key->index;
	return LTTNG_MAP_KEY_STATUS_OK;
}

enum lttng_map_key_status lttng_map_key_string_get_string(const struct lttng_map_key *key,
							  const char **str)
{
	if (!key || !str || key->type != LTTNG_MAP_KEY_TYPE_STRING) {
		return LTTNG_MAP_KEY_STATUS_INVALID_PARAMETER;
	}

	*str = key->str.c_str();
	return LTTNG_MAP_KEY_STATUS_OK;
}

enum lttng_map_key_set_status lttng_map_key_set_get_type(const struct lttng_map_key_set *set,
							 enum lttng_map_key_type *type)
{
	if (!set || !type) {
		return LTTNG_MAP_KEY_SET_STATUS_INVALID_PARAMETER;
	}

	*type = set->type;
	return LTTNG_MAP_KEY_SET_STATUS_OK;
}

enum lttng_map_key_set_status lttng_map_key_set_get_count(const struct lttng_map_key_set *set,
							  uint64_t *count)
{
	if (!set || !count) {
		return LTTNG_MAP_KEY_SET_STATUS_INVALID_PARAMETER;
	}

	*count = set->keys.size();
	return LTTNG_MAP_KEY_SET_STATUS_OK;
}

enum lttng_map_key_set_status lttng_map_key_set_get_at_index(const struct lttng_map_key_set *set,
							     uint64_t index,
							     const struct lttng_map_key **key)
{
	if (!set || !key || index >= set->keys.size()) {
		return LTTNG_MAP_KEY_SET_STATUS_INVALID_PARAMETER;
	}

	*key = set->keys[index].get();
	return LTTNG_MAP_KEY_SET_STATUS_OK;
}

void lttng_map_key_set_destroy(struct lttng_map_key_set *set)
{
	delete set;
}

enum lttng_map_key_set_status lttng_map_key_set_string_get_key_by_string(
	const struct lttng_map_key_set *set, const char *str, const struct lttng_map_key **key)
{
	const auto matches_string = [str](const std::unique_ptr<lttng_map_key>& current_key) {
		return current_key->str == str;
	};
	auto it = std::vector<std::unique_ptr<lttng_map_key>>::const_iterator{};

	if (!set || !str || !key || set->type != LTTNG_MAP_KEY_TYPE_STRING) {
		return LTTNG_MAP_KEY_SET_STATUS_INVALID_PARAMETER;
	}

	it = std::find_if(set->keys.cbegin(), set->keys.cend(), matches_string);
	if (it == set->keys.cend()) {
		return LTTNG_MAP_KEY_SET_STATUS_NOT_FOUND;
	}

	*key = it->get();
	return LTTNG_MAP_KEY_SET_STATUS_OK;
}

} /* extern "C" */
