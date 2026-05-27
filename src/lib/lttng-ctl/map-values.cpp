/*
 * SPDX-FileCopyrightText: 2026 EfficiOS Inc.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#define _LGPL_SOURCE

#include "map-internal.hpp"

#include <lttng/map/values-set.h>
#include <lttng/map/values-signed-int.h>
#include <lttng/map/values.h>

#include <cstdint>

extern "C" {

enum lttng_map_values_status
lttng_map_values_get_partition_id(const struct lttng_map_values *values, unsigned int *partition_id)
{
	if (!values || !partition_id || !values->partition_id) {
		return LTTNG_MAP_VALUES_STATUS_INVALID_PARAMETER;
	}

	*partition_id = *values->partition_id;
	return LTTNG_MAP_VALUES_STATUS_OK;
}

enum lttng_map_values_status lttng_map_values_signed_int_get_value_at_index(
	const struct lttng_map_values *values, uint64_t index, int64_t *value)
{
	if (!values || !value || index >= values->signed_values.size()) {
		return LTTNG_MAP_VALUES_STATUS_INVALID_PARAMETER;
	}

	*value = values->signed_values[index];
	return LTTNG_MAP_VALUES_STATUS_OK;
}

enum lttng_map_values_status lttng_map_values_signed_int_has_overflow_at_index(
	const struct lttng_map_values *values, uint64_t index, bool *has_overflow)
{
	if (!values || !has_overflow || index >= values->has_overflow.size()) {
		return LTTNG_MAP_VALUES_STATUS_INVALID_PARAMETER;
	}

	*has_overflow = values->has_overflow[index];
	return LTTNG_MAP_VALUES_STATUS_OK;
}

enum lttng_map_values_set_status
lttng_map_values_set_get_count(const struct lttng_map_values_set *set, uint64_t *count)
{
	if (!set || !count) {
		return LTTNG_MAP_VALUES_SET_STATUS_INVALID_PARAMETER;
	}

	*count = set->values.size();
	return LTTNG_MAP_VALUES_SET_STATUS_OK;
}

enum lttng_map_values_set_status
lttng_map_values_set_get_at_index(const struct lttng_map_values_set *set,
				  uint64_t index,
				  const struct lttng_map_values **values)
{
	if (!set || !values || index >= set->values.size()) {
		return LTTNG_MAP_VALUES_SET_STATUS_INVALID_PARAMETER;
	}

	*values = set->values[index].get();
	return LTTNG_MAP_VALUES_SET_STATUS_OK;
}

void lttng_map_values_set_destroy(struct lttng_map_values_set *set)
{
	delete set;
}

} /* extern "C" */
