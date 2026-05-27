/*
 * SPDX-FileCopyrightText: 2026 EfficiOS Inc.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#define _LGPL_SOURCE

#include "map-internal.hpp"

#include <lttng/map/channel-descriptor-kernel.h>
#include <lttng/map/channel-descriptor-user.h>
#include <lttng/map/channel-descriptor.h>

#include <cstdint>
#include <new>
#include <string>

namespace {
namespace lcmd = lttng::ctl::map::details;
} /* namespace */

extern "C" {

struct lttng_map_channel_descriptor *
lttng_map_channel_descriptor_user_string_key_scalar_value_create(
	enum lttng_map_value_type value_type,
	enum lttng_map_channel_buffer_ownership ownership_model)
{
	lttng_map_channel_descriptor *descriptor;

	if (!lcmd::value_type_is_valid(value_type) ||
	    !lcmd::buffer_ownership_is_valid(ownership_model)) {
		return nullptr;
	}

	descriptor = new (std::nothrow) lttng_map_channel_descriptor();
	if (!descriptor) {
		return nullptr;
	}

	descriptor->type = LTTNG_MAP_CHANNEL_TYPE_USER;
	descriptor->value_type = value_type;
	descriptor->buffer_ownership = ownership_model;
	return descriptor;
}

struct lttng_map_channel_descriptor *
lttng_map_channel_descriptor_kernel_string_key_scalar_value_create(
	enum lttng_map_value_type value_type)
{
	lttng_map_channel_descriptor *descriptor;

	if (!lcmd::value_type_is_valid(value_type)) {
		return nullptr;
	}

	descriptor = new (std::nothrow) lttng_map_channel_descriptor();
	if (!descriptor) {
		return nullptr;
	}

	descriptor->type = LTTNG_MAP_CHANNEL_TYPE_KERNEL;
	descriptor->value_type = value_type;
	return descriptor;
}

enum lttng_map_channel_descriptor_status
lttng_map_channel_descriptor_set_name(struct lttng_map_channel_descriptor *descriptor,
				      const char *name)
{
	if (!descriptor || !name) {
		return LTTNG_MAP_CHANNEL_DESCRIPTOR_STATUS_INVALID_PARAMETER;
	}

	try {
		descriptor->name = name;
	} catch (const std::bad_alloc&) {
		return LTTNG_MAP_CHANNEL_DESCRIPTOR_STATUS_INVALID_PARAMETER;
	}

	descriptor->name_is_set = true;
	return LTTNG_MAP_CHANNEL_DESCRIPTOR_STATUS_OK;
}

enum lttng_map_channel_descriptor_status
lttng_map_channel_descriptor_get_name(const struct lttng_map_channel_descriptor *descriptor,
				      const char **name)
{
	if (!descriptor || !name) {
		return LTTNG_MAP_CHANNEL_DESCRIPTOR_STATUS_INVALID_PARAMETER;
	}
	if (!descriptor->name_is_set) {
		return LTTNG_MAP_CHANNEL_DESCRIPTOR_STATUS_UNSET;
	}

	*name = descriptor->name.c_str();
	return LTTNG_MAP_CHANNEL_DESCRIPTOR_STATUS_OK;
}

enum lttng_map_channel_descriptor_status
lttng_map_channel_descriptor_get_type(const struct lttng_map_channel_descriptor *descriptor,
				      enum lttng_map_channel_type *type)
{
	if (!descriptor || !type) {
		return LTTNG_MAP_CHANNEL_DESCRIPTOR_STATUS_INVALID_PARAMETER;
	}

	*type = descriptor->type;
	return LTTNG_MAP_CHANNEL_DESCRIPTOR_STATUS_OK;
}

enum lttng_map_channel_descriptor_status
lttng_map_channel_descriptor_get_value_type(const struct lttng_map_channel_descriptor *descriptor,
					    enum lttng_map_value_type *value_type)
{
	if (!descriptor || !value_type) {
		return LTTNG_MAP_CHANNEL_DESCRIPTOR_STATUS_INVALID_PARAMETER;
	}

	*value_type = descriptor->value_type;
	return LTTNG_MAP_CHANNEL_DESCRIPTOR_STATUS_OK;
}

enum lttng_map_channel_descriptor_status
lttng_map_channel_descriptor_set_max_key_count(struct lttng_map_channel_descriptor *descriptor,
					       uint64_t max_key_count)
{
	if (!descriptor || max_key_count == 0) {
		return LTTNG_MAP_CHANNEL_DESCRIPTOR_STATUS_INVALID_PARAMETER;
	}

	descriptor->max_key_count = max_key_count;
	return LTTNG_MAP_CHANNEL_DESCRIPTOR_STATUS_OK;
}

enum lttng_map_channel_descriptor_status lttng_map_channel_descriptor_get_max_key_count(
	const struct lttng_map_channel_descriptor *descriptor, uint64_t *max_key_count)
{
	if (!descriptor || !max_key_count) {
		return LTTNG_MAP_CHANNEL_DESCRIPTOR_STATUS_INVALID_PARAMETER;
	}

	*max_key_count = descriptor->max_key_count;
	return LTTNG_MAP_CHANNEL_DESCRIPTOR_STATUS_OK;
}

enum lttng_map_channel_descriptor_status
lttng_map_channel_descriptor_set_update_policy(struct lttng_map_channel_descriptor *descriptor,
					       enum lttng_map_channel_update_policy policy)
{
	if (!descriptor || !lcmd::update_policy_is_valid(policy)) {
		return LTTNG_MAP_CHANNEL_DESCRIPTOR_STATUS_INVALID_PARAMETER;
	}

	descriptor->update_policy = policy;
	return LTTNG_MAP_CHANNEL_DESCRIPTOR_STATUS_OK;
}

enum lttng_map_channel_descriptor_status lttng_map_channel_descriptor_get_update_policy(
	const struct lttng_map_channel_descriptor *descriptor,
	enum lttng_map_channel_update_policy *policy)
{
	if (!descriptor || !policy) {
		return LTTNG_MAP_CHANNEL_DESCRIPTOR_STATUS_INVALID_PARAMETER;
	}

	*policy = descriptor->update_policy;
	return LTTNG_MAP_CHANNEL_DESCRIPTOR_STATUS_OK;
}

void lttng_map_channel_descriptor_destroy(struct lttng_map_channel_descriptor *descriptor)
{
	delete descriptor;
}

enum lttng_map_channel_descriptor_status lttng_map_channel_descriptor_user_get_buffer_ownership(
	const struct lttng_map_channel_descriptor *descriptor,
	enum lttng_map_channel_buffer_ownership *ownership_model)
{
	if (!descriptor || !ownership_model || descriptor->type != LTTNG_MAP_CHANNEL_TYPE_USER) {
		return LTTNG_MAP_CHANNEL_DESCRIPTOR_STATUS_INVALID_PARAMETER;
	}

	*ownership_model = descriptor->buffer_ownership;
	return LTTNG_MAP_CHANNEL_DESCRIPTOR_STATUS_OK;
}

enum lttng_map_channel_descriptor_status lttng_map_channel_descriptor_user_set_dead_group_policy(
	struct lttng_map_channel_descriptor *descriptor,
	enum lttng_map_channel_dead_group_policy policy)
{
	if (!descriptor || descriptor->type != LTTNG_MAP_CHANNEL_TYPE_USER ||
	    descriptor->buffer_ownership != LTTNG_MAP_CHANNEL_BUFFER_OWNERSHIP_PER_PID ||
	    !lcmd::dead_group_policy_is_valid(policy)) {
		return LTTNG_MAP_CHANNEL_DESCRIPTOR_STATUS_INVALID_PARAMETER;
	}

	descriptor->dead_group_policy = policy;
	return LTTNG_MAP_CHANNEL_DESCRIPTOR_STATUS_OK;
}

enum lttng_map_channel_descriptor_status lttng_map_channel_descriptor_user_get_dead_group_policy(
	const struct lttng_map_channel_descriptor *descriptor,
	enum lttng_map_channel_dead_group_policy *policy)
{
	if (!descriptor || !policy || descriptor->type != LTTNG_MAP_CHANNEL_TYPE_USER ||
	    descriptor->buffer_ownership != LTTNG_MAP_CHANNEL_BUFFER_OWNERSHIP_PER_PID) {
		return LTTNG_MAP_CHANNEL_DESCRIPTOR_STATUS_INVALID_PARAMETER;
	}

	*policy = descriptor->dead_group_policy;
	return LTTNG_MAP_CHANNEL_DESCRIPTOR_STATUS_OK;
}

} /* extern "C" */
