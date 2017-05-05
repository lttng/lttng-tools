/*
 * Copyright (C) 2017 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License, version 2.1 only,
 * as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef LTTNG_CONDITION_BUFFER_USAGE_INTERNAL_H
#define LTTNG_CONDITION_BUFFER_USAGE_INTERNAL_H

#include <lttng/condition/buffer-usage.h>
#include <lttng/condition/condition-internal.h>
#include <lttng/condition/evaluation-internal.h>
#include <lttng/domain.h>
#include "common/buffer-view.h"

struct lttng_condition_buffer_usage {
	struct lttng_condition parent;
	struct {
		bool set;
		uint64_t value;
	} threshold_bytes;
	struct {
		bool set;
		double value;
	} threshold_ratio;
	char *session_name;
	char *channel_name;
	struct {
		bool set;
		enum lttng_domain_type type;
	} domain;
};

struct lttng_condition_buffer_usage_comm {
	uint8_t threshold_set_in_bytes;
	/*
	 * Expressed in bytes if "threshold_set_in_bytes" is not 0.
	 * Otherwise, it is expressed a ratio in the interval [0.0, 1.0]
	 * that is mapped to the range on a 32-bit unsigned integer.
	 * The ratio is obtained by (threshold / UINT32_MAX).
	 */
	uint32_t threshold;
	/* Both lengths include the trailing \0. */
	uint32_t session_name_len;
	uint32_t channel_name_len;
	/* enum lttng_domain_type */
	int8_t domain_type;
	/* session and channel names. */
	char names[];
} LTTNG_PACKED;

struct lttng_evaluation_buffer_usage {
	struct lttng_evaluation parent;
	uint64_t buffer_use;
	uint64_t buffer_capacity;
};

struct lttng_evaluation_buffer_usage_comm {
	uint64_t buffer_use;
	uint64_t buffer_capacity;
} LTTNG_PACKED;

LTTNG_HIDDEN
struct lttng_evaluation *lttng_evaluation_buffer_usage_create(
		enum lttng_condition_type type, uint64_t use,
		uint64_t capacity);

LTTNG_HIDDEN
ssize_t lttng_condition_buffer_usage_low_create_from_buffer(
		const struct lttng_buffer_view *view,
		struct lttng_condition **condition);

LTTNG_HIDDEN
ssize_t lttng_condition_buffer_usage_high_create_from_buffer(
		const struct lttng_buffer_view *view,
		struct lttng_condition **condition);

LTTNG_HIDDEN
ssize_t lttng_evaluation_buffer_usage_low_create_from_buffer(
		const struct lttng_buffer_view *view,
		struct lttng_evaluation **evaluation);

LTTNG_HIDDEN
ssize_t lttng_evaluation_buffer_usage_high_create_from_buffer(
		const struct lttng_buffer_view *view,
		struct lttng_evaluation **evaluation);

#endif /* LTTNG_CONDITION_BUFFER_USAGE_INTERNAL_H */
