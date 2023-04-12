/*
 * Copyright (C) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_CONDITION_BUFFER_USAGE_INTERNAL_H
#define LTTNG_CONDITION_BUFFER_USAGE_INTERNAL_H

#include "common/buffer-view.hpp"

#include <common/macros.hpp>

#include <lttng/condition/buffer-usage.h>
#include <lttng/condition/condition-internal.hpp>
#include <lttng/condition/evaluation-internal.hpp>
#include <lttng/domain.h>

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
	uint64_t threshold_bytes;
	double threshold_ratio;
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

struct lttng_evaluation *lttng_evaluation_buffer_usage_create(enum lttng_condition_type type,
							      uint64_t use,
							      uint64_t capacity);

ssize_t lttng_condition_buffer_usage_low_create_from_payload(struct lttng_payload_view *view,
							     struct lttng_condition **condition);

ssize_t lttng_condition_buffer_usage_high_create_from_payload(struct lttng_payload_view *view,
							      struct lttng_condition **condition);

ssize_t lttng_evaluation_buffer_usage_low_create_from_payload(struct lttng_payload_view *view,
							      struct lttng_evaluation **evaluation);

ssize_t
lttng_evaluation_buffer_usage_high_create_from_payload(struct lttng_payload_view *view,
						       struct lttng_evaluation **evaluation);

#endif /* LTTNG_CONDITION_BUFFER_USAGE_INTERNAL_H */
