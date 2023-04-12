/*
 * Copyright (C) 2015 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_CHANNEL_INTERNAL_H
#define LTTNG_CHANNEL_INTERNAL_H

#include <common/macros.hpp>

struct lttng_channel_extended {
	uint64_t discarded_events;
	uint64_t lost_packets;
	uint64_t monitor_timer_interval;
	int64_t blocking_timeout;
} LTTNG_PACKED;

struct lttng_channel_comm {
	/* Includes terminator `\0`. */
	uint32_t name_len;
	uint8_t enabled;

	/* attr */
	int8_t overwrite;
	uint64_t subbuf_size;
	uint64_t num_subbuf;
	uint32_t switch_timer_interval;
	uint32_t read_timer_interval;
	uint8_t output;
	uint64_t tracefile_size;
	uint64_t tracefile_count;
	uint32_t live_timer_interval;

	/* Extended struct */
	uint64_t discarded_events;
	uint64_t lost_packets;
	uint64_t monitor_timer_interval;
	int64_t blocking_timeout;
} LTTNG_PACKED;

struct lttng_channel *lttng_channel_create_internal();

struct lttng_channel *lttng_channel_copy(const struct lttng_channel *src);

ssize_t lttng_channel_create_from_buffer(const struct lttng_buffer_view *view,
					 struct lttng_channel **event);

int lttng_channel_serialize(struct lttng_channel *channel, struct lttng_dynamic_buffer *buf);

void lttng_channel_set_default_extended_attr(struct lttng_domain *domain,
					     struct lttng_channel_extended *extended_attr);

enum lttng_error_code lttng_channels_create_and_flatten_from_buffer(
	const struct lttng_buffer_view *view, unsigned int count, struct lttng_channel **channels);

#endif /* LTTNG_CHANNEL_INTERNAL_H */
