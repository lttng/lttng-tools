/*
 * Copyright (C) 2015 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_CHANNEL_INTERNAL_H
#define LTTNG_CHANNEL_INTERNAL_H

#include <common/macros.h>

struct lttng_channel_extended {
	uint64_t discarded_events;
	uint64_t lost_packets;
	uint64_t monitor_timer_interval;
	int64_t blocking_timeout;
} LTTNG_PACKED;

#endif /* LTTNG_CHANNEL_INTERNAL_H */
