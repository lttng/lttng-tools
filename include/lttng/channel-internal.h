/*
 * Copyright (C) 2015 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
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

#ifndef LTTNG_CHANNEL_INTERNAL_H
#define LTTNG_CHANNEL_INTERNAL_H

struct lttng_channel_extended {
	uint64_t discarded_events;
	uint64_t lost_packets;
	uint64_t monitor_timer_interval;
	int64_t blocking_timeout;
} LTTNG_PACKED;

#endif /* LTTNG_CHANNEL_INTERNAL_H */
