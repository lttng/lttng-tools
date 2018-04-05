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

#ifndef LTTNG_LOCATION_INTERNAL_H
#define LTTNG_LOCATION_INTERNAL_H

#include <lttng/location.h>
#include <common/macros.h>

struct lttng_trace_archive_location {
	enum lttng_trace_archive_location_type type;
	union {
		struct {
			char *absolute_path;
		} local;
		struct {
			char *host;
			enum lttng_trace_archive_location_relay_protocol_type protocol;
			struct {
				uint16_t control, data;
			} ports;
			char *relative_path;
		} relay;
	} types;
};

LTTNG_HIDDEN
struct lttng_trace_archive_location *lttng_trace_archive_location_local_create(
		const char *path);

LTTNG_HIDDEN
struct lttng_trace_archive_location *lttng_trace_archive_location_relay_create(
		const char *host,
		enum lttng_trace_archive_location_relay_protocol_type protocol,
		uint16_t control_port, uint16_t data_port,
		const char *relative_path);

LTTNG_HIDDEN
void lttng_trace_archive_location_destroy(
		struct lttng_trace_archive_location *location);

#endif /* LTTNG_LOCATION_INTERNAL_H */
