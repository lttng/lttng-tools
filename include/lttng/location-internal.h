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
#include <common/dynamic-buffer.h>
#include <common/buffer-view.h>
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

struct lttng_trace_archive_location_comm {
	/* A value from enum lttng_trace_archive_location_type */
	int8_t type;
	union {
		struct {
			/* Includes the trailing \0. */
			uint32_t absolute_path_len;
		} LTTNG_PACKED local;
		struct {
			/* Includes the trailing \0. */
			uint32_t hostname_len;
			/*
			 * A value from
			 * enum lttng_trace_archive_location_relay_protocol_type.
			 */
			int8_t protocol;
			struct {
				uint16_t control, data;
			} ports;
			/* Includes the trailing \0. */
			uint32_t relative_path_len;
		} LTTNG_PACKED relay;
	} LTTNG_PACKED types;
	/*
	 * Payload is composed of:
	 * - LTTNG_TRACE_ARCHIVE_LOCATION_TYPE_LOCAL
	 *   - absolute path, including \0
	 * - LTTNG_TRACE_ARCHIVE_LOCATION_TYPE_RELAY
	 *   - hostname, including \0
	 *   - relative path, including \0
	 */
	char payload[];
} LTTNG_PACKED;


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
ssize_t lttng_trace_archive_location_create_from_buffer(
		const struct lttng_buffer_view *buffer,
		struct lttng_trace_archive_location **location);

LTTNG_HIDDEN
ssize_t lttng_trace_archive_location_serialize(
		const struct lttng_trace_archive_location *location,
		struct lttng_dynamic_buffer *buffer);

LTTNG_HIDDEN
void lttng_trace_archive_location_destroy(
		struct lttng_trace_archive_location *location);

#endif /* LTTNG_LOCATION_INTERNAL_H */
