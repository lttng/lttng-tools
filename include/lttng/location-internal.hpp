/*
 * Copyright (C) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_LOCATION_INTERNAL_H
#define LTTNG_LOCATION_INTERNAL_H

#include <common/buffer-view.hpp>
#include <common/dynamic-buffer.hpp>
#include <common/macros.hpp>

#include <lttng/location.h>

#include <sys/types.h>
#include <urcu/ref.h>

/*
 * The public API assumes that trace archive locations are always
 * provided as "constant". This means that the user of liblttng-ctl never
 * has to destroy a trace archive location. Hence, users of liblttng-ctl
 * have no visibility of the reference counting of archive locations.
 */
struct lttng_trace_archive_location {
	struct urcu_ref ref;
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

struct lttng_trace_archive_location *lttng_trace_archive_location_local_create(const char *path);

struct lttng_trace_archive_location *lttng_trace_archive_location_relay_create(
	const char *host,
	enum lttng_trace_archive_location_relay_protocol_type protocol,
	uint16_t control_port,
	uint16_t data_port,
	const char *relative_path);

ssize_t
lttng_trace_archive_location_create_from_buffer(const struct lttng_buffer_view *buffer,
						struct lttng_trace_archive_location **location);

ssize_t lttng_trace_archive_location_serialize(const struct lttng_trace_archive_location *location,
					       struct lttng_dynamic_buffer *buffer);

void lttng_trace_archive_location_get(struct lttng_trace_archive_location *location);

void lttng_trace_archive_location_put(struct lttng_trace_archive_location *location);

#endif /* LTTNG_LOCATION_INTERNAL_H */
