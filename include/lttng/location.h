/*
 * Copyright (C) 2018 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_LOCATION_H
#define LTTNG_LOCATION_H

#include <lttng/lttng-export.h>

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum lttng_trace_archive_location_type {
	LTTNG_TRACE_ARCHIVE_LOCATION_TYPE_UNKNOWN = 0,
	LTTNG_TRACE_ARCHIVE_LOCATION_TYPE_LOCAL = 1,
	LTTNG_TRACE_ARCHIVE_LOCATION_TYPE_RELAY = 2,
};

enum lttng_trace_archive_location_status {
	LTTNG_TRACE_ARCHIVE_LOCATION_STATUS_OK = 0,
	LTTNG_TRACE_ARCHIVE_LOCATION_STATUS_INVALID = -1,
	LTTNG_TRACE_ARCHIVE_LOCATION_STATUS_ERROR = -2,
};

enum lttng_trace_archive_location_relay_protocol_type {
	LTTNG_TRACE_ARCHIVE_LOCATION_RELAY_PROTOCOL_TYPE_TCP = 0,
};

/*
 * Location of a trace archive.
 */
struct lttng_trace_archive_location;

/*
 * Get a trace archive location's type.
 */
LTTNG_EXPORT extern enum lttng_trace_archive_location_type
lttng_trace_archive_location_get_type(const struct lttng_trace_archive_location *location);

/*
 * Get the absolute path of a local trace archive location.
 *
 * The trace archive location maintains ownership of the absolute_path.
 */
LTTNG_EXPORT extern enum lttng_trace_archive_location_status
lttng_trace_archive_location_local_get_absolute_path(
	const struct lttng_trace_archive_location *location, const char **absolute_path);

/*
 * Get the host address of the relay daemon associated to this trace archive
 * location. May be a hostname, IPv4, or IPv6 address.
 *
 * The trace archive location maintains ownership of relay_host.
 */
LTTNG_EXPORT extern enum lttng_trace_archive_location_status
lttng_trace_archive_location_relay_get_host(const struct lttng_trace_archive_location *location,
					    const char **relay_host);

/*
 * Get the control port of the relay daemon associated to this trace archive
 * location.
 */
LTTNG_EXPORT extern enum lttng_trace_archive_location_status
lttng_trace_archive_location_relay_get_control_port(
	const struct lttng_trace_archive_location *location, uint16_t *control_port);

/*
 * Get the data port of the relay daemon associated to this trace archive
 * location.
 */
LTTNG_EXPORT extern enum lttng_trace_archive_location_status
lttng_trace_archive_location_relay_get_data_port(
	const struct lttng_trace_archive_location *location, uint16_t *data_port);

/*
 * Get the protocol used to communicate with the relay daemon associated to this
 * trace archive location.
 */
LTTNG_EXPORT extern enum lttng_trace_archive_location_status
lttng_trace_archive_location_relay_get_protocol_type(
	const struct lttng_trace_archive_location *location,
	enum lttng_trace_archive_location_relay_protocol_type *protocol);

/*
 * Get path relative to the relay daemon's current output path.
 *
 * The trace archive location maintains ownership of relative_path.
 */
LTTNG_EXPORT extern enum lttng_trace_archive_location_status
lttng_trace_archive_location_relay_get_relative_path(
	const struct lttng_trace_archive_location *location, const char **relative_path);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_LOCATION_H */
