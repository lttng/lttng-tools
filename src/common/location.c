/*
 * Copyright (C) 2018 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
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

#include <lttng/location-internal.h>
#include <common/macros.h>
#include <stdlib.h>

static
struct lttng_trace_archive_location *lttng_trace_archive_location_create(
		enum lttng_trace_archive_location_type type)
{
	struct lttng_trace_archive_location *location;

	location = zmalloc(sizeof(*location));
	if (!location) {
		goto end;
	}

	location->type = type;
end:
	return location;
}

LTTNG_HIDDEN
void lttng_trace_archive_location_destroy(
		struct lttng_trace_archive_location *location)
{
	if (!location) {
		return;
	}

	switch (location->type) {
	case LTTNG_TRACE_ARCHIVE_LOCATION_TYPE_LOCAL:
		free(location->types.local.absolute_path);
		break;
	case LTTNG_TRACE_ARCHIVE_LOCATION_TYPE_RELAY:
		free(location->types.relay.host);
		free(location->types.relay.relative_path);
		break;
	default:
		abort();
	}

	free(location);
}

LTTNG_HIDDEN
struct lttng_trace_archive_location *lttng_trace_archive_location_local_create(
		const char *absolute_path)
{
	struct lttng_trace_archive_location *location = NULL;

	if (!absolute_path) {
		goto end;
	}

	location = lttng_trace_archive_location_create(
			LTTNG_TRACE_ARCHIVE_LOCATION_TYPE_LOCAL);
	if (!location) {
		goto end;
	}

	location->types.local.absolute_path = strdup(absolute_path);
	if (!location->types.local.absolute_path) {
		goto error;
	}

end:
	return location;
error:
	lttng_trace_archive_location_destroy(location);
	return NULL;
}

LTTNG_HIDDEN
struct lttng_trace_archive_location *lttng_trace_archive_location_relay_create(
		const char *host,
		enum lttng_trace_archive_location_relay_protocol_type protocol,
		uint16_t control_port, uint16_t data_port,
		const char *relative_path)
{
	struct lttng_trace_archive_location *location = NULL;

	if (!host || !relative_path) {
		goto end;
	}

	location = lttng_trace_archive_location_create(
			LTTNG_TRACE_ARCHIVE_LOCATION_TYPE_RELAY);
	if (!location) {
		goto end;
	}

	location->types.relay.host = strdup(host);
	if (!location->types.relay.host) {
		goto error;
	}
	location->types.relay.relative_path = strdup(relative_path);
	if (!location->types.relay.relative_path) {
		goto error;
	}

	location->types.relay.protocol = protocol;
	location->types.relay.ports.control = control_port;
	location->types.relay.ports.data = data_port;
end:
	return location;
error:
	lttng_trace_archive_location_destroy(location);
	return NULL;
}

enum lttng_trace_archive_location_type lttng_trace_archive_location_get_type(
		const struct lttng_trace_archive_location *location)
{
	enum lttng_trace_archive_location_type type;

	if (!location) {
		type = LTTNG_TRACE_ARCHIVE_LOCATION_TYPE_UNKNOWN;
		goto end;
	}

	type = location->type;
end:
	return type;
}

enum lttng_trace_archive_location_status
lttng_trace_archive_location_local_get_absolute_path(
		const struct lttng_trace_archive_location *location,
		const char **absolute_path)
{
	enum lttng_trace_archive_location_status status =
			LTTNG_TRACE_ARCHIVE_LOCATION_STATUS_OK;

	if (!location || !absolute_path ||
			location->type != LTTNG_TRACE_ARCHIVE_LOCATION_TYPE_LOCAL) {
		status = LTTNG_TRACE_ARCHIVE_LOCATION_STATUS_INVALID;
		goto end;
	}

	*absolute_path = location->types.local.absolute_path;
end:
	return status;
}

enum lttng_trace_archive_location_status
lttng_trace_archive_location_relay_get_host(
		const struct lttng_trace_archive_location *location,
		const char **relay_host)
{
	enum lttng_trace_archive_location_status status =
			LTTNG_TRACE_ARCHIVE_LOCATION_STATUS_OK;

	if (!location || !relay_host ||
			location->type != LTTNG_TRACE_ARCHIVE_LOCATION_TYPE_RELAY) {
		status = LTTNG_TRACE_ARCHIVE_LOCATION_STATUS_INVALID;
		goto end;
	}

	*relay_host = location->types.relay.host;
end:
	return status;
}

enum lttng_trace_archive_location_status
lttng_trace_archive_location_relay_get_relative_path(
		const struct lttng_trace_archive_location *location,
		const char **relative_path)
{
	enum lttng_trace_archive_location_status status =
			LTTNG_TRACE_ARCHIVE_LOCATION_STATUS_OK;

	if (!location || !relative_path ||
			location->type != LTTNG_TRACE_ARCHIVE_LOCATION_TYPE_RELAY) {
		status = LTTNG_TRACE_ARCHIVE_LOCATION_STATUS_INVALID;
		goto end;
	}

	*relative_path = location->types.relay.relative_path;
end:
	return status;
}

enum lttng_trace_archive_location_status
lttng_trace_archive_location_relay_get_control_port(
		const struct lttng_trace_archive_location *location,
		uint16_t *control_port)
{
	enum lttng_trace_archive_location_status status =
			LTTNG_TRACE_ARCHIVE_LOCATION_STATUS_OK;

	if (!location || !control_port ||
			location->type != LTTNG_TRACE_ARCHIVE_LOCATION_TYPE_RELAY) {
		status = LTTNG_TRACE_ARCHIVE_LOCATION_STATUS_INVALID;
		goto end;
	}

	*control_port = location->types.relay.ports.control;
end:
	return status;
}

enum lttng_trace_archive_location_status
lttng_trace_archive_location_relay_get_data_port(
		const struct lttng_trace_archive_location *location,
		uint16_t *data_port)
{
	enum lttng_trace_archive_location_status status =
			LTTNG_TRACE_ARCHIVE_LOCATION_STATUS_OK;

	if (!location || !data_port ||
			location->type != LTTNG_TRACE_ARCHIVE_LOCATION_TYPE_RELAY) {
		status = LTTNG_TRACE_ARCHIVE_LOCATION_STATUS_INVALID;
		goto end;
	}

	*data_port = location->types.relay.ports.data;
end:
	return status;
}

enum lttng_trace_archive_location_status
lttng_trace_archive_location_relay_get_protocol_type(
		const struct lttng_trace_archive_location *location,
		enum lttng_trace_archive_location_relay_protocol_type *protocol)
{
	enum lttng_trace_archive_location_status status =
			LTTNG_TRACE_ARCHIVE_LOCATION_STATUS_OK;

	if (!location || !protocol ||
			location->type != LTTNG_TRACE_ARCHIVE_LOCATION_TYPE_RELAY) {
		status = LTTNG_TRACE_ARCHIVE_LOCATION_STATUS_INVALID;
		goto end;
	}

	*protocol = location->types.relay.protocol;
end:
	return status;
}
