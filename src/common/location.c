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

LTTNG_HIDDEN
ssize_t lttng_trace_archive_location_create_from_buffer(
		const struct lttng_buffer_view *view,
		struct lttng_trace_archive_location **location)
{
	size_t offset = 0;
	const struct lttng_trace_archive_location_comm *location_comm;
	struct lttng_buffer_view location_comm_view;

	location_comm_view = lttng_buffer_view_from_view(view, 0,
			sizeof(*location_comm));
	if (!location_comm_view.data) {
		goto error;
	}
	offset += location_comm_view.size;
	location_comm = (const struct lttng_trace_archive_location_comm *) view->data;

	switch ((enum lttng_trace_archive_location_type) location_comm->type) {
	case LTTNG_TRACE_ARCHIVE_LOCATION_TYPE_LOCAL:
	{
		const struct lttng_buffer_view absolute_path_view =
				lttng_buffer_view_from_view(view, offset,
				location_comm->types.local.absolute_path_len);

		if (!absolute_path_view.data) {
			goto error;
		}
		if (absolute_path_view.data[absolute_path_view.size - 1] != '\0') {
			goto error;
		}
		offset += absolute_path_view.size;

		*location = lttng_trace_archive_location_local_create(
				absolute_path_view.data);
		if (!*location) {
			goto error;
		}
		break;
	}
	case LTTNG_TRACE_ARCHIVE_LOCATION_TYPE_RELAY:
	{
		const struct lttng_buffer_view hostname_view =
				lttng_buffer_view_from_view(view, offset,
				location_comm->types.relay.hostname_len);
		const struct lttng_buffer_view relative_path_view =
				lttng_buffer_view_from_view(view,
				offset + hostname_view.size,
				location_comm->types.relay.relative_path_len);

		if (!hostname_view.data || !relative_path_view.data) {
			goto error;
		}
		if (hostname_view.data[hostname_view.size - 1] != '\0') {
			goto error;
		}
		if (relative_path_view.data[relative_path_view.size - 1] != '\0') {
			goto error;
		}
		offset += hostname_view.size + relative_path_view.size;

		*location = lttng_trace_archive_location_relay_create(
				hostname_view.data,
				(enum lttng_trace_archive_location_relay_protocol_type) location_comm->types.relay.protocol,
				location_comm->types.relay.ports.control,
				location_comm->types.relay.ports.data,
				relative_path_view.data);
		if (!*location) {
			goto error;
		}
		break;
	}
	default:
		goto error;
	}

error:
	return -1;
}

LTTNG_HIDDEN
ssize_t lttng_trace_archive_location_serialize(
		const struct lttng_trace_archive_location *location,
		struct lttng_dynamic_buffer *buffer)
{
	int ret;
	struct lttng_trace_archive_location_comm location_comm;
	const size_t original_buffer_size = buffer->size;

	location_comm.type = (int8_t) location->type;

	switch (location->type) {
	case LTTNG_TRACE_ARCHIVE_LOCATION_TYPE_LOCAL:
		location_comm.types.local.absolute_path_len =
				strlen(location->types.local.absolute_path) + 1;
		break;
	case LTTNG_TRACE_ARCHIVE_LOCATION_TYPE_RELAY:
		location_comm.types.relay.hostname_len =
				strlen(location->types.relay.host) + 1;
		location_comm.types.relay.protocol =
				(int8_t) location->types.relay.protocol;
		location_comm.types.relay.ports.control =
				location->types.relay.ports.control;
		location_comm.types.relay.ports.data =
				location->types.relay.ports.data;
		location_comm.types.relay.relative_path_len =
				strlen(location->types.relay.relative_path) + 1;
		break;
	default:
		abort();
	}

	ret = lttng_dynamic_buffer_append(buffer, &location_comm,
			sizeof(location_comm));
	if (ret) {
		goto error;
	}

	switch (location->type) {
	case LTTNG_TRACE_ARCHIVE_LOCATION_TYPE_LOCAL:
		ret = lttng_dynamic_buffer_append(buffer,
				location->types.local.absolute_path,
				location_comm.types.local.absolute_path_len);
		if (ret) {
			goto error;
		}
		break;
	case LTTNG_TRACE_ARCHIVE_LOCATION_TYPE_RELAY:
		ret = lttng_dynamic_buffer_append(buffer,
				location->types.relay.host,
				location_comm.types.relay.hostname_len);
		if (ret) {
			goto error;
		}
		ret = lttng_dynamic_buffer_append(buffer,
				location->types.relay.relative_path,
				location_comm.types.relay.relative_path_len);
		if (ret) {
			goto error;
		}
		break;
	default:
		abort();
	}

	return buffer->size - original_buffer_size;
error:
	return -1;
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
