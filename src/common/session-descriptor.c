/*
 * Copyright (C) 2019 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
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

#include <lttng/session-descriptor-internal.h>
#include <common/macros.h>
#include <common/uri.h>
#include <common/defaults.h>
#include <common/error.h>
#include <time.h>
#include <assert.h>
#include <stdio.h>

struct lttng_session_descriptor_network_location {
	struct lttng_uri *control;
	struct lttng_uri *data;
};

struct lttng_session_descriptor {
	enum lttng_session_descriptor_type type;
	/*
	 * If an output type that is not OUTPUT_TYPE_NONE is specified,
	 * it means that an output of that type must be generated at
	 * session-creation time.
	 */
	enum lttng_session_descriptor_output_type output_type;
	char *name;
	union {
		struct lttng_session_descriptor_network_location network;
		struct lttng_uri *local;
	} output;
};

struct lttng_session_descriptor_snapshot {
	struct lttng_session_descriptor base;
	/*
	 * Assumes at-most one snapshot output is supported. Uses
	 * the output field of the base class.
	 */
};

struct lttng_session_descriptor_live {
	struct lttng_session_descriptor base;
	unsigned long long live_timer_us;
};

struct lttng_session_descriptor_comm {
	/* enum lttng_session_descriptor_type */
	uint8_t type;
	/* enum lttng_session_descriptor_output_type */
	uint8_t output_type;
	/* Includes trailing null. */
	uint32_t name_len;
	/* Name follows, followed by URIs */
	uint8_t uri_count;
} LTTNG_PACKED;

struct lttng_session_descriptor_live_comm {
	struct lttng_session_descriptor_comm base;
	/* Live-specific parameters. */
	uint64_t live_timer_us;
} LTTNG_PACKED;

static
struct lttng_uri *uri_copy(const struct lttng_uri *uri)
{
	struct lttng_uri *new_uri = NULL;

	if (!uri) {
		goto end;
	}

	new_uri = zmalloc(sizeof(*new_uri));
	if (!new_uri) {
		goto end;
	}
	memcpy(new_uri, uri, sizeof(*new_uri));
end:
	return new_uri;
}

static
struct lttng_uri *uri_from_path(const char *path)
{
	struct lttng_uri *uris = NULL;
	ssize_t uri_count;
	char local_protocol_string[LTTNG_PATH_MAX + sizeof("file://")] =
			"file://";

	if (strlen(path) >= LTTNG_PATH_MAX) {
		goto end;
	}

	if (path[0] != '/') {
		/* Not an absolute path. */
		goto end;
	}

	strncat(local_protocol_string, path, LTTNG_PATH_MAX);
	uri_count = uri_parse(local_protocol_string, &uris);
	if (uri_count != 1) {
		goto error;
	}
	if (uris[0].dtype != LTTNG_DST_PATH) {
		goto error;
	}

end:
	return uris;
error:
	free(uris);
	return NULL;
}

static
void network_location_fini(
		struct lttng_session_descriptor_network_location *location)
{
	free(location->control);
	free(location->data);
}

/* Assumes ownership of control and data. */
static
int network_location_set_from_lttng_uris(
		struct lttng_session_descriptor_network_location *location,
		struct lttng_uri *control, struct lttng_uri *data)
{
	int ret = 0;

	if (!control && !data) {
		goto end;
	}

	if (!(control && data)) {
		/* None or both must be set. */
		ret = -1;
		goto end;
	}

	if (control->stype != LTTNG_STREAM_CONTROL ||
			data->stype != LTTNG_STREAM_DATA) {
		ret = -1;
		goto end;
	}

	free(location->control);
	free(location->data);
	location->control = control;
	location->data = data;
	control = NULL;
	data = NULL;
end:
	free(control);
	free(data);
	return ret;
}

static
int network_location_set_from_uri_strings(
		struct lttng_session_descriptor_network_location *location,
		const char *control, const char *data)
{
	int ret = 0;
	ssize_t uri_count;
	struct lttng_uri *parsed_uris = NULL;
	struct lttng_uri *control_uri = NULL;
	struct lttng_uri *data_uri = NULL;

	uri_count = uri_parse_str_urls(control, data, &parsed_uris);
	if (uri_count != 2 && uri_count != 0) {
		ret = -1;
		goto end;
	}

	/*
	 * uri_parse_str_urls returns a contiguous array of lttng_uris whereas
	 * session descriptors expect individually allocated lttng_uris.
	 */
	if (uri_count == 2) {
		control_uri = zmalloc(sizeof(*control_uri));
		data_uri = zmalloc(sizeof(*data_uri));
		if (!control_uri || !data_uri) {
			ret = -1;
			goto end;
		}
		memcpy(control_uri, &parsed_uris[0], sizeof(*control_uri));
		memcpy(data_uri, &parsed_uris[1], sizeof(*data_uri));
	}

	/* Ownership of control and data uris is transferred. */
	ret = network_location_set_from_lttng_uris(
			location,
			control_uri,
			data_uri);
	control_uri = NULL;
	data_uri = NULL;
end:
	free(parsed_uris);
	free(control_uri);
	free(data_uri);
	return ret;
}

struct lttng_session_descriptor *
lttng_session_descriptor_create(const char *name)
{
	struct lttng_session_descriptor *descriptor;

	descriptor = zmalloc(sizeof(*descriptor));
	if (!descriptor) {
		goto error;
	}

	descriptor->type = LTTNG_SESSION_DESCRIPTOR_TYPE_REGULAR;
	descriptor->output_type =
			LTTNG_SESSION_DESCRIPTOR_OUTPUT_TYPE_NONE;
	if (lttng_session_descriptor_set_session_name(descriptor, name)) {
		goto error;
	}
	return descriptor;
error:
	lttng_session_descriptor_destroy(descriptor);
	return NULL;
}

/* Ownership of uri is transferred. */
static
struct lttng_session_descriptor *
_lttng_session_descriptor_local_create(const char *name,
		struct lttng_uri *uri)
{
	struct lttng_session_descriptor *descriptor;

	descriptor = lttng_session_descriptor_create(name);
	if (!descriptor) {
		goto error;
	}
	descriptor->type = LTTNG_SESSION_DESCRIPTOR_TYPE_REGULAR;
	descriptor->output_type =
			LTTNG_SESSION_DESCRIPTOR_OUTPUT_TYPE_LOCAL;
	if (uri) {
		if (uri->dtype != LTTNG_DST_PATH) {
			goto error;
		}
		descriptor->output.local = uri;
		uri = NULL;
	}
	return descriptor;
error:
	free(uri);
	lttng_session_descriptor_destroy(descriptor);
	return NULL;
}

struct lttng_session_descriptor *
lttng_session_descriptor_local_create(const char *name, const char *path)
{
	struct lttng_uri *uri = NULL;
	struct lttng_session_descriptor *descriptor;

	if (path) {
		uri = uri_from_path(path);
		if (!uri) {
			goto error;
		}
	}
	descriptor = _lttng_session_descriptor_local_create(name, uri);
	return descriptor;
error:
	return NULL;
}

/* Assumes the ownership of both uris. */
static
struct lttng_session_descriptor *
_lttng_session_descriptor_network_create(const char *name,
		struct lttng_uri *control, struct lttng_uri *data)
{
	int ret;
	struct lttng_session_descriptor *descriptor;

	descriptor = lttng_session_descriptor_create(name);
	if (!descriptor) {
		goto error;
	}

	descriptor->type = LTTNG_SESSION_DESCRIPTOR_TYPE_REGULAR;
	descriptor->output_type = LTTNG_SESSION_DESCRIPTOR_OUTPUT_TYPE_NETWORK;
	/* Assumes the ownership of both uris. */
	ret = network_location_set_from_lttng_uris(&descriptor->output.network,
			control, data);
	control = NULL;
	data = NULL;
	if (ret) {
		goto error;
	}
	return descriptor;
error:
	lttng_session_descriptor_destroy(descriptor);
	free(control);
	free(data);
	return NULL;
}

struct lttng_session_descriptor *
lttng_session_descriptor_network_create(const char *name,
		const char *control_url, const char *data_url)
{
	int ret;
	struct lttng_session_descriptor *descriptor;

	descriptor = _lttng_session_descriptor_network_create(name,
			NULL, NULL);
	if (!descriptor) {
		goto error;
	}

	ret = network_location_set_from_uri_strings(&descriptor->output.network,
			control_url, data_url);
	if (ret) {
		goto error;
	}
	return descriptor;
error:
	lttng_session_descriptor_destroy(descriptor);
	return NULL;
}

static
struct lttng_session_descriptor_snapshot *
_lttng_session_descriptor_snapshot_create(const char *name)
{
	struct lttng_session_descriptor_snapshot *descriptor;

	descriptor = zmalloc(sizeof(*descriptor));
	if (!descriptor) {
		goto error;
	}

	descriptor->base.type = LTTNG_SESSION_DESCRIPTOR_TYPE_SNAPSHOT;
	descriptor->base.output_type =
			LTTNG_SESSION_DESCRIPTOR_OUTPUT_TYPE_NONE;
	if (lttng_session_descriptor_set_session_name(&descriptor->base,
			name)) {
		goto error;
	}
	return descriptor;
error:
	lttng_session_descriptor_destroy(descriptor ? &descriptor->base : NULL);
	return NULL;
}

/* Ownership of control and data is transferred. */
static
struct lttng_session_descriptor_snapshot *
_lttng_session_descriptor_snapshot_network_create(const char *name,
		struct lttng_uri *control, struct lttng_uri *data)
{
	int ret;
	struct lttng_session_descriptor_snapshot *descriptor;

	descriptor = _lttng_session_descriptor_snapshot_create(name);
	if (!descriptor) {
		goto error;
	}

	descriptor->base.output_type =
			LTTNG_SESSION_DESCRIPTOR_OUTPUT_TYPE_NETWORK;
	/* Ownership of control and data is transferred. */
	ret = network_location_set_from_lttng_uris(
			&descriptor->base.output.network,
			control, data);
	control = NULL;
	data = NULL;
	if (ret) {
		goto error;
	}
	return descriptor;
error:
	free(control);
	free(data);
	lttng_session_descriptor_destroy(descriptor ? &descriptor->base : NULL);
	return NULL;
}

struct lttng_session_descriptor *
lttng_session_descriptor_snapshot_create(const char *name)
{
	struct lttng_session_descriptor_snapshot *descriptor;

	descriptor = _lttng_session_descriptor_snapshot_create(name);
	return descriptor ? &descriptor->base : NULL;
}

struct lttng_session_descriptor *
lttng_session_descriptor_snapshot_network_create(const char *name,
		const char *control_url, const char *data_url)
{
	int ret;
	struct lttng_session_descriptor_snapshot *descriptor;

	descriptor = _lttng_session_descriptor_snapshot_network_create(name,
			NULL, NULL);
	if (!descriptor) {
		goto error;
	}

	ret = network_location_set_from_uri_strings(
			&descriptor->base.output.network,
			control_url, data_url);
	if (ret) {
		goto error;
	}
	return &descriptor->base;
error:
	lttng_session_descriptor_destroy(descriptor ? &descriptor->base : NULL);
	return NULL;
}

/* Ownership of uri is transferred. */
static
struct lttng_session_descriptor_snapshot *
_lttng_session_descriptor_snapshot_local_create(const char *name,
		struct lttng_uri *uri)
{
	struct lttng_session_descriptor_snapshot *descriptor;

	descriptor = _lttng_session_descriptor_snapshot_create(name);
	if (!descriptor) {
		goto error;
	}
	descriptor->base.output_type =
			LTTNG_SESSION_DESCRIPTOR_OUTPUT_TYPE_LOCAL;
	if (uri) {
		if (uri->dtype != LTTNG_DST_PATH) {
			goto error;
		}
		descriptor->base.output.local = uri;
		uri = NULL;
	}
	return descriptor;
error:
	free(uri);
	lttng_session_descriptor_destroy(descriptor ? &descriptor->base : NULL);
	return NULL;
}

struct lttng_session_descriptor *
lttng_session_descriptor_snapshot_local_create(const char *name,
		const char *path)
{
	struct lttng_uri *path_uri = NULL;
	struct lttng_session_descriptor_snapshot *descriptor;

	if (path) {
		path_uri = uri_from_path(path);
		if (!path_uri) {
			goto error;
		}
	}
	descriptor = _lttng_session_descriptor_snapshot_local_create(name,
			path_uri);
	return descriptor ? &descriptor->base : NULL;
error:
	return NULL;
}

static
struct lttng_session_descriptor_live *
_lttng_session_descriptor_live_create(const char *name,
		unsigned long long live_timer_interval_us)
{
	struct lttng_session_descriptor_live *descriptor = NULL;

	if (live_timer_interval_us == 0) {
		goto error;
	}
	descriptor = zmalloc(sizeof(*descriptor));
	if (!descriptor) {
		goto error;
	}

	descriptor->base.type = LTTNG_SESSION_DESCRIPTOR_TYPE_LIVE;
	descriptor->base.output_type =
			LTTNG_SESSION_DESCRIPTOR_OUTPUT_TYPE_NONE;
	descriptor->live_timer_us = live_timer_interval_us;
	if (lttng_session_descriptor_set_session_name(&descriptor->base,
			name)) {
		goto error;
	}

	return descriptor;
error:
	lttng_session_descriptor_destroy(descriptor ? &descriptor->base : NULL);
	return NULL;
}

/* Ownership of control and data is transferred. */
static
struct lttng_session_descriptor_live *
_lttng_session_descriptor_live_network_create(
		const char *name,
		struct lttng_uri *control, struct lttng_uri *data,
		unsigned long long live_timer_interval_us)
{
	int ret;
	struct lttng_session_descriptor_live *descriptor;

	descriptor = _lttng_session_descriptor_live_create(name,
			live_timer_interval_us);
	if (!descriptor) {
		goto error;
	}

	descriptor->base.output_type =
			LTTNG_SESSION_DESCRIPTOR_OUTPUT_TYPE_NETWORK;

	/* Ownerwhip of control and data is transferred. */
	ret = network_location_set_from_lttng_uris(
			&descriptor->base.output.network,
			control, data);
	control = NULL;
	data = NULL;
	if (ret) {
		goto error;
	}
	return descriptor;
error:
	free(control);
	free(data);
	lttng_session_descriptor_destroy(descriptor ? &descriptor->base : NULL);
	return NULL;
}

struct lttng_session_descriptor *
lttng_session_descriptor_live_create(
		const char *name,
		unsigned long long live_timer_us)
{
	struct lttng_session_descriptor_live *descriptor;

	descriptor = _lttng_session_descriptor_live_create(name, live_timer_us);

	return descriptor ? &descriptor->base : NULL;
}

struct lttng_session_descriptor *
lttng_session_descriptor_live_network_create(
		const char *name,
		const char *control_url, const char *data_url,
		unsigned long long live_timer_us)
{
	int ret;
	struct lttng_session_descriptor_live *descriptor;

	descriptor = _lttng_session_descriptor_live_network_create(name,
			NULL, NULL, live_timer_us);
	if (!descriptor) {
		goto error;
	}

	ret = network_location_set_from_uri_strings(
			&descriptor->base.output.network,
			control_url, data_url);
	if (ret) {
		goto error;
	}
	return &descriptor->base;
error:
	lttng_session_descriptor_destroy(descriptor ? &descriptor->base : NULL);
	return NULL;
}

void lttng_session_descriptor_destroy(
		struct lttng_session_descriptor *descriptor)
{
	if (!descriptor) {
		return;
	}

	switch (descriptor->output_type) {
	case LTTNG_SESSION_DESCRIPTOR_OUTPUT_TYPE_NONE:
		break;
	case LTTNG_SESSION_DESCRIPTOR_OUTPUT_TYPE_LOCAL:
		free(descriptor->output.local);
		break;
	case LTTNG_SESSION_DESCRIPTOR_OUTPUT_TYPE_NETWORK:
		network_location_fini(&descriptor->output.network);
		break;
	default:
		abort();
	}

	free(descriptor->name);
	free(descriptor);
}

LTTNG_HIDDEN
ssize_t lttng_session_descriptor_create_from_buffer(
		const struct lttng_buffer_view *payload,
		struct lttng_session_descriptor **descriptor)
{
	int i;
	ssize_t offset = 0, ret;
	struct lttng_buffer_view current_view;
	const char *name = NULL;
	const struct lttng_session_descriptor_comm *base_header;
	size_t max_expected_uri_count;
	uint64_t live_timer_us = 0;
	struct lttng_uri *uris[2] = {};
	enum lttng_session_descriptor_type type;
	enum lttng_session_descriptor_output_type output_type;

	current_view = lttng_buffer_view_from_view(payload, offset,
			sizeof(*base_header));
	base_header = (typeof(base_header)) current_view.data;
	if (!base_header) {
		ret = -1;
		goto end;
	}

	switch (base_header->type) {
	case LTTNG_SESSION_DESCRIPTOR_TYPE_REGULAR:
	case LTTNG_SESSION_DESCRIPTOR_TYPE_SNAPSHOT:
		break;
	case LTTNG_SESSION_DESCRIPTOR_TYPE_LIVE:
	{
		const struct lttng_session_descriptor_live_comm *live_header;

		current_view = lttng_buffer_view_from_view(payload, offset,
				sizeof(*live_header));
		live_header = (typeof(live_header)) current_view.data;
		if (!live_header) {
			ret = -1;
			goto end;
		}

		live_timer_us = live_header->live_timer_us;
		break;
	}
	default:
		ret = -1;
		goto end;
	}
	/* type has been validated. */
	type = base_header->type;

	switch (base_header->output_type) {
	case LTTNG_SESSION_DESCRIPTOR_OUTPUT_TYPE_NONE:
		max_expected_uri_count = 0;
		break;
	case LTTNG_SESSION_DESCRIPTOR_OUTPUT_TYPE_LOCAL:
		max_expected_uri_count = 1;
		break;
	case LTTNG_SESSION_DESCRIPTOR_OUTPUT_TYPE_NETWORK:
		max_expected_uri_count = 2;
		break;
	default:
		ret = -1;
		goto end;
	}
	/* output_type has been validated. */
	output_type = base_header->output_type;

	/* Skip after header. */
	offset += current_view.size;
	if (!base_header->name_len) {
		goto skip_name;
	}

	/* Map the name. */
	current_view = lttng_buffer_view_from_view(payload, offset,
			base_header->name_len);
	name = current_view.data;
	if (!name) {
		ret = -1;
		goto end;
	}

	if (base_header->name_len == 1 ||
			name[base_header->name_len - 1] ||
			strlen(name) != base_header->name_len - 1) {
		/*
		 * Check that the name is not NULL, is NULL-terminated, and
		 * does not contain a NULL before the last byte.
		 */
		ret = -1;
		goto end;
	}

	/* Skip after the name. */
	offset += base_header->name_len;
skip_name:
	if (base_header->uri_count > max_expected_uri_count) {
		ret = -1;
		goto end;
	}

	for (i = 0; i < base_header->uri_count; i++) {
		struct lttng_uri *uri;

		/* Map a URI. */
		current_view = lttng_buffer_view_from_view(payload,
				offset, sizeof(*uri));
		uri = (typeof(uri)) current_view.data;
		if (!uri) {
			ret = -1;
			goto end;
		}
		uris[i] = zmalloc(sizeof(*uri));
		if (!uris[i]) {
			ret = -1;
			goto end;
		}
		memcpy(uris[i], uri, sizeof(*uri));
		offset += sizeof(*uri);
	}

	switch (type) {
	case LTTNG_SESSION_DESCRIPTOR_TYPE_REGULAR:
		switch (output_type) {
		case LTTNG_SESSION_DESCRIPTOR_OUTPUT_TYPE_NONE:
			*descriptor = lttng_session_descriptor_create(name);
			break;
		case LTTNG_SESSION_DESCRIPTOR_OUTPUT_TYPE_LOCAL:
			*descriptor = _lttng_session_descriptor_local_create(
					name, uris[0]);
			break;
		case LTTNG_SESSION_DESCRIPTOR_OUTPUT_TYPE_NETWORK:
			*descriptor = _lttng_session_descriptor_network_create(
					name, uris[0], uris[1]);
			break;
		default:
			/* Already checked. */
			abort();
		}
		break;
	case LTTNG_SESSION_DESCRIPTOR_TYPE_SNAPSHOT:
	{
		struct lttng_session_descriptor_snapshot *snapshot;
		switch (output_type) {
		case LTTNG_SESSION_DESCRIPTOR_OUTPUT_TYPE_NONE:
			snapshot = _lttng_session_descriptor_snapshot_create(
					name);
			break;
		case LTTNG_SESSION_DESCRIPTOR_OUTPUT_TYPE_LOCAL:
			snapshot = _lttng_session_descriptor_snapshot_local_create(
					name, uris[0]);
			break;
		case LTTNG_SESSION_DESCRIPTOR_OUTPUT_TYPE_NETWORK:
			snapshot = _lttng_session_descriptor_snapshot_network_create(
					name, uris[0], uris[1]);
			break;
		default:
			/* Already checked. */
			abort();
		}
		*descriptor = snapshot ? &snapshot->base : NULL;
		break;
	}
	case LTTNG_SESSION_DESCRIPTOR_TYPE_LIVE:
	{
		struct lttng_session_descriptor_live *live;

		switch (output_type) {
		case LTTNG_SESSION_DESCRIPTOR_OUTPUT_TYPE_NONE:
			live = _lttng_session_descriptor_live_create(
					name, live_timer_us);
			break;
		case LTTNG_SESSION_DESCRIPTOR_OUTPUT_TYPE_NETWORK:
			live = _lttng_session_descriptor_live_network_create(
					name, uris[0], uris[1],
					live_timer_us);
			break;
		case LTTNG_SESSION_DESCRIPTOR_OUTPUT_TYPE_LOCAL:
			ret = -1;
			goto end;
		default:
			/* Already checked. */
			abort();
		}
		*descriptor = live ? &live->base : NULL;
		break;
	}
	default:
		/* Already checked. */
		abort();
	}
	memset(uris, 0, sizeof(uris));
	if (!*descriptor) {
		ret = -1;
		goto end;
	}

	ret = offset;
end:
	free(uris[0]);
	free(uris[1]);
	return ret;
}

LTTNG_HIDDEN
int lttng_session_descriptor_serialize(
		const struct lttng_session_descriptor *descriptor,
		struct lttng_dynamic_buffer *buffer)
{
	int ret, i;
	/* There are, at most, two URIs to serialize. */
	struct lttng_uri *uris[2] = {};
	size_t uri_count = 0;
	/* The live header is a superset of all headers. */
	struct lttng_session_descriptor_live_comm header = {
		.base.type = (uint8_t) descriptor->type,
		.base.output_type = (uint8_t) descriptor->output_type,
		.base.name_len = descriptor->name ?
				strlen(descriptor->name) + 1 : 0,
	};
	const void *header_ptr = NULL;
	size_t header_size;

	switch (descriptor->output_type) {
	case LTTNG_SESSION_DESCRIPTOR_OUTPUT_TYPE_NONE:
		break;
	case LTTNG_SESSION_DESCRIPTOR_OUTPUT_TYPE_LOCAL:
		uris[0] = descriptor->output.local;
		break;
	case LTTNG_SESSION_DESCRIPTOR_OUTPUT_TYPE_NETWORK:
		uris[0] = descriptor->output.network.control;
		uris[1] = descriptor->output.network.data;
		break;
	default:
		ret = -1;
		goto end;
	}
	uri_count += !!uris[0];
	uri_count += !!uris[1];

	header.base.uri_count = uri_count;
	if (descriptor->type == LTTNG_SESSION_DESCRIPTOR_TYPE_LIVE) {
		const struct lttng_session_descriptor_live *live =
				container_of(descriptor, typeof(*live),
				base);

		header.live_timer_us = live->live_timer_us;
		header_ptr = &header;
		header_size = sizeof(header);
	} else {
		header_ptr = &header.base;
		header_size = sizeof(header.base);
	}

	ret = lttng_dynamic_buffer_append(buffer, header_ptr, header_size);
	if (ret) {
		goto end;
	}
	if (header.base.name_len) {
		ret = lttng_dynamic_buffer_append(buffer, descriptor->name,
				header.base.name_len);
		if (ret) {
			goto end;
		}
	}

	for (i = 0; i < uri_count; i++) {
		ret = lttng_dynamic_buffer_append(buffer, uris[i],
				sizeof(struct lttng_uri));
		if (ret) {
			goto end;
		}
	}
end:
	return ret;
}

LTTNG_HIDDEN
enum lttng_session_descriptor_type
lttng_session_descriptor_get_type(
		const struct lttng_session_descriptor *descriptor)
{
	return descriptor->type;
}

LTTNG_HIDDEN
enum lttng_session_descriptor_output_type
lttng_session_descriptor_get_output_type(
		const struct lttng_session_descriptor *descriptor)
{
	return descriptor->output_type;
}

LTTNG_HIDDEN
void lttng_session_descriptor_get_local_output_uri(
		const struct lttng_session_descriptor *descriptor,
		struct lttng_uri *local_uri)
{
	memcpy(local_uri, descriptor->output.local, sizeof(*local_uri));
}

LTTNG_HIDDEN
void lttng_session_descriptor_get_network_output_uris(
		const struct lttng_session_descriptor *descriptor,
		struct lttng_uri *control,
		struct lttng_uri *data)
{
	memcpy(control, descriptor->output.network.control, sizeof(*control));
	memcpy(data, descriptor->output.network.data, sizeof(*data));
}

LTTNG_HIDDEN
unsigned long long
lttng_session_descriptor_live_get_timer_interval(
		const struct lttng_session_descriptor *descriptor)
{
	struct lttng_session_descriptor_live *live;

	live = container_of(descriptor, typeof(*live), base);
	return live->live_timer_us;
}

enum lttng_session_descriptor_status
lttng_session_descriptor_get_session_name(
		const struct lttng_session_descriptor *descriptor,
		const char **session_name)
{
	enum lttng_session_descriptor_status status;

	if (!descriptor || !session_name) {
		status = LTTNG_SESSION_DESCRIPTOR_STATUS_INVALID;
		goto end;
	}

	*session_name = descriptor->name;
	status = descriptor->name ?
			LTTNG_SESSION_DESCRIPTOR_STATUS_OK :
			LTTNG_SESSION_DESCRIPTOR_STATUS_UNSET;
end:
	return status;
}

LTTNG_HIDDEN
int lttng_session_descriptor_set_session_name(
		struct lttng_session_descriptor *descriptor,
		const char *name)
{
	int ret = 0;
	char *new_name;

	if (!name) {
		goto end;
	}
	if (strlen(name) >= LTTNG_NAME_MAX) {
		ret = -1;
		goto end;
	}
	new_name = strdup(name);
	if (!new_name) {
		ret = -1;
		goto end;
	}
	free(descriptor->name);
	descriptor->name = new_name;
end:
	return ret;
}

LTTNG_HIDDEN
bool lttng_session_descriptor_is_output_destination_initialized(
		const struct lttng_session_descriptor *descriptor)
{
	switch (descriptor->output_type) {
	case LTTNG_SESSION_DESCRIPTOR_OUTPUT_TYPE_NONE:
		return true;
	case LTTNG_SESSION_DESCRIPTOR_OUTPUT_TYPE_LOCAL:
		return descriptor->output.local;
	case LTTNG_SESSION_DESCRIPTOR_OUTPUT_TYPE_NETWORK:
		return descriptor->output.network.control;
	default:
		abort();
	}
}

LTTNG_HIDDEN
bool lttng_session_descriptor_has_output_directory(
		const struct lttng_session_descriptor *descriptor)
{
	switch (descriptor->output_type) {
	case LTTNG_SESSION_DESCRIPTOR_OUTPUT_TYPE_NONE:
		break;
	case LTTNG_SESSION_DESCRIPTOR_OUTPUT_TYPE_LOCAL:
		if (descriptor->output.local) {
			return *descriptor->output.local->dst.path;
		}
		break;
	case LTTNG_SESSION_DESCRIPTOR_OUTPUT_TYPE_NETWORK:
		if (descriptor->output.network.control) {
			return *descriptor->output.network.control->subdir;
		}
		break;
	default:
		abort();
	}
	return false;
}

LTTNG_HIDDEN
enum lttng_error_code lttng_session_descriptor_set_default_output(
		struct lttng_session_descriptor *descriptor,
		time_t *session_creation_time,
		const char *absolute_home_path)
{
	enum lttng_error_code ret_code = LTTNG_OK;
	struct lttng_uri *uris = NULL;

	switch (descriptor->output_type) {
	case LTTNG_SESSION_DESCRIPTOR_OUTPUT_TYPE_NONE:
		goto end;
	case LTTNG_SESSION_DESCRIPTOR_OUTPUT_TYPE_LOCAL:
	{
		int ret;
		ssize_t uri_ret;
		char local_uri[LTTNG_PATH_MAX];
		char creation_datetime_suffix[17] = {};

		if (session_creation_time) {
			size_t strftime_ret;
			struct tm *timeinfo;

			timeinfo = localtime(session_creation_time);
			if (!timeinfo) {
				ret_code = LTTNG_ERR_FATAL;
				goto end;
			}
			strftime_ret = strftime(creation_datetime_suffix,
					sizeof(creation_datetime_suffix),
				 	"-%Y%m%d-%H%M%S", timeinfo);
			if (strftime_ret == 0) {
				ERR("Failed to format session creation timestamp while setting default local output destination");
				ret_code = LTTNG_ERR_FATAL;
				goto end;
			}
		}
		assert(descriptor->name);
		ret = snprintf(local_uri, sizeof(local_uri),
				"file://%s/%s/%s%s",
				absolute_home_path,
				DEFAULT_TRACE_DIR_NAME, descriptor->name,
				creation_datetime_suffix);
		if (ret >= sizeof(local_uri)) {
			ERR("Truncation occurred while setting default local output destination");
			ret_code = LTTNG_ERR_SET_URL;
			goto end;
		} else if (ret < 0) {
			PERROR("Failed to format default local output URI");
			ret_code = LTTNG_ERR_SET_URL;
			goto end;
		}

		uri_ret = uri_parse(local_uri, &uris);
		if (uri_ret != 1) {
			ret_code = LTTNG_ERR_SET_URL;
			goto end;
		}
		free(descriptor->output.local);
		descriptor->output.local = &uris[0];
		uris = NULL;
		break;
	}
	case LTTNG_SESSION_DESCRIPTOR_OUTPUT_TYPE_NETWORK:
	{
		int ret;
		ssize_t uri_ret;
		struct lttng_uri *control = NULL, *data = NULL;

		uri_ret = uri_parse_str_urls("net://127.0.0.1", NULL, &uris);
		if (uri_ret != 2) {
			ret_code = LTTNG_ERR_SET_URL;
			goto end;
		}

		control = uri_copy(&uris[0]);
		data = uri_copy(&uris[1]);
		if (!control || !data) {
			free(control);
			free(data);
			ret_code = LTTNG_ERR_SET_URL;
			goto end;
		}

		/* Ownership of uris is transferred. */
		ret = network_location_set_from_lttng_uris(
				&descriptor->output.network,
				control, data);
		if (ret) {
			abort();
			ret_code = LTTNG_ERR_SET_URL;
			goto end;
		}
		break;
	}
	default:
		abort();
	}
end:
	free(uris);
	return ret_code;
}

/*
 * Note that only properties that can be populated by the session daemon
 * (output destination and name) are assigned.
 */
LTTNG_HIDDEN
int lttng_session_descriptor_assign(
		struct lttng_session_descriptor *dst,
		const struct lttng_session_descriptor *src)
{
	int ret = 0;

	if (dst->type != src->type) {
		ret = -1;
		goto end;
	}
	if (dst->output_type != src->output_type) {
		ret = -1;
		goto end;
	}
	ret = lttng_session_descriptor_set_session_name(dst, src->name);
	if (ret) {
		goto end;
	}
	switch (dst->output_type) {
	case LTTNG_SESSION_DESCRIPTOR_OUTPUT_TYPE_LOCAL:
		free(dst->output.local);
		dst->output.local = uri_copy(src->output.local);
		if (!dst->output.local) {
			ret = -1;
			goto end;
		}
		break;
	case LTTNG_SESSION_DESCRIPTOR_OUTPUT_TYPE_NETWORK:
	{
		struct lttng_uri *control_copy = NULL, *data_copy = NULL;

		control_copy = uri_copy(dst->output.network.control);
		if (!control_copy && dst->output.network.control) {
			ret = -1;
			goto end;
		}
		data_copy = uri_copy(dst->output.network.data);
		if (!data_copy && dst->output.network.data) {
			free(control_copy);
			ret = -1;
			goto end;
		}
		ret = network_location_set_from_lttng_uris(&dst->output.network,
				control_copy, data_copy);
		break;
	}
	case LTTNG_SESSION_DESCRIPTOR_OUTPUT_TYPE_NONE:
		goto end;
	}
end:
	return ret;
}
