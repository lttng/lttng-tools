/*
 * Copyright (C) 2018 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include <inttypes.h>

#include <common/common.hpp>
#include <common/sessiond-comm/relayd.hpp>

#include <common/compat/endian.hpp>
#include <common/compat/string.hpp>
#include <lttng/constant.h>

#include "cmd-2-11.hpp"
#include "utils.hpp"

int cmd_create_session_2_11(const struct lttng_buffer_view *payload,
		char *session_name, char *hostname, char *base_path,
		uint32_t *live_timer, bool *snapshot,
		uint64_t *id_sessiond,
		lttng_uuid& sessiond_uuid,
		bool *has_current_chunk, uint64_t *current_chunk_id,
		time_t *creation_time,
		bool *session_name_contains_creation_time)
{
	int ret;
	struct lttcomm_relayd_create_session_2_11 header;
	size_t header_len, received_names_size, offset;
	struct lttng_buffer_view session_name_view;
	struct lttng_buffer_view hostname_view;
	struct lttng_buffer_view base_path_view;

	header_len = sizeof(header);

	if (payload->size < header_len) {
		ERR("Unexpected payload size in \"cmd_create_session_2_11\": expected >= %zu bytes, got %zu bytes",
				header_len, payload->size);
		ret = -1;
		goto error;
	}
	memcpy(&header, payload->data, header_len);

	header.session_name_len = be32toh(header.session_name_len);
	header.hostname_len = be32toh(header.hostname_len);
	header.base_path_len = be32toh(header.base_path_len);
	header.live_timer = be32toh(header.live_timer);
	header.current_chunk_id.value = be64toh(header.current_chunk_id.value);
	header.current_chunk_id.is_set = !!header.current_chunk_id.is_set;
	header.creation_time = be64toh(header.creation_time);
	header.session_id = be64toh(header.session_id);

	std::copy(std::begin(header.sessiond_uuid), std::end(header.sessiond_uuid), sessiond_uuid.begin());

	received_names_size = header.session_name_len + header.hostname_len +
				header.base_path_len;
	if (payload->size < header_len + received_names_size) {
		ERR("Unexpected payload size in \"cmd_create_session_2_11\": expected >= %zu bytes, got %zu bytes",
				header_len + received_names_size, payload->size);
		ret = -1;
		goto error;
	}

	/* Validate length against defined constant. */
	if (header.session_name_len > LTTNG_NAME_MAX) {
		ret = -ENAMETOOLONG;
		ERR("Length of session name (%" PRIu32 " bytes) received in create_session command exceeds maximum length (%d bytes)", header.session_name_len, LTTNG_NAME_MAX);
		goto error;
	} else if (header.session_name_len == 0) {
		ret = -EINVAL;
		ERR("Illegal session name length of 0 received");
		goto error;
	}
	if (header.hostname_len > LTTNG_HOST_NAME_MAX) {
		ret = -ENAMETOOLONG;
		ERR("Length of hostname (%" PRIu32 " bytes) received in create_session command exceeds maximum length (%d bytes)", header.hostname_len, LTTNG_HOST_NAME_MAX);
		goto error;
	}
	if (header.base_path_len > LTTNG_PATH_MAX) {
		ret = -ENAMETOOLONG;
		ERR("Length of base_path (%" PRIu32 " bytes) received in create_session command exceeds maximum length (%d bytes)", header.base_path_len, PATH_MAX);
		goto error;
	}

	offset = header_len;
	session_name_view = lttng_buffer_view_from_view(payload, offset,
			header.session_name_len);
	if (!lttng_buffer_view_is_valid(&session_name_view)) {
		ERR("Invalid payload in \"cmd_create_session_2_11\": buffer too short to contain session name");
		ret = -1;
		goto error;
	}

	offset += header.session_name_len;
	hostname_view = lttng_buffer_view_from_view(payload,
			offset, header.hostname_len);
	if (!lttng_buffer_view_is_valid(&hostname_view)) {
		ERR("Invalid payload in \"cmd_create_session_2_11\": buffer too short to contain hostname");
		ret = -1;
		goto error;
	}

	offset += header.hostname_len;
	base_path_view = lttng_buffer_view_from_view(payload,
			offset, header.base_path_len);
	if (header.base_path_len > 0 && !lttng_buffer_view_is_valid(&base_path_view)) {
		ERR("Invalid payload in \"cmd_create_session_2_11\": buffer too short to contain base path");
		ret = -1;
		goto error;
	}

	/* Validate that names are NULL terminated. */
	if (session_name_view.data[session_name_view.size - 1] != '\0') {
		ERR("cmd_create_session_2_11 session_name is invalid (not NULL terminated)");
		ret = -1;
		goto error;
	}

	if (hostname_view.data[hostname_view.size - 1] != '\0') {
		ERR("cmd_create_session_2_11 hostname is invalid (not NULL terminated)");
		ret = -1;
		goto error;
	}

	if (base_path_view.size != 0 &&
			base_path_view.data[base_path_view.size - 1] != '\0') {
		ERR("cmd_create_session_2_11 base_path is invalid (not NULL terminated)");
		ret = -1;
		goto error;
	}

	/*
	 * Length and null-termination check are already performed.
	 * LTTNG_NAME_MAX, LTTNG_HOST_NAME_MAX, and LTTNG_PATH_MAX max sizes are expected.
	 */
	strcpy(session_name, session_name_view.data);
	strcpy(hostname, hostname_view.data);
	strcpy(base_path, base_path_view.size ? base_path_view.data : "");

	*live_timer = header.live_timer;
	*snapshot = !!header.snapshot;
	*current_chunk_id = header.current_chunk_id.value;
	*has_current_chunk = header.current_chunk_id.is_set;
	*creation_time = (time_t) header.creation_time;
	*session_name_contains_creation_time =
		header.session_name_contains_creation_time;
	*id_sessiond = header.session_id;

	ret = 0;

error:
	return ret;
}

/*
 * cmd_recv_stream_2_11 allocates path_name and channel_name.
 */
int cmd_recv_stream_2_11(const struct lttng_buffer_view *payload,
		char **ret_path_name, char **ret_channel_name,
		uint64_t *tracefile_size, uint64_t *tracefile_count,
		uint64_t *trace_archive_id)
{
	int ret;
	struct lttcomm_relayd_add_stream_2_11 header;
	size_t header_len, received_names_size;
	struct lttng_buffer_view channel_name_view;
	struct lttng_buffer_view pathname_view;
	char *path_name = NULL;
	char *channel_name = NULL;

	header_len = sizeof(header);

	if (payload->size < header_len) {
		ERR("Unexpected payload size in \"cmd_recv_stream_2_11\": expected >= %zu bytes, got %zu bytes",
				header_len, payload->size);
		ret = -1;
		goto error;
	}
	memcpy(&header, payload->data, header_len);

	header.channel_name_len = be32toh(header.channel_name_len);
	header.pathname_len = be32toh(header.pathname_len);
	header.tracefile_size = be64toh(header.tracefile_size);
	header.tracefile_count = be64toh(header.tracefile_count);
	header.trace_chunk_id = be64toh(header.trace_chunk_id);

	received_names_size = header.channel_name_len + header.pathname_len;
	if (payload->size < header_len + received_names_size) {
		ERR("Unexpected payload size in \"cmd_recv_stream_2_11\": expected >= %zu bytes, got %zu bytes",
				header_len + received_names_size, payload->size);
		ret = -1;
		goto error;
	}

	/* Validate length against defined constant. */
	if (header.channel_name_len > DEFAULT_STREAM_NAME_LEN) {
		ret = -ENAMETOOLONG;
		ERR("Channel name too long");
		goto error;
	}
	if (header.pathname_len > LTTNG_NAME_MAX) {
		ret = -ENAMETOOLONG;
		ERR("Pathname too long");
		goto error;
	}

	/* Validate that names are (NULL terminated. */
	channel_name_view = lttng_buffer_view_from_view(payload, header_len,
			header.channel_name_len);
	if (!lttng_buffer_view_is_valid(&channel_name_view)) {
		ERR("Invalid payload received in \"cmd_recv_stream_2_11\": buffer too short for channel name");
		ret = -1;
		goto error;
	}

	if (channel_name_view.data[channel_name_view.size - 1] != '\0') {
		ERR("cmd_recv_stream_2_11 channel_name is invalid (not NULL terminated)");
		ret = -1;
		goto error;
	}

	pathname_view = lttng_buffer_view_from_view(payload,
			header_len + header.channel_name_len, header.pathname_len);
	if (!lttng_buffer_view_is_valid(&pathname_view)) {
		ERR("Invalid payload received in \"cmd_recv_stream_2_11\": buffer too short for path name");
		ret = -1;
		goto error;
	}

	if (pathname_view.data[pathname_view.size - 1] != '\0') {
		ERR("cmd_recv_stream_2_11 patname is invalid (not NULL terminated)");
		ret = -1;
		goto error;
	}

	channel_name = strdup(channel_name_view.data);
	if (!channel_name) {
		ret = -errno;
		PERROR("Channel name allocation");
		goto error;
	}

	path_name = strdup(pathname_view.data);
	if (!path_name) {
		PERROR("Path name allocation");
		ret = -ENOMEM;
		goto error;
	}

	*tracefile_size = header.tracefile_size;
	*tracefile_count = header.tracefile_count;
	*trace_archive_id = header.trace_chunk_id;
	*ret_path_name = path_name;
	*ret_channel_name = channel_name;
	/* Move ownership to caller */
	path_name = NULL;
	channel_name = NULL;
	ret = 0;
error:
	free(channel_name);
	free(path_name);
	return ret;
}
