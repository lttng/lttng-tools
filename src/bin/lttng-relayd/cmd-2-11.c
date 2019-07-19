/*
 * Copyright (C) 2018 - Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define _LGPL_SOURCE
#include <assert.h>
#include <inttypes.h>

#include <common/common.h>
#include <common/sessiond-comm/relayd.h>

#include <common/compat/endian.h>
#include <common/compat/string.h>
#include <lttng/constant.h>

#include "cmd-2-11.h"
#include "utils.h"

int cmd_create_session_2_11(const struct lttng_buffer_view *payload,
		char *session_name, char *hostname,
		uint32_t *live_timer, bool *snapshot,
		uint64_t *id_sessiond, lttng_uuid sessiond_uuid,
		bool *has_current_chunk, uint64_t *current_chunk_id,
		time_t *creation_time)
{
	int ret;
	struct lttcomm_relayd_create_session_2_11 header;
	size_t header_len, received_names_size;
	struct lttng_buffer_view session_name_view;
	struct lttng_buffer_view hostname_view;

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
	header.live_timer = be32toh(header.live_timer);
	header.current_chunk_id.value = be64toh(header.current_chunk_id.value);
	header.current_chunk_id.is_set = !!header.current_chunk_id.is_set;
	header.creation_time = be64toh(header.creation_time);

	lttng_uuid_copy(sessiond_uuid, header.sessiond_uuid);

	received_names_size = header.session_name_len + header.hostname_len;
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
	}
	if (header.hostname_len > LTTNG_HOST_NAME_MAX) {
		ret = -ENAMETOOLONG;
		ERR("Length of hostname (%" PRIu32 " bytes) received in create_session command exceeds maximum length (%d bytes)", header.hostname_len, LTTNG_HOST_NAME_MAX);
		goto error;
	}

	session_name_view = lttng_buffer_view_from_view(payload, header_len,
			header.session_name_len);
	hostname_view = lttng_buffer_view_from_view(payload,
			header_len + header.session_name_len, header.hostname_len);

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

	/*
	 * Length and null-termination check are already performed.
	 * LTTNG_NAME_MAX and LTTNG_HOST_NAME_MAX max size are expected.
	 */
	strcpy(session_name, session_name_view.data);
	strcpy(hostname, hostname_view.data);

	*live_timer = header.live_timer;
	*snapshot = !!header.snapshot;
	*current_chunk_id = header.current_chunk_id.value;
	*has_current_chunk = header.current_chunk_id.is_set;
	*creation_time = (time_t) header.creation_time;

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
	header.trace_archive_id = be64toh(header.trace_archive_id);

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
	pathname_view = lttng_buffer_view_from_view(payload,
			header_len + header.channel_name_len, header.pathname_len);

	if (channel_name_view.data[channel_name_view.size - 1] != '\0') {
		ERR("cmd_recv_stream_2_11 channel_name is invalid (not NULL terminated)");
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

	path_name = create_output_path(pathname_view.data);
	if (!path_name) {
		PERROR("Path name allocation");
		ret = -ENOMEM;
		goto error;
	}

	*tracefile_size = header.tracefile_size;
	*tracefile_count = header.tracefile_count;
	*trace_archive_id = header.trace_archive_id;
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
