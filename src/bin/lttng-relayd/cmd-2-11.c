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
#include "lttng-relayd.h"

int cmd_create_session_2_11(const struct lttng_buffer_view *payload,
		char *session_name, char *hostname,
		uint32_t *live_timer, bool *snapshot)
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

	ret = 0;

error:
	return ret;
}
