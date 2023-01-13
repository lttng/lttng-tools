/*
 * Copyright (C) 2013 Julien Desfossez <jdesfossez@efficios.com>
 * Copyright (C) 2013 David Goulet <dgoulet@efficios.com>
 * Copyright (C) 2015 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE

#include "cmd-2-4.hpp"
#include "lttng-relayd.hpp"

#include <common/common.hpp>
#include <common/compat/endian.hpp>
#include <common/compat/string.hpp>
#include <common/sessiond-comm/relayd.hpp>

#include <lttng/constant.h>

int cmd_create_session_2_4(const struct lttng_buffer_view *payload,
			   char *session_name,
			   char *hostname,
			   uint32_t *live_timer,
			   bool *snapshot)
{
	int ret;
	struct lttcomm_relayd_create_session_2_4 session_info;
	size_t len;

	if (payload->size < sizeof(session_info)) {
		ERR("Unexpected payload size in \"cmd_create_session_2_4\": expected >= %zu bytes, got %zu bytes",
		    sizeof(session_info),
		    payload->size);
		ret = -1;
		goto error;
	}
	memcpy(&session_info, payload->data, sizeof(session_info));

	len = lttng_strnlen(session_info.session_name, sizeof(session_info.session_name));
	/* Ensure that NULL-terminated and fits in local filename length. */
	if (len == sizeof(session_info.session_name) || len >= LTTNG_NAME_MAX) {
		ret = -ENAMETOOLONG;
		ERR("Session name too long");
		goto error;
	} else if (len == 0) {
		ret = -EINVAL;
		ERR("Session name can't be of length 0");
		goto error;
	}
	strncpy(session_name, session_info.session_name, LTTNG_NAME_MAX);

	len = lttng_strnlen(session_info.hostname, sizeof(session_info.hostname));
	if (len == sizeof(session_info.hostname) || len >= LTTNG_HOST_NAME_MAX) {
		ret = -ENAMETOOLONG;
		ERR("Session name too long");
		goto error;
	}
	strncpy(hostname, session_info.hostname, LTTNG_HOST_NAME_MAX);

	*live_timer = be32toh(session_info.live_timer);
	*snapshot = be32toh(session_info.snapshot);

	ret = 0;

error:
	return ret;
}
