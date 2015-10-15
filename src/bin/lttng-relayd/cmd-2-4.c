/*
 * Copyright (C) 2013 - Julien Desfossez <jdesfossez@efficios.com>
 *                      David Goulet <dgoulet@efficios.com>
 *               2015 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

#include <common/common.h>
#include <common/sessiond-comm/relayd.h>

#include <common/compat/endian.h>
#include <common/compat/string.h>
#include <lttng/constant.h>

#include "cmd-generic.h"
#include "lttng-relayd.h"

int cmd_create_session_2_4(struct relay_connection *conn,
		char *session_name, char *hostname,
		uint32_t *live_timer, bool *snapshot)
{
	int ret;
	struct lttcomm_relayd_create_session_2_4 session_info;
	size_t len;

	ret = cmd_recv(conn->sock, &session_info, sizeof(session_info));
	if (ret < 0) {
		ERR("Unable to recv session info version 2.4");
		goto error;
	}
	len = lttng_strnlen(session_info.session_name, sizeof(session_info.session_name));
	/* Ensure that NULL-terminated and fits in local filename length. */
	if (len == sizeof(session_info.session_name) || len >= LTTNG_NAME_MAX) {
		ret = -ENAMETOOLONG;
		ERR("Session name too long");
		goto error;
	}
	strncpy(session_name, session_info.session_name,
			sizeof(session_info.session_name));

	len = lttng_strnlen(session_info.hostname, sizeof(session_info.hostname));
	if (len == sizeof(session_info.hostname) || len >= LTTNG_HOST_NAME_MAX) {
		ret = -ENAMETOOLONG;
		ERR("Session name too long");
		goto error;
	}
	strncpy(hostname, session_info.hostname,
			sizeof(session_info.hostname));
	*live_timer = be32toh(session_info.live_timer);
	*snapshot = be32toh(session_info.snapshot);

	ret = 0;

error:
	return ret;
}
