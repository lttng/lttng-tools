/*
 * Copyright (C) 2013 - Julien Desfossez <jdesfossez@efficios.com>
 *                      David Goulet <dgoulet@efficios.com>
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

#define _GNU_SOURCE
#include <assert.h>
#include <string.h>

#include <common/common.h>
#include <common/sessiond-comm/relayd.h>

#include "cmd-generic.h"
#include "lttng-relayd.h"

int cmd_create_session_2_4(struct relay_command *cmd,
		struct relay_session *session)
{
	int ret;
	struct lttcomm_relayd_create_session_2_4 session_info;

	assert(cmd);
	assert(session);

	ret = cmd_recv(cmd->sock, &session_info, sizeof(session_info));
	if (ret < 0) {
		ERR("Unable to recv session info version 2.4");
		goto error;
	}

	strncpy(session->session_name, session_info.session_name,
			sizeof(session->session_name));
	strncpy(session->hostname, session_info.hostname,
			sizeof(session->hostname));
	session->live_timer = be32toh(session_info.live_timer);
	session->snapshot = be32toh(session_info.snapshot);

	ret = 0;

error:
	return ret;
}
