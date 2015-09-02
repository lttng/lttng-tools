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

#define _GNU_SOURCE
#define _LGPL_SOURCE
#include <assert.h>
#include <string.h>

#include <common/common.h>
#include <common/sessiond-comm/relayd.h>

#include "cmd-generic.h"
#include "cmd-2-1.h"
#include "utils.h"

/*
 * cmd_recv_stream_2_1 allocates path_name and channel_name.
 */
int cmd_recv_stream_2_1(struct relay_connection *conn,
		char **path_name, char **channel_name)
{
	int ret;
	struct lttcomm_relayd_add_stream stream_info;

	ret = cmd_recv(conn->sock, &stream_info, sizeof(stream_info));
	if (ret < 0) {
		ERR("Unable to recv stream version 2.1");
		goto error;
	}

	*path_name = create_output_path(stream_info.pathname);
	if (*path_name == NULL) {
		PERROR("Path name allocation");
		ret = -ENOMEM;
		goto error;
	}

	*channel_name = strdup(stream_info.channel_name);
	if (*channel_name == NULL) {
		ret = -errno;
		PERROR("Path name allocation");
		goto error;
	}
	ret = 0;

error:
	return ret;
}
