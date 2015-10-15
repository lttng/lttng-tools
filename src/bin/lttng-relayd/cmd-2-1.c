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
#include <common/compat/string.h>
#include <lttng/constant.h>

#include "cmd-generic.h"
#include "cmd-2-1.h"
#include "utils.h"

/*
 * cmd_recv_stream_2_1 allocates path_name and channel_name.
 */
int cmd_recv_stream_2_1(struct relay_connection *conn,
		char **ret_path_name, char **ret_channel_name)
{
	int ret;
	struct lttcomm_relayd_add_stream stream_info;
	char *path_name = NULL;
	char *channel_name = NULL;
	size_t len;

	ret = cmd_recv(conn->sock, &stream_info, sizeof(stream_info));
	if (ret < 0) {
		ERR("Unable to recv stream version 2.1");
		goto error;
	}

	len = lttng_strnlen(stream_info.pathname, sizeof(stream_info.pathname));
	/* Ensure that NULL-terminated and fits in local filename length. */
	if (len == sizeof(stream_info.pathname) || len >= LTTNG_NAME_MAX) {
		ret = -ENAMETOOLONG;
		ERR("Path name too long");
		goto error;
	}
	path_name = create_output_path(stream_info.pathname);
	if (!path_name) {
		PERROR("Path name allocation");
		ret = -ENOMEM;
		goto error;
	}
	len = lttng_strnlen(stream_info.channel_name, sizeof(stream_info.channel_name));
	if (len == sizeof(stream_info.channel_name) || len >= DEFAULT_STREAM_NAME_LEN) {
		ret = -ENAMETOOLONG;
		ERR("Channel name too long");
		goto error;
	}
	channel_name = strdup(stream_info.channel_name);
	if (!channel_name) {
		ret = -errno;
		PERROR("Channel name allocation");
		goto error;
	}

	*ret_path_name = path_name;
	*ret_channel_name = channel_name;
	return 0;
error:
	free(path_name);
	free(channel_name);
	return ret;
}
