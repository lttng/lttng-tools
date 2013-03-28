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
#include "cmd-2-1.h"
#include "utils.h"

int cmd_recv_stream_2_2(struct relay_command *cmd, struct relay_stream *stream)
{
	int ret;
	struct lttcomm_relayd_add_stream_2_2 stream_info;

	assert(cmd);
	assert(stream);

	ret = cmd_recv(cmd->sock, &stream_info, sizeof(stream_info));
	if (ret < 0) {
		ERR("Unable to recv stream version 2.2");
		goto error;
	}

	stream->path_name = create_output_path(stream_info.pathname);
	if (stream->path_name == NULL) {
		PERROR("Path name allocation");
		ret = -ENOMEM;
		goto error;
	}

	stream->channel_name = strdup(stream_info.channel_name);
	if (stream->channel_name == NULL) {
		ret = -errno;
		PERROR("Path name allocation");
		goto error;
	}

	stream->tracefile_size = be64toh(stream_info.tracefile_size);
	stream->tracefile_count = be64toh(stream_info.tracefile_count);
	ret = 0;

error:
	return ret;
}
