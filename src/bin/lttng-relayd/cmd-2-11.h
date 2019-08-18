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
#ifndef RELAYD_CMD_2_11_H
#define RELAYD_CMD_2_11_H

#include "lttng-relayd.h"
#include <common/buffer-view.h>
#include <common/compat/uuid.h>

int cmd_create_session_2_11(const struct lttng_buffer_view *payload,
		char *session_name, char *hostname, char *base_path,
		uint32_t *live_timer, bool *snapshot,
		uint64_t *id_sessiond, lttng_uuid sessiond_uuid,
		bool *has_current_chunk, uint64_t *current_chunk_id,
		time_t *creation_time,
		bool *session_name_contains_creation_time);

int cmd_recv_stream_2_11(const struct lttng_buffer_view *payload,
		char **ret_path_name, char **ret_channel_name,
		uint64_t *tracefile_size, uint64_t *tracefile_count,
		uint64_t *trace_archive_id);

#endif /* RELAYD_CMD_2_11_H */
