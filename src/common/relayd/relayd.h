/*
 * Copyright (C) 2012 - David Goulet <dgoulet@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _RELAYD_H
#define _RELAYD_H

#include <unistd.h>
#include <stdbool.h>

#include <common/sessiond-comm/relayd.h>
#include <common/sessiond-comm/sessiond-comm.h>
#include <common/trace-chunk.h>
#include <common/dynamic-array.h>

struct relayd_stream_rotation_position {
	uint64_t stream_id;
	/*
	 * Sequence number of the first packet belonging to the new
	 * "destination" trace chunk to which the stream is rotating.
	 *
	 * Ignored for metadata streams.
	 */
	uint64_t rotate_at_seq_num;
};

int relayd_connect(struct lttcomm_relayd_sock *sock);
int relayd_close(struct lttcomm_relayd_sock *sock);
int relayd_create_session(struct lttcomm_relayd_sock *rsock,
		uint64_t *relayd_session_id,
		const char *session_name, const char *hostname,
		int session_live_timer,
		unsigned int snapshot, uint64_t sessiond_session_id,
		const lttng_uuid sessiond_uuid,
		const uint64_t *current_chunk_id,
		time_t creation_time);
int relayd_add_stream(struct lttcomm_relayd_sock *sock, const char *channel_name,
		const char *pathname, uint64_t *stream_id,
		uint64_t tracefile_size, uint64_t tracefile_count,
		struct lttng_trace_chunk *trace_chunk);
int relayd_streams_sent(struct lttcomm_relayd_sock *rsock);
int relayd_send_close_stream(struct lttcomm_relayd_sock *sock, uint64_t stream_id,
		uint64_t last_net_seq_num);
int relayd_version_check(struct lttcomm_relayd_sock *sock);
int relayd_start_data(struct lttcomm_relayd_sock *sock);
int relayd_send_metadata(struct lttcomm_relayd_sock *sock, size_t len);
int relayd_send_data_hdr(struct lttcomm_relayd_sock *sock,
		struct lttcomm_relayd_data_hdr *hdr, size_t size);
int relayd_data_pending(struct lttcomm_relayd_sock *sock, uint64_t stream_id,
		uint64_t last_net_seq_num);
int relayd_quiescent_control(struct lttcomm_relayd_sock *sock,
		uint64_t metadata_stream_id);
int relayd_begin_data_pending(struct lttcomm_relayd_sock *sock, uint64_t id);
int relayd_end_data_pending(struct lttcomm_relayd_sock *sock, uint64_t id,
		unsigned int *is_data_inflight);
int relayd_send_index(struct lttcomm_relayd_sock *rsock,
		struct ctf_packet_index *index, uint64_t relay_stream_id,
		uint64_t net_seq_num);
int relayd_reset_metadata(struct lttcomm_relayd_sock *rsock,
		uint64_t stream_id, uint64_t version);
/* `positions` is an array of `stream_count` relayd_stream_rotation_position. */
int relayd_rotate_streams(struct lttcomm_relayd_sock *sock,
		unsigned int stream_count, uint64_t *new_chunk_id,
		const struct relayd_stream_rotation_position *positions);
int relayd_create_trace_chunk(struct lttcomm_relayd_sock *sock,
		struct lttng_trace_chunk *chunk);
int relayd_close_trace_chunk(struct lttcomm_relayd_sock *sock,
		struct lttng_trace_chunk *chunk);
int relayd_trace_chunk_exists(struct lttcomm_relayd_sock *sock,
		uint64_t chunk_id, bool *chunk_exists);

#endif /* _RELAYD_H */
