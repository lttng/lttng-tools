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

#include <common/sessiond-comm/relayd.h>
#include <common/sessiond-comm/sessiond-comm.h>

int relayd_connect(struct lttcomm_relayd_sock *sock);
int relayd_close(struct lttcomm_relayd_sock *sock);
int relayd_create_session(struct lttcomm_relayd_sock *sock, uint64_t *session_id,
		char *session_name, char *hostname, int session_live_timer,
		unsigned int snapshot);
int relayd_add_stream(struct lttcomm_relayd_sock *sock, const char *channel_name,
		const char *pathname, uint64_t *stream_id,
		uint64_t tracefile_size, uint64_t tracefile_count);
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

#endif /* _RELAYD_H */
