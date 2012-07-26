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

int relayd_connect(struct lttcomm_sock *sock);
int relayd_close(struct lttcomm_sock *sock);
#if 0
int relayd_create_session(struct lttcomm_sock *sock, const char *hostname,
		const char *session_name);
#endif
int relayd_add_stream(struct lttcomm_sock *sock, const char *channel_name,
		const char *pathname, uint64_t *stream_id);
int relayd_send_close_stream(struct lttcomm_sock *sock, uint64_t stream_id,
		uint64_t last_net_seq_num);
int relayd_version_check(struct lttcomm_sock *sock, uint32_t major,
		uint32_t minor);
int relayd_start_data(struct lttcomm_sock *sock);
int relayd_send_metadata(struct lttcomm_sock *sock, size_t len);
int relayd_send_data_hdr(struct lttcomm_sock *sock,
		struct lttcomm_relayd_data_hdr *hdr, size_t size);

#endif /* _RELAYD_H */
