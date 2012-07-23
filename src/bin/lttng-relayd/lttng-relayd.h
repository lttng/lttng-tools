/*
 * Copyright (C) 2012 - Julien Desfossez <jdesfossez@efficios.com>
 *                      David Goulet <dgoulet@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef LTTNG_RELAYD_H
#define LTTNG_RELAYD_H

#define _LGPL_SOURCE
#include <urcu.h>
#include <urcu/wfqueue.h>

/*
 * Queue used to enqueue relay requests
 */
struct relay_cmd_queue {
	struct cds_wfq_queue queue;
	int32_t futex;
};

enum connection_type {
	RELAY_DATA,
	RELAY_CONTROL,
};

/*
 * Represents a session for the relay point of view
 */
struct relay_session {
	uint64_t id;
	struct lttcomm_sock *sock;
	unsigned int version_check_done:1;
};

/*
 * Represents a stream in the relay
 */
struct relay_stream {
	uint64_t stream_handle;
	uint64_t seq;
	struct lttng_ht_node_ulong stream_n;
	struct relay_session *session;
	int fd;
};

/*
 * Internal structure to map a socket with the corresponding session.
 * A hashtable indexed on the socket FD is used for the lookups.
 */
struct relay_command {
	struct lttcomm_sock *sock;
	struct relay_session *session;
	struct cds_wfq_node node;
	struct lttng_ht_node_ulong sock_n;
	enum connection_type type;
};

#endif /* LTTNG_RELAYD_H */
