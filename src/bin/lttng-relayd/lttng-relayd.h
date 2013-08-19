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
#include <common/hashtable/hashtable.h>
#include <common/index/lttng-index.h>

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
	/*
	 * This session id is used to identify a set of stream to a tracing session
	 * but also make sure we have a unique session id associated with a session
	 * daemon which can provide multiple data source.
	 */
	uint64_t id;
	struct lttcomm_sock *sock;
};

/*
 * Represents a stream in the relay
 */
struct relay_stream {
	uint64_t stream_handle;
	uint64_t prev_seq;	/* previous data sequence number encountered */
	struct lttng_ht_node_ulong stream_n;
	struct relay_session *session;
	struct rcu_head rcu_node;
	int fd;
	/* FD on which to write the index data. */
	int index_fd;

	char *path_name;
	char *channel_name;
	/* on-disk circular buffer of tracefiles */
	uint64_t tracefile_size;
	uint64_t tracefile_size_current;
	uint64_t tracefile_count;
	uint64_t tracefile_count_current;

	/* Information telling us when to close the stream  */
	unsigned int close_flag:1;
	uint64_t last_net_seq_num;
	/* Indicate if the stream was initialized for a data pending command. */
	unsigned int data_pending_check_done:1;
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
	struct rcu_head rcu_node;
	enum connection_type type;
	unsigned int version_check_done:1;
	/* protocol version to use for this session */
	uint32_t major;
	uint32_t minor;
};

extern char *opt_output_path;

#endif /* LTTNG_RELAYD_H */
