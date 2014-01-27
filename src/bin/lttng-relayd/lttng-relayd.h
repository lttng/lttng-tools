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
#include <limits.h>
#include <urcu.h>
#include <urcu/wfqueue.h>
#include <urcu/list.h>

#include <common/hashtable/hashtable.h>
#include <common/index/ctf-index.h>

#include "ctf-trace.h"

/*
 * Queue used to enqueue relay requests
 */
struct relay_cmd_queue {
	struct cds_wfq_queue queue;
	int32_t futex;
};

enum connection_type {
	RELAY_DATA                  = 1,
	RELAY_CONTROL               = 2,
	RELAY_VIEWER_COMMAND        = 3,
	RELAY_VIEWER_NOTIFICATION   = 4,
};

/*
 * When we receive a stream, it gets stored in a list (on a per connection
 * basis) until we have all the streams of the same channel and the metadata
 * associated with it, then it gets flagged with viewer_ready.
 */
struct relay_stream_recv_handle {
	uint64_t id;	/* stream handle */
	struct cds_list_head node;
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
	char session_name[NAME_MAX];
	char hostname[HOST_NAME_MAX];
	uint32_t live_timer;
	struct lttng_ht_node_ulong session_n;
	struct rcu_head rcu_node;
	uint32_t viewer_attached;
	uint32_t stream_count;
	/* Tell if this session is for a snapshot or not. */
	unsigned int snapshot:1;

	/*
	 * Indicate version protocol for this session. This is especially useful
	 * for the data thread that has no idea which version it operates on since
	 * linking control/data sockets is non trivial.
	 */
	uint64_t minor;
	uint64_t major;
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
	/* FD on which to read the index data for the viewer. */
	int read_index_fd;

	char *path_name;
	char *channel_name;
	/* on-disk circular buffer of tracefiles */
	uint64_t tracefile_size;
	uint64_t tracefile_size_current;
	uint64_t tracefile_count;
	uint64_t tracefile_count_current;
	/* To inform the viewer up to where it can go back in time. */
	uint64_t oldest_tracefile_id;

	uint64_t total_index_received;
	struct relay_viewer_stream *viewer_stream;
	uint64_t last_net_seq_num;

	/*
	 * This node is added to the *control* connection hash table and the
	 * pointer is copied in here so we can access it when deleting this object.
	 * When deleting this, the ctf trace ht MUST NOT be destroyed. This happens
	 * at connection deletion.
	 */
	struct lttng_ht_node_str ctf_trace_node;
	struct lttng_ht *ctf_traces_ht;

	/*
	 * To protect from concurrent read/update between the
	 * streaming-side and the viewer-side.
	 * This lock must be held, we reading/updating the
	 * ctf_trace pointer.
	 */
	pthread_mutex_t lock;

	struct ctf_trace *ctf_trace;
	/*
	 * If the stream is inactive, this field is updated with the live beacon
	 * timestamp end, when it is active, this field == -1ULL.
	 */
	uint64_t beacon_ts_end;
	/*
	 * To protect the update of the close_write_flag and the checks of
	 * the tracefile_count_current.
	 * It is taken before checking whenever we need to know if the
	 * writer and reader are working in the same tracefile.
	 */
	pthread_mutex_t viewer_stream_rotation_lock;

	/* Information telling us when to close the stream  */
	unsigned int close_flag:1;
	/* Indicate if the stream was initialized for a data pending command. */
	unsigned int data_pending_check_done:1;
	unsigned int metadata_flag:1;
	/*
	 * To detect when we start overwriting old data, it is used to
	 * update the oldest_tracefile_id.
	 */
	unsigned int tracefile_overwrite:1;
	/*
	 * Can this stream be used by a viewer or are we waiting for additional
	 * information.
	 */
	unsigned int viewer_ready:1;
};

/*
 * Shadow copy of the relay_stream structure for the viewer side.  The only
 * fields updated by the writer (streaming side) after allocation are :
 * total_index_received and close_flag. Everything else is updated by the
 * reader (viewer side).
 */
struct relay_viewer_stream {
	uint64_t stream_handle;
	uint64_t session_id;
	int read_fd;
	int index_read_fd;
	char *path_name;
	char *channel_name;
	uint64_t last_sent_index;
	uint64_t total_index_received;
	uint64_t tracefile_count;
	uint64_t tracefile_count_current;
	/* Stop after reading this tracefile. */
	uint64_t tracefile_count_last;
	struct lttng_ht_node_u64 stream_n;
	struct rcu_head rcu_node;
	struct ctf_trace *ctf_trace;
	/*
	 * This lock blocks only when the writer is about to start overwriting
	 * a file currently read by the reader.
	 *
	 * This is nested INSIDE the viewer_stream_rotation_lock.
	 */
	pthread_mutex_t overwrite_lock;
	/* Information telling us if the stream is a metadata stream. */
	unsigned int metadata_flag:1;
	/*
	 * Information telling us that the stream is closed in write, so
	 * we don't expect new indexes and we can read up to EOF.
	 */
	unsigned int close_write_flag:1;
	/*
	 * If the streaming side closes a FD in use in the viewer side,
	 * it sets this flag to inform that it is a normal error.
	 */
	unsigned int abort_flag:1;
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
	/* protocol version to use for this session */
	uint32_t major;
	uint32_t minor;
	struct lttng_ht *ctf_traces_ht;	/* indexed by path name */
	uint64_t session_id;
	struct cds_list_head recv_head;
	unsigned int version_check_done:1;
};

struct relay_local_data {
	struct lttng_ht *sessions_ht;
};

extern char *opt_output_path;

extern struct lttng_ht *relay_streams_ht;
extern struct lttng_ht *viewer_streams_ht;
extern struct lttng_ht *indexes_ht;

extern const char *tracing_group_name;

extern const char * const config_section_name;

struct relay_stream *relay_stream_find_by_id(uint64_t stream_id);
void lttng_relay_notify_ready(void);

#endif /* LTTNG_RELAYD_H */
