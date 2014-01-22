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

#ifndef _STREAM_H
#define _STREAM_H

#include <limits.h>
#include <inttypes.h>
#include <pthread.h>
#include <urcu/list.h>

#include <common/hashtable/hashtable.h>

#include "session.h"

/*
 * Represents a stream in the relay
 */
struct relay_stream {
	uint64_t stream_handle;
	uint64_t prev_seq;	/* previous data sequence number encountered */
	struct lttng_ht_node_u64 node;
	/*
	 * When we receive a stream, it gets stored in a list (on a per connection
	 * basis) until we have all the streams of the same channel and the metadata
	 * associated with it, then it gets flagged with viewer_ready.
	 */
	struct cds_list_head recv_list;

	/* Added to the corresponding ctf_trace. */
	struct cds_list_head trace_list;
	struct rcu_head rcu_node;
	uint64_t session_id;
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
	uint64_t last_net_seq_num;

	/*
	 * To protect from concurrent read/update. Also used to synchronize the
	 * closing of this stream.
	 */
	pthread_mutex_t lock;

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
	/*
	 * Indicates if the stream has been effectively closed thus having the
	 * information in it invalidated but NOT freed. The stream lock MUST be
	 * held to read/update that value.
	 */
	unsigned int terminated_flag:1;
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

struct relay_stream *stream_find_by_id(struct lttng_ht *ht,
		uint64_t stream_id);
int stream_close(struct relay_session *session, struct relay_stream *stream);
void stream_delete(struct lttng_ht *ht, struct relay_stream *stream);
void stream_destroy(struct relay_stream *stream);

#endif /* _STREAM_H */
