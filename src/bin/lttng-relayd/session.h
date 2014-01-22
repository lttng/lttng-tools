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

#ifndef _SESSION_H
#define _SESSION_H

#include <limits.h>
#include <inttypes.h>
#include <pthread.h>

#include <common/hashtable/hashtable.h>

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
	char session_name[NAME_MAX];
	char hostname[HOST_NAME_MAX];
	uint32_t live_timer;
	struct lttng_ht_node_u64 session_n;
	struct rcu_head rcu_node;
	uint32_t stream_count;
	/* Tell if this session is for a snapshot or not. */
	unsigned int snapshot:1;
	/* Tell if the session has been closed on the streaming side. */
	unsigned int close_flag:1;

	/* Number of viewer using it. Set to 0, it should be destroyed. */
	int viewer_refcount;

	/* Contains ctf_trace object of that session indexed by path name. */
	struct lttng_ht *ctf_traces_ht;

	/*
	 * Indicate version protocol for this session. This is especially useful
	 * for the data thread that has no idea which version it operates on since
	 * linking control/data sockets is non trivial.
	 */
	uint64_t minor;
	uint64_t major;
	/*
	 * Flag checked and exchanged with uatomic_cmpxchg to tell the
	 * viewer-side if new streams got added since the last check.
	 */
	unsigned long new_streams;

	/*
	 * Used to synchronize the process where we flag every streams readiness
	 * for the viewer when the streams_sent message is received and the viewer
	 * process of sending those streams.
	 */
	pthread_mutex_t viewer_ready_lock;
};

static inline void session_viewer_attach(struct relay_session *session)
{
	uatomic_inc(&session->viewer_refcount);
}

static inline void session_viewer_detach(struct relay_session *session)
{
	uatomic_add(&session->viewer_refcount, -1);
}

struct relay_session *session_find_by_id(struct lttng_ht *ht, uint64_t id);
struct relay_session *session_create(void);
int session_delete(struct lttng_ht *ht, struct relay_session *session);

/*
 * Direct destroy without reading the refcount.
 */
void session_destroy(struct relay_session *session);

/*
 * Destroy the session if the refcount is down to 0.
 */
void session_try_destroy(struct lttng_ht *ht, struct relay_session *session);

/*
 * Decrement the viewer refcount and destroy it if down to 0.
 */
void session_viewer_try_destroy(struct lttng_ht *ht,
		struct relay_session *session);

#endif /* _SESSION_H */
