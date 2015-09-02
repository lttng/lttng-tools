#ifndef _SESSION_H
#define _SESSION_H

/*
 * Copyright (C) 2013 - Julien Desfossez <jdesfossez@efficios.com>
 *                      David Goulet <dgoulet@efficios.com>
 *               2015 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

#include <limits.h>
#include <inttypes.h>
#include <pthread.h>
#include <urcu/list.h>
#include <urcu/ref.h>

#include <common/hashtable/hashtable.h>

/*
 * Represents a session for the relay point of view
 */
struct relay_session {
	/*
	 * This session id is used to identify a set of stream to a
	 * tracing session but also make sure we have a unique session
	 * id associated with a session daemon which can provide
	 * multiple data source.
	 */
	uint64_t id;
	char session_name[NAME_MAX];
	char hostname[HOST_NAME_MAX];
	uint32_t live_timer;

	/* Tell if this session is for a snapshot or not. */
	bool snapshot;

	/*
	 * Session has no back reference to its connection because it
	 * has a life-time that can be longer than the consumer connection
	 * life-time: a reference can still be held by the viewer
	 * connection.
	 */

	/* Reference count of ctf-traces and viewers using the session. */
	struct urcu_ref ref;
	/* session reflock nests inside ctf_trace reflock. */
	pthread_mutex_t reflock;

	pthread_mutex_t lock;

	/*
	 * major/minor version used for this session.
	 */
	uint32_t major;
	uint32_t minor;

	bool viewer_attached;
	/* Tell if the session connection has been closed on the streaming side. */
	bool connection_closed;

	/* Contains ctf_trace object of that session indexed by path name. */
	struct lttng_ht *ctf_traces_ht;

	/*
	 * This contains streams that are received on that connection.
	 * It's used to store them until we get the streams sent
	 * command. When this is received, we remove those streams for
	 * the list and publish them.
	 * Updates are protected by the recv_list_lock.
	 * Traversals are protected by RCU.
	 * recv_list_lock also protects stream_count.
	 */
	struct cds_list_head recv_list;	/* RCU list. */
	uint32_t stream_count;
	pthread_mutex_t recv_list_lock;

	/*
	 * Flag checked and exchanged with uatomic_cmpxchg to tell the
	 * viewer-side if new streams got added since the last check.
	 */
	unsigned long new_streams;

	/*
	 * Node in the global session hash table.
	 */
	struct lttng_ht_node_u64 session_n;
	/*
	 * Member of the session list in struct relay_viewer_session.
	 * Updates are protected by the relay_viewer_session
	 * session_list_lock. Traversals are protected by RCU.
	 */
	struct cds_list_head viewer_session_node;
	struct rcu_head rcu_node;	/* For call_rcu teardown. */
};

struct relay_session *session_create(const char *session_name,
		const char *hostname, uint32_t live_timer,
		bool snapshot, uint32_t major, uint32_t minor);
struct relay_session *session_get_by_id(uint64_t id);
bool session_get(struct relay_session *session);
void session_put(struct relay_session *session);

int session_close(struct relay_session *session);
void print_sessions(void);

#endif /* _SESSION_H */
