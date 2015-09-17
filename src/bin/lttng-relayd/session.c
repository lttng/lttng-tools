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

#define _LGPL_SOURCE
#include <common/common.h>
#include <urcu/rculist.h>

#include "lttng-relayd.h"
#include "ctf-trace.h"
#include "session.h"
#include "stream.h"

/* Global session id used in the session creation. */
static uint64_t last_relay_session_id;
static pthread_mutex_t last_relay_session_id_lock = PTHREAD_MUTEX_INITIALIZER;

/*
 * Create a new session by assigning a new session ID.
 *
 * Return allocated session or else NULL.
 */
struct relay_session *session_create(const char *session_name,
		const char *hostname, uint32_t live_timer,
		bool snapshot, uint32_t major, uint32_t minor)
{
	struct relay_session *session;

	session = zmalloc(sizeof(*session));
	if (!session) {
		PERROR("relay session zmalloc");
		goto error;
	}
	if (lttng_strncpy(session->session_name, session_name,
			sizeof(session->session_name))) {
		goto error;
	}
	if (lttng_strncpy(session->hostname, hostname,
			sizeof(session->hostname))) {
		goto error;
	}
	session->ctf_traces_ht = lttng_ht_new(0, LTTNG_HT_TYPE_STRING);
	if (!session->ctf_traces_ht) {
		goto error;
	}

	pthread_mutex_lock(&last_relay_session_id_lock);
	session->id = ++last_relay_session_id;
	pthread_mutex_unlock(&last_relay_session_id_lock);

	session->major = major;
	session->minor = minor;
	lttng_ht_node_init_u64(&session->session_n, session->id);
	urcu_ref_init(&session->ref);
	CDS_INIT_LIST_HEAD(&session->recv_list);
	pthread_mutex_init(&session->lock, NULL);
	pthread_mutex_init(&session->recv_list_lock, NULL);

	session->live_timer = live_timer;
	session->snapshot = snapshot;

	lttng_ht_add_unique_u64(sessions_ht, &session->session_n);
	return session;

error:
	free(session);
	return NULL;
}

/* Should be called with RCU read-side lock held. */
bool session_get(struct relay_session *session)
{
	return urcu_ref_get_unless_zero(&session->ref);
}

/*
 * Lookup a session within the session hash table using the session id
 * as key. A session reference is taken when a session is returned.
 * session_put() must be called on that session.
 *
 * Return session or NULL if not found.
 */
struct relay_session *session_get_by_id(uint64_t id)
{
	struct relay_session *session = NULL;
	struct lttng_ht_node_u64 *node;
	struct lttng_ht_iter iter;

	rcu_read_lock();
	lttng_ht_lookup(sessions_ht, &id, &iter);
	node = lttng_ht_iter_get_node_u64(&iter);
	if (!node) {
		DBG("Session find by ID %" PRIu64 " id NOT found", id);
		goto end;
	}
	session = caa_container_of(node, struct relay_session, session_n);
	DBG("Session find by ID %" PRIu64 " id found", id);
	if (!session_get(session)) {
		session = NULL;
	}
end:
	rcu_read_unlock();
	return session;
}

static void rcu_destroy_session(struct rcu_head *rcu_head)
{
	struct relay_session *session =
			caa_container_of(rcu_head, struct relay_session,
				rcu_node);
	/*
	 * Since each trace has a reference on the session, it means
	 * that if we are at the point where we teardown the session, no
	 * trace belonging to that session exist at this point.
	 * Calling lttng_ht_destroy in call_rcu worker thread so we
	 * don't hold the RCU read-side lock while calling it.
	 */
	lttng_ht_destroy(session->ctf_traces_ht);
	free(session);
}

/*
 * Delete session from the given hash table.
 *
 * Return lttng ht del error code being 0 on success and 1 on failure.
 */
static int session_delete(struct relay_session *session)
{
	struct lttng_ht_iter iter;

	iter.iter.node = &session->session_n.node;
	return lttng_ht_del(sessions_ht, &iter);
}


static void destroy_session(struct relay_session *session)
{
	int ret;

	ret = session_delete(session);
	assert(!ret);
	call_rcu(&session->rcu_node, rcu_destroy_session);
}

void session_release(struct urcu_ref *ref)
{
	struct relay_session *session =
			caa_container_of(ref, struct relay_session, ref);

	destroy_session(session);
}

void session_put(struct relay_session *session)
{
	rcu_read_lock();
	urcu_ref_put(&session->ref, session_release);
	rcu_read_unlock();
}

int session_close(struct relay_session *session)
{
	int ret = 0;
	struct ctf_trace *trace;
	struct lttng_ht_iter iter;
	struct relay_stream *stream;

	pthread_mutex_lock(&session->lock);
	DBG("closing session %" PRIu64 ": is conn already closed %d",
			session->id, session->connection_closed);
	if (session->connection_closed) {
		ret = -1;
		goto unlock;
	}
	session->connection_closed = true;
unlock:
	pthread_mutex_unlock(&session->lock);
	if (ret) {
		return ret;
	}

	rcu_read_lock();
	cds_lfht_for_each_entry(session->ctf_traces_ht->ht,
			&iter.iter, trace, node.node) {
		ret = ctf_trace_close(trace);
		if (ret) {
			goto rcu_unlock;
		}
	}
	cds_list_for_each_entry_rcu(stream, &session->recv_list,
			recv_node) {
		/* Close streams which have not been published yet. */
		try_stream_close(stream);
	}
rcu_unlock:
	rcu_read_unlock();
	if (ret) {
		return ret;
	}
	/* Put self-reference from create. */
	session_put(session);
	return ret;
}

int session_abort(struct relay_session *session)
{
	int ret = 0;

	if (!session) {
		return 0;
	}

	pthread_mutex_lock(&session->lock);
	DBG("aborting session %" PRIu64, session->id);
	if (session->aborted) {
		ERR("session %" PRIu64 " is already aborted", session->id);
		ret = -1;
		goto unlock;
	}
	session->aborted = true;
unlock:
	pthread_mutex_unlock(&session->lock);
	return ret;
}

void print_sessions(void)
{
	struct lttng_ht_iter iter;
	struct relay_session *session;

	if (!sessions_ht) {
		return;
	}

	rcu_read_lock();
	cds_lfht_for_each_entry(sessions_ht->ht, &iter.iter, session,
			session_n.node) {
		if (!session_get(session)) {
			continue;
		}
		DBG("session %p refcount %ld session %" PRIu64,
			session,
			session->ref.refcount,
			session->id);
		session_put(session);
	}
	rcu_read_unlock();
}
