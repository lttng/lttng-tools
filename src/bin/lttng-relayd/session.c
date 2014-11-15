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

#define _GNU_SOURCE
#include <common/common.h>

#include "ctf-trace.h"
#include "session.h"
#include "stream.h"

/* Global session id used in the session creation. */
static uint64_t last_relay_session_id;

static void rcu_destroy_session(struct rcu_head *head)
{
	struct relay_session *session =
		caa_container_of(head, struct relay_session, rcu_node);

	free(session);
}

/*
 * Create a new session by assigning a new session ID.
 *
 * Return allocated session or else NULL.
 */
struct relay_session *session_create(void)
{
	struct relay_session *session;

	session = zmalloc(sizeof(*session));
	if (!session) {
		PERROR("relay session zmalloc");
		goto error;
	}

	session->ctf_traces_ht = lttng_ht_new(0, LTTNG_HT_TYPE_STRING);
	if (!session->ctf_traces_ht) {
		free(session);
		session = NULL;
		goto error;
	}

	pthread_mutex_init(&session->viewer_ready_lock, NULL);
	session->id = ++last_relay_session_id;
	lttng_ht_node_init_u64(&session->session_n, session->id);

error:
	return session;
}

/*
 * Lookup a session within the given hash table and session id. RCU read side
 * lock MUST be acquired before calling this and as long as the caller has a
 * reference to the object.
 *
 * Return session or NULL if not found.
 */
struct relay_session *session_find_by_id(struct lttng_ht *ht, uint64_t id)
{
	struct relay_session *session = NULL;
	struct lttng_ht_node_u64 *node;
	struct lttng_ht_iter iter;

	assert(ht);

	lttng_ht_lookup(ht, &id, &iter);
	node = lttng_ht_iter_get_node_u64(&iter);
	if (!node) {
		DBG("Session find by ID %" PRIu64 " id NOT found", id);
		goto end;
	}
	session = caa_container_of(node, struct relay_session, session_n);
	DBG("Session find by ID %" PRIu64 " id found", id);

end:
	return session;
}

/*
 * Delete session from the given hash table.
 *
 * Return lttng ht del error code being 0 on success and 1 on failure.
 */
int session_delete(struct lttng_ht *ht, struct relay_session *session)
{
	struct lttng_ht_iter iter;

	assert(ht);
	assert(session);

	iter.iter.node = &session->session_n.node;
	return lttng_ht_del(ht, &iter);
}

/*
 * The caller MUST be from the viewer thread since the viewer refcount is
 * decremented. With this calue down to 0, it will try to destroy the session.
 */
void session_viewer_try_destroy(struct lttng_ht *ht,
		struct relay_session *session)
{
	unsigned long ret_ref;

	assert(session);

	ret_ref = uatomic_add_return(&session->viewer_refcount, -1);
	if (ret_ref == 0) {
		session_try_destroy(ht, session);
	}
}

/*
 * Should only be called from the main streaming thread since it does not touch
 * the viewer refcount. If this refcount is down to 0, destroy the session only
 * and only if the session deletion succeeds. This is done because the viewer
 * *and* the streaming thread can both concurently try to destroy the session
 * thus the first come first serve.
 */
void session_try_destroy(struct lttng_ht *ht, struct relay_session *session)
{
	int ret = 0;
	unsigned long ret_ref;

	assert(session);

	ret_ref = uatomic_read(&session->viewer_refcount);
	if (ret_ref == 0 && session->close_flag) {
		if (ht) {
			ret = session_delete(ht, session);
		}
		if (!ret) {
			/* Only destroy the session if the deletion was successful. */
			session_destroy(session);
		}
	}
}

/*
 * Destroy a session object.
 *
 * This function must *NOT* be called with an RCU read lock held since
 * the session's ctf_traces_ht is destroyed.
 */
void session_destroy(struct relay_session *session)
{
	struct ctf_trace *ctf_trace;
	struct lttng_ht_iter iter;

	assert(session);

	DBG("Relay destroying session %" PRIu64, session->id);

	/*
	 * Empty the ctf trace hash table which will destroy the stream contained
	 * in that table.
	 */
	rcu_read_lock();
	cds_lfht_for_each_entry(session->ctf_traces_ht->ht, &iter.iter, ctf_trace,
			node.node) {
		ctf_trace_delete(session->ctf_traces_ht, ctf_trace);
		ctf_trace_destroy(ctf_trace);
	}
	rcu_read_unlock();
	lttng_ht_destroy(session->ctf_traces_ht);

	call_rcu(&session->rcu_node, rcu_destroy_session);
}
