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
#include <assert.h>

#include <common/common.h>
#include <common/utils.h>
#include <urcu/rculist.h>

#include "ctf-trace.h"
#include "lttng-relayd.h"
#include "stream.h"

static uint64_t last_relay_ctf_trace_id;
static pthread_mutex_t last_relay_ctf_trace_id_lock = PTHREAD_MUTEX_INITIALIZER;

static void rcu_destroy_ctf_trace(struct rcu_head *rcu_head)
{
	struct ctf_trace *trace =
		caa_container_of(rcu_head, struct ctf_trace, rcu_node);

	free(trace);
}

/*
 * Destroy a ctf trace and all stream contained in it.
 *
 * MUST be called with the RCU read side lock.
 */
void ctf_trace_destroy(struct ctf_trace *trace)
{
	/*
	 * Getting to this point, every stream referenced by that trace
	 * have put back their ref since the've been closed by the
	 * control side.
	 */
	assert(cds_list_empty(&trace->stream_list));
	session_put(trace->session);
	trace->session = NULL;
	call_rcu(&trace->rcu_node, rcu_destroy_ctf_trace);
}

void ctf_trace_release(struct urcu_ref *ref)
{
	struct ctf_trace *trace =
		caa_container_of(ref, struct ctf_trace, ref);
	int ret;
	struct lttng_ht_iter iter;

	iter.iter.node = &trace->node.node;
	ret = lttng_ht_del(trace->session->ctf_traces_ht, &iter);
	assert(!ret);
	ctf_trace_destroy(trace);
}

/*
 * Should be called with RCU read-side lock held.
 */
bool ctf_trace_get(struct ctf_trace *trace)
{
	return urcu_ref_get_unless_zero(&trace->ref);
}

/*
 * Create and return an allocated ctf_trace. NULL on error.
 * There is no "open" and "close" for a ctf_trace, but rather just a
 * create and refcounting. Whenever all the streams belonging to a trace
 * put their reference, its refcount drops to 0.
 */
static struct ctf_trace *ctf_trace_create(struct relay_session *session,
		char *path_name)
{
	struct ctf_trace *trace;

	trace = zmalloc(sizeof(*trace));
	if (!trace) {
		PERROR("ctf_trace alloc");
		goto error;
	}

	if (!session_get(session)) {
		ERR("Cannot get session");
		free(trace);
		trace = NULL;
		goto error;
	}
	trace->session = session;

	CDS_INIT_LIST_HEAD(&trace->stream_list);

	pthread_mutex_lock(&last_relay_ctf_trace_id_lock);
	trace->id = ++last_relay_ctf_trace_id;
	pthread_mutex_unlock(&last_relay_ctf_trace_id_lock);

	lttng_ht_node_init_str(&trace->node, path_name);
	trace->session = session;
	urcu_ref_init(&trace->ref);
	pthread_mutex_init(&trace->lock, NULL);
	pthread_mutex_init(&trace->stream_list_lock, NULL);
	lttng_ht_add_str(session->ctf_traces_ht, &trace->node);

	DBG("Created ctf_trace %" PRIu64 " with path: %s", trace->id, path_name);

error:
	return trace;
}

/*
 * Return a ctf_trace if found by id in the given hash table else NULL.
 * Hold a reference on the ctf_trace, and must be paired with
 * ctf_trace_put().
 */
struct ctf_trace *ctf_trace_get_by_path_or_create(struct relay_session *session,
		char *path_name)
{
	struct lttng_ht_node_str *node;
	struct lttng_ht_iter iter;
	struct ctf_trace *trace = NULL;

	rcu_read_lock();
	lttng_ht_lookup(session->ctf_traces_ht, (void *) path_name, &iter);
	node = lttng_ht_iter_get_node_str(&iter);
	if (!node) {
		DBG("CTF Trace path %s not found", path_name);
		goto end;
	}
	trace = caa_container_of(node, struct ctf_trace, node);
	if (!ctf_trace_get(trace)) {
		trace = NULL;
	}
end:
	rcu_read_unlock();
	if (!trace) {
		/* Try to create */
		trace = ctf_trace_create(session, path_name);
	}
	return trace;
}

void ctf_trace_put(struct ctf_trace *trace)
{
	rcu_read_lock();
	urcu_ref_put(&trace->ref, ctf_trace_release);
	rcu_read_unlock();
}

int ctf_trace_close(struct ctf_trace *trace)
{
	struct relay_stream *stream;

	rcu_read_lock();
	cds_list_for_each_entry_rcu(stream, &trace->stream_list,
			stream_node) {
		/*
		 * Close stream since the connection owning the trace is being
		 * torn down.
		 */
		try_stream_close(stream);
	}
	rcu_read_unlock();
	/*
	 * Since all references to the trace are held by its streams, we
	 * don't need to do any self-ref put.
	 */
	return 0;
}

struct relay_viewer_stream *ctf_trace_get_viewer_metadata_stream(struct ctf_trace *trace)
{
	struct relay_viewer_stream *vstream;

	rcu_read_lock();
	vstream = rcu_dereference(trace->viewer_metadata_stream);
	if (!vstream) {
		goto end;
	}
	if (!viewer_stream_get(vstream)) {
		vstream = NULL;
	}
end:
	rcu_read_unlock();
	return vstream;
}
