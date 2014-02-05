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
#include <assert.h>

#include <common/common.h>
#include <common/utils.h>

#include "ctf-trace.h"
#include "lttng-relayd.h"
#include "stream.h"

static uint64_t last_relay_ctf_trace_id;

static void rcu_destroy_ctf_trace(struct rcu_head *head)
{
	struct lttng_ht_node_str *node =
		caa_container_of(head, struct lttng_ht_node_str, head);
	struct ctf_trace *trace=
		caa_container_of(node, struct ctf_trace, node);

	free(trace);
}

/*
 * Destroy a ctf trace and all stream contained in it.
 *
 * MUST be called with the RCU read side lock.
 */
void ctf_trace_destroy(struct ctf_trace *obj)
{
	struct relay_stream *stream, *tmp_stream;

	assert(obj);
	/*
	 * Getting to this point, every stream referenced to that object have put
	 * back their ref since the've been closed by the control side.
	 */
	assert(!obj->refcount);

	cds_list_for_each_entry_safe(stream, tmp_stream, &obj->stream_list,
			trace_list) {
		stream_delete(relay_streams_ht, stream);
		stream_destroy(stream);
	}

	call_rcu(&obj->node.head, rcu_destroy_ctf_trace);
}

void ctf_trace_try_destroy(struct relay_session *session,
		struct ctf_trace *ctf_trace)
{
	assert(session);
	assert(ctf_trace);

	/*
	 * Considering no viewer attach to the session and the trace having no more
	 * stream attached, wipe the trace.
	 */
	if (uatomic_read(&session->viewer_refcount) == 0 &&
			uatomic_read(&ctf_trace->refcount) == 0) {
		ctf_trace_delete(session->ctf_traces_ht, ctf_trace);
		ctf_trace_destroy(ctf_trace);
	}
}

/*
 * Create and return an allocated ctf_trace object. NULL on error.
 */
struct ctf_trace *ctf_trace_create(char *path_name)
{
	struct ctf_trace *obj;

	assert(path_name);

	obj = zmalloc(sizeof(*obj));
	if (!obj) {
		PERROR("ctf_trace alloc");
		goto error;
	}

	CDS_INIT_LIST_HEAD(&obj->stream_list);

	obj->id = ++last_relay_ctf_trace_id;
	lttng_ht_node_init_str(&obj->node, path_name);

	DBG("Created ctf_trace %" PRIu64 " with path: %s", obj->id, path_name);

error:
	return obj;
}

/*
 * Return a ctf_trace object if found by id in the given hash table else NULL.
 */
struct ctf_trace *ctf_trace_find_by_path(struct lttng_ht *ht,
		char *path_name)
{
	struct lttng_ht_node_str *node;
	struct lttng_ht_iter iter;
	struct ctf_trace *trace = NULL;

	assert(ht);

	lttng_ht_lookup(ht, (void *) path_name, &iter);
	node = lttng_ht_iter_get_node_str(&iter);
	if (!node) {
		DBG("CTF Trace path %s not found", path_name);
		goto end;
	}
	trace = caa_container_of(node, struct ctf_trace, node);

end:
	return trace;
}

/*
 * Add stream to a given hash table.
 */
void ctf_trace_add(struct lttng_ht *ht, struct ctf_trace *trace)
{
	assert(ht);
	assert(trace);

	lttng_ht_add_str(ht, &trace->node);
}

/*
 * Delete stream from a given hash table.
 */
void ctf_trace_delete(struct lttng_ht *ht, struct ctf_trace *trace)
{
	int ret;
	struct lttng_ht_iter iter;

	assert(ht);
	assert(trace);

	iter.iter.node = &trace->node.node;
	ret = lttng_ht_del(ht, &iter);
	assert(!ret);
}
