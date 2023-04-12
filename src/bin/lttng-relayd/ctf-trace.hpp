#ifndef _CTF_TRACE_H
#define _CTF_TRACE_H

/*
 * Copyright (C) 2013 Julien Desfossez <jdesfossez@efficios.com>
 * Copyright (C) 2013 David Goulet <dgoulet@efficios.com>
 * Copyright (C) 2015 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "session.hpp"
#include "stream.hpp"
#include "viewer-stream.hpp"

#include <common/hashtable/hashtable.hpp>

#include <inttypes.h>
#include <urcu/ref.h>

struct ctf_trace {
	struct urcu_ref ref; /* Every stream has a ref on the trace. */
	struct relay_session *session; /* Back ref to trace session */

	/* Trace sub-folder relative to the session output path. */
	char *path;

	/*
	 * The ctf_trace lock nests inside the session lock.
	 */
	pthread_mutex_t lock;
	uint64_t id;
	struct relay_viewer_stream *viewer_metadata_stream; /* RCU protected */

	/*
	 * Relay streams associated with this ctf trace.
	 * Updates are protected by the stream_list lock.
	 * Traversals are protected by RCU.
	 */
	struct cds_list_head stream_list;
	pthread_mutex_t stream_list_lock;

	/*
	 * Node within session trace hash table. Node is indexed by
	 * stream path name.
	 */
	struct lttng_ht_node_str node;
	struct rcu_head rcu_node; /* For call_rcu teardown. */

	/*
	 * True if the metadata stream of this trace was sent the viewer in the
	 * past.
	 */
	bool metadata_stream_sent_to_viewer;
};

struct ctf_trace *ctf_trace_get_by_path_or_create(struct relay_session *session,
						  const char *subpath);
bool ctf_trace_get(struct ctf_trace *trace);
void ctf_trace_put(struct ctf_trace *trace);

int ctf_trace_close(struct ctf_trace *trace);

struct relay_viewer_stream *ctf_trace_get_viewer_metadata_stream(struct ctf_trace *trace);

#endif /* _CTF_TRACE_H */
