#ifndef _VIEWER_SESSION_H
#define _VIEWER_SESSION_H

/*
 * Copyright (C) 2013 Julien Desfossez <jdesfossez@efficios.com>
 * Copyright (C) 2013 David Goulet <dgoulet@efficios.com>
 * Copyright (C) 2015 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "lttng-viewer-abi.hpp"
#include "session.hpp"

#include <common/hashtable/hashtable.hpp>
#include <common/trace-chunk.hpp>

#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <urcu/list.h>
#include <urcu/ref.h>

struct relay_viewer_session {
	/*
	 * Session list. Updates are protected by the session_list_lock.
	 * Traversals are protected by RCU.
	 * This list limits the design to having the sessions in at most
	 * one viewer session.
	 */
	struct cds_list_head session_list; /* RCU list. */
	pthread_mutex_t session_list_lock; /* Protects list updates. */
	/*
	 * The viewer session's current trace chunk is initially set, when
	 * a viewer attaches to the viewer session, to a copy the corresponding
	 * relay_session's current trace chunk.
	 *
	 * A live session always attempts to "catch-up" to the newest available
	 * trace chunk. This means that when a viewer reaches the end of a
	 * trace chunk, the viewer session may not transition to the "next" one:
	 * it jumps to the most recent trace chunk available (the one being
	 * produced by the relay_session). Hence, if the producer performs
	 * multiple rotations before a viewer completes the consumption of a
	 * trace chunk, it will skip over those "intermediary" trace chunks.
	 *
	 * A viewer session updates its current trace chunk when:
	 *   1) new viewer streams are created,
	 *   2) a new index is requested,
	 *   3) metadata is requested.
	 *
	 * Hence, as a general principle, the viewer session will reference the
	 * most recent trace chunk available _even if its streams do not point to
	 * it_. It indicates which trace chunk viewer streams should transition
	 * to when the end of their current trace chunk is reached.
	 *
	 * Note that a viewer session's trace chunk points to the session's
	 * output directory. The sub-directories in which the various stream files
	 * are created are considered as being a part of their name.
	 */
	struct lttng_trace_chunk *current_trace_chunk;
};

struct relay_viewer_session *viewer_session_create(void);
void viewer_session_destroy(struct relay_viewer_session *vsession);
void viewer_session_close(struct relay_viewer_session *vsession);

enum lttng_viewer_attach_return_code viewer_session_attach(struct relay_viewer_session *vsession,
							   struct relay_session *session);
int viewer_session_is_attached(struct relay_viewer_session *vsession,
			       struct relay_session *session);
void viewer_session_close_one_session(struct relay_viewer_session *vsession,
				      struct relay_session *session);
int viewer_session_set_trace_chunk_copy(struct relay_viewer_session *vsession,
					struct lttng_trace_chunk *relay_session_trace_chunk);

#endif /* _VIEWER_SESSION_H */
