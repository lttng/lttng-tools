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

#ifndef _CTF_TRACE_H
#define _CTF_TRACE_H

#include <inttypes.h>

#include <common/hashtable/hashtable.h>

#include "lttng-relayd.h"
#include "session.h"

struct ctf_trace {
	int refcount;
	unsigned int invalid_flag:1;
	uint64_t id;
	uint64_t metadata_received;
	uint64_t metadata_sent;
	struct relay_stream *metadata_stream;
	struct relay_viewer_stream *viewer_metadata_stream;
	/* Node indexed by stream path name in the corresponding session. */
	struct lttng_ht_node_str node;

	/* Relay stream associated with this ctf trace. */
	struct cds_list_head stream_list;
};

static inline void ctf_trace_get_ref(struct ctf_trace *trace)
{
	uatomic_inc(&trace->refcount);
}

static inline void ctf_trace_put_ref(struct ctf_trace *trace)
{
	uatomic_add(&trace->refcount, -1);
}

void ctf_trace_assign(struct relay_stream *stream);
struct ctf_trace *ctf_trace_create(char *path_name);
void ctf_trace_destroy(struct ctf_trace *obj);
void ctf_trace_try_destroy(struct relay_session *session,
		struct ctf_trace *ctf_trace);
struct ctf_trace *ctf_trace_find_by_path(struct lttng_ht *ht,
		char *path_name);
void ctf_trace_add(struct lttng_ht *ht, struct ctf_trace *trace);
void ctf_trace_delete(struct lttng_ht *ht, struct ctf_trace *trace);

#endif /* _CTF_TRACE_H */
