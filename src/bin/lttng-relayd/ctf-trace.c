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

static uint64_t last_relay_ctf_trace_id;

/*
 * Try to destroy a ctf_trace object meaning that the refcount is decremented
 * and checked if down to 0 which will free it.
 */
void ctf_trace_try_destroy(struct ctf_trace *obj)
{
	unsigned long ret_ref;

	if (!obj) {
		return;
	}

	ret_ref = uatomic_add_return(&obj->refcount, -1);
	if (ret_ref == 0) {
		DBG("Freeing ctf_trace %" PRIu64, obj->id);
		free(obj);
	}
}

/*
 * Create and return an allocated ctf_trace object. NULL on error.
 */
struct ctf_trace *ctf_trace_create(void)
{
	struct ctf_trace *obj;

	obj = zmalloc(sizeof(*obj));
	if (!obj) {
		PERROR("ctf_trace alloc");
		goto error;
	}

	obj->id = ++last_relay_ctf_trace_id;
	DBG("Created ctf_trace %" PRIu64, obj->id);

error:
	return obj;
}

/*
 * Check if we can assign the ctf_trace id and metadata stream to one or all
 * the streams with the same path_name (our unique ID for ctf traces).
 *
 * The given stream MUST be new and NOT visible (in any hash table).
 */
void ctf_trace_assign(struct lttng_ht *ht, struct relay_stream *stream)
{
	struct lttng_ht_iter iter;
	struct relay_stream *tmp_stream;

	assert(ht);
	assert(stream);

	rcu_read_lock();
	cds_lfht_for_each_entry_duplicate(ht->ht,
			ht->hash_fct((void *) stream->path_name, lttng_ht_seed),
			ht->match_fct, (void *) stream->path_name,
			&iter.iter, tmp_stream, ctf_trace_node.node) {
		if (stream->metadata_flag) {
			/*
			 * The new stream is the metadata stream for this trace,
			 * assign the ctf_trace pointer to all the streams in
			 * this bucket.
			 */
			pthread_mutex_lock(&tmp_stream->lock);
			tmp_stream->ctf_trace = stream->ctf_trace;
			uatomic_inc(&tmp_stream->ctf_trace->refcount);
			pthread_mutex_unlock(&tmp_stream->lock);
			DBG("Assigned ctf_trace %" PRIu64 " to stream %" PRIu64,
					tmp_stream->ctf_trace->id, tmp_stream->stream_handle);
		} else if (tmp_stream->ctf_trace) {
			/*
			 * The ctf_trace already exists for this bucket,
			 * just assign the pointer to the new stream and exit.
			 */
			stream->ctf_trace = tmp_stream->ctf_trace;
			uatomic_inc(&stream->ctf_trace->refcount);
			DBG("Assigned ctf_trace %" PRIu64 " to stream %" PRIu64,
					tmp_stream->ctf_trace->id, tmp_stream->stream_handle);
			goto end;
		} else {
			/*
			 * We don't know yet the ctf_trace ID (no metadata has been added),
			 * so leave it there until the metadata stream arrives.
			 */
			goto end;
		}
	}

end:
	rcu_read_unlock();
	return;
}

