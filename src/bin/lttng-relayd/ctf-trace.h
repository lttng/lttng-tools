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

struct ctf_trace {
	int refcount;
	uint64_t id;
	uint64_t metadata_received;
	uint64_t metadata_sent;
	struct relay_stream *metadata_stream;
};

void ctf_trace_assign(struct lttng_ht *ht, struct relay_stream *stream);
struct ctf_trace *ctf_trace_create(void);
void ctf_trace_try_destroy(struct ctf_trace *obj);

#endif /* _CTF_TRACE_H */
