/*
 * Copyright (C) 2012 - Julien Desfossez <jdesfossez@efficios.com>
 *                      David Goulet <dgoulet@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef LTTNG_RELAYD_H
#define LTTNG_RELAYD_H

#define _LGPL_SOURCE
#include <limits.h>
#include <urcu.h>
#include <urcu/wfqueue.h>

#include <common/hashtable/hashtable.h>

/*
 * Queue used to enqueue relay requests
 */
struct relay_conn_queue {
	struct cds_wfq_queue queue;
	int32_t futex;
};

struct relay_local_data {
	struct lttng_ht *sessions_ht;
};

extern char *opt_output_path;

/*
 * Contains stream indexed by ID. This is important since many commands lookup
 * streams only by ID thus also keeping them in this hash table makes the
 * search O(1) instead of iterating over the ctf_traces_ht of the session.
 */
extern struct lttng_ht *relay_streams_ht;

extern struct lttng_ht *viewer_streams_ht;
extern struct lttng_ht *indexes_ht;

extern const char *tracing_group_name;

extern const char * const config_section_name;

void lttng_relay_notify_ready(void);

#endif /* LTTNG_RELAYD_H */
