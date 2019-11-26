#ifndef LTTNG_RELAYD_H
#define LTTNG_RELAYD_H

/*
 * Copyright (C) 2012 - Julien Desfossez <jdesfossez@efficios.com>
 *                      David Goulet <dgoulet@efficios.com>
 *               2015 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

#include <limits.h>
#include <urcu.h>
#include <urcu/wfcqueue.h>

#include <common/hashtable/hashtable.h>
#include <common/fd-tracker/fd-tracker.h>

struct sessiond_trace_chunk_registry;

/*
 * Queue used to enqueue relay requests
 */
struct relay_conn_queue {
	struct cds_wfcq_head head;
	struct cds_wfcq_tail tail;
	int32_t futex;
};

enum relay_group_output_by {
	RELAYD_GROUP_OUTPUT_BY_UNKNOWN,
	RELAYD_GROUP_OUTPUT_BY_HOST,
	RELAYD_GROUP_OUTPUT_BY_SESSION,
};

/*
 * Contains stream indexed by ID. This is important since many commands lookup
 * streams only by ID thus also keeping them in this hash table makes the
 * search O(1).
 */
extern struct lttng_ht *sessions_ht;
extern struct lttng_ht *relay_streams_ht;
extern struct lttng_ht *viewer_streams_ht;
extern struct sessiond_trace_chunk_registry *sessiond_trace_chunk_registry;

extern char *opt_output_path;
extern const char *tracing_group_name;
extern const char * const config_section_name;
extern enum relay_group_output_by opt_group_output_by;

extern int thread_quit_pipe[2];

extern struct fd_tracker *the_fd_tracker;

void lttng_relay_notify_ready(void);
int lttng_relay_stop_threads(void);

#endif /* LTTNG_RELAYD_H */
