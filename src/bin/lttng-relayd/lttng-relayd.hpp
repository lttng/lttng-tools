#ifndef LTTNG_RELAYD_H
#define LTTNG_RELAYD_H

/*
 * Copyright (C) 2012 Julien Desfossez <jdesfossez@efficios.com>
 * Copyright (C) 2012 David Goulet <dgoulet@efficios.com>
 * Copyright (C) 2015 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include <common/compat/poll.hpp>
#include <common/fd-tracker/fd-tracker.hpp>
#include <common/hashtable/hashtable.hpp>

#include <limits.h>
#include <urcu.h>
#include <urcu/wfcqueue.h>

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
extern const char *const config_section_name;
extern enum relay_group_output_by opt_group_output_by;

extern struct fd_tracker *the_fd_tracker;

void lttng_relay_notify_ready(void);
int lttng_relay_stop_threads(void);

int relayd_init_thread_quit_pipe(void);
int relayd_notify_thread_quit_pipe(void);
void relayd_close_thread_quit_pipe(void);
bool relayd_is_thread_quit_pipe(const int fd);

int create_named_thread_poll_set(struct lttng_poll_event *events, int size, const char *name);

#endif /* LTTNG_RELAYD_H */
