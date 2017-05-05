/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 * Copyright (C) 2016 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _LTT_TRACE_UST_H
#define _LTT_TRACE_UST_H

#include <limits.h>
#include <urcu/list.h>

#include <lttng/lttng.h>
#include <common/hashtable/hashtable.h>
#include <common/defaults.h>

#include "consumer.h"
#include "ust-ctl.h"

struct agent;

struct ltt_ust_ht_key {
	const char *name;
	const struct lttng_filter_bytecode *filter;
	enum lttng_ust_loglevel_type loglevel_type;
	int loglevel_value;
	const struct lttng_event_exclusion *exclusion;
};

/* Context hash table nodes */
struct ltt_ust_context {
	struct lttng_ust_context_attr ctx;
	struct lttng_ht_node_ulong node;
	struct cds_list_head list;
};

/* UST event */
struct ltt_ust_event {
	unsigned int enabled;
	struct lttng_ust_event attr;
	struct lttng_ht_node_str node;
	char *filter_expression;
	struct lttng_filter_bytecode *filter;
	struct lttng_event_exclusion *exclusion;
	/*
	 * An internal event is an event which was created by the session daemon
	 * through which, for example, events emitted in Agent domains are
	 * "funelled". This is used to hide internal events from external
	 * clients as they should never be modified by the external world.
	 */
	bool internal;
};

/* UST channel */
struct ltt_ust_channel {
	uint64_t id;	/* unique id per session. */
	unsigned int enabled;
	/*
	 * A UST channel can be part of a userspace sub-domain such as JUL,
	 * Log4j, Python.
	 */
	enum lttng_domain_type domain;
	char name[LTTNG_UST_SYM_NAME_LEN];
	struct lttng_ust_channel_attr attr;
	struct lttng_ht *ctx;
	struct cds_list_head ctx_list;
	struct lttng_ht *events;
	struct lttng_ht_node_str node;
	uint64_t tracefile_size;
	uint64_t tracefile_count;
	uint64_t per_pid_closed_app_discarded;
	uint64_t per_pid_closed_app_lost;
	uint64_t monitor_timer_interval;
};

/* UST domain global (LTTNG_DOMAIN_UST) */
struct ltt_ust_domain_global {
	struct lttng_ht *channels;
	struct cds_list_head registry_buffer_uid_list;
};

struct ust_pid_tracker_node {
	struct lttng_ht_node_ulong node;
};

struct ust_pid_tracker {
	struct lttng_ht *ht;
};

/* UST session */
struct ltt_ust_session {
	uint64_t id;    /* Unique identifier of session */
	struct ltt_ust_domain_global domain_global;
	/* Hash table of agent indexed by agent domain. */
	struct lttng_ht *agents;
	/* UID/GID of the user owning the session */
	uid_t uid;
	gid_t gid;
	/* Is the session active meaning has is been started or stopped. */
	unsigned int active:1;
	struct consumer_output *consumer;
	/* Sequence number for filters so the tracer knows the ordering. */
	uint64_t filter_seq_num;
	/* This indicates which type of buffer this session is set for. */
	enum lttng_buffer_type buffer_type;
	/* If set to 1, the buffer_type can not be changed anymore. */
	int buffer_type_changed;
	/* For per UID buffer, every buffer reg object is kept of this session */
	struct cds_list_head buffer_reg_uid_list;
	/* Next channel ID available for a newly registered channel. */
	uint64_t next_channel_id;
	/* Once this value reaches UINT32_MAX, no more id can be allocated. */
	uint64_t used_channel_id;
	/* Tell or not if the session has to output the traces. */
	unsigned int output_traces;
	unsigned int snapshot_mode;
	unsigned int has_non_default_channel;
	unsigned int live_timer_interval;	/* usec */

	/* Metadata channel attributes. */
	struct lttng_ust_channel_attr metadata_attr;

	/*
	 * Path where to keep the shared memory files.
	 */
	char root_shm_path[PATH_MAX];
	char shm_path[PATH_MAX];

	struct ust_pid_tracker pid_tracker;
};

/*
 * Validate that the id has reached the maximum allowed or not.
 *
 * Return 0 if NOT else 1.
 */
static inline int trace_ust_is_max_id(uint64_t id)
{
	return (id == UINT64_MAX) ? 1 : 0;
}

/*
 * Return next available channel id and increment the used counter. The
 * trace_ust_is_max_id function MUST be called before in order to validate if
 * the maximum number of IDs have been reached. If not, it is safe to call this
 * function.
 *
 * Return a unique channel ID. If max is reached, the used_channel_id counter
 * is returned.
 */
static inline uint64_t trace_ust_get_next_chan_id(struct ltt_ust_session *s)
{
	if (trace_ust_is_max_id(s->used_channel_id)) {
		return s->used_channel_id;
	}

	s->used_channel_id++;
	return s->next_channel_id++;
}

#ifdef HAVE_LIBLTTNG_UST_CTL

int trace_ust_ht_match_event(struct cds_lfht_node *node, const void *_key);
int trace_ust_ht_match_event_by_name(struct cds_lfht_node *node,
		const void *_key);

/*
 * Lookup functions. NULL is returned if not found.
 */
struct ltt_ust_event *trace_ust_find_event(struct lttng_ht *ht,
		char *name, struct lttng_filter_bytecode *filter,
		enum lttng_ust_loglevel_type loglevel_type, int loglevel_value,
		struct lttng_event_exclusion *exclusion);
struct ltt_ust_channel *trace_ust_find_channel_by_name(struct lttng_ht *ht,
		char *name);
struct agent *trace_ust_find_agent(struct ltt_ust_session *session,
		enum lttng_domain_type domain_type);

/*
 * Create functions malloc() the data structure.
 */
struct ltt_ust_session *trace_ust_create_session(uint64_t session_id);
struct ltt_ust_channel *trace_ust_create_channel(struct lttng_channel *attr,
		enum lttng_domain_type domain);
struct ltt_ust_event *trace_ust_create_event(struct lttng_event *ev,
		char *filter_expression,
		struct lttng_filter_bytecode *filter,
		struct lttng_event_exclusion *exclusion,
		bool internal_event);
struct ltt_ust_context *trace_ust_create_context(
		struct lttng_event_context *ctx);
int trace_ust_match_context(struct ltt_ust_context *uctx,
		struct lttng_event_context *ctx);
void trace_ust_delete_channel(struct lttng_ht *ht,
		struct ltt_ust_channel *channel);

/*
 * Destroy functions free() the data structure and remove from linked list if
 * it's applies.
 */
void trace_ust_destroy_session(struct ltt_ust_session *session);
void trace_ust_destroy_channel(struct ltt_ust_channel *channel);
void trace_ust_destroy_event(struct ltt_ust_event *event);
void trace_ust_destroy_context(struct ltt_ust_context *ctx);

int trace_ust_track_pid(struct ltt_ust_session *session, int pid);
int trace_ust_untrack_pid(struct ltt_ust_session *session, int pid);

int trace_ust_pid_tracker_lookup(struct ltt_ust_session *session, int pid);

ssize_t trace_ust_list_tracker_pids(struct ltt_ust_session *session,
		int32_t **_pids);

#else /* HAVE_LIBLTTNG_UST_CTL */

static inline int trace_ust_ht_match_event(struct cds_lfht_node *node,
		const void *_key)
{
	return 0;
}
static inline int trace_ust_ht_match_event_by_name(struct cds_lfht_node *node,
		const void *_key)
{
	return 0;
}
static inline
struct ltt_ust_channel *trace_ust_find_channel_by_name(struct lttng_ht *ht,
		char *name)
{
	return NULL;
}

static inline
struct ltt_ust_session *trace_ust_create_session(unsigned int session_id)
{
	return NULL;
}
static inline
struct ltt_ust_channel *trace_ust_create_channel(struct lttng_channel *attr,
		enum lttng_domain_type domain)
{
	return NULL;
}
static inline
struct ltt_ust_event *trace_ust_create_event(struct lttng_event *ev,
		const char *filter_expression,
		struct lttng_filter_bytecode *filter,
		struct lttng_event_exclusion *exclusion,
		bool internal_event)
{
	return NULL;
}
static inline
void trace_ust_destroy_session(struct ltt_ust_session *session)
{
}

static inline
void trace_ust_destroy_channel(struct ltt_ust_channel *channel)
{
}

static inline
void trace_ust_destroy_event(struct ltt_ust_event *event)
{
}
static inline
struct ltt_ust_context *trace_ust_create_context(
		struct lttng_event_context *ctx)
{
	return NULL;
}
static inline
int trace_ust_match_context(struct ltt_ust_context *uctx,
		struct lttng_event_context *ctx)
{
	return 0;
}
static inline
struct ltt_ust_event *trace_ust_find_event(struct lttng_ht *ht,
		char *name, struct lttng_filter_bytecode *filter,
		enum lttng_ust_loglevel_type loglevel_type, int loglevel_value,
		struct lttng_event_exclusion *exclusion)
{
	return NULL;
}
static inline
void trace_ust_delete_channel(struct lttng_ht *ht,
		struct ltt_ust_channel *channel)
{
	return;
}
static inline
struct agent *trace_ust_find_agent(struct ltt_ust_session *session,
		enum lttng_domain_type domain_type)
{
	return NULL;
}
static inline
int trace_ust_track_pid(struct ltt_ust_session *session, int pid)
{
	return 0;
}
static inline
int trace_ust_untrack_pid(struct ltt_ust_session *session, int pid)
{
	return 0;
}
static inline
int trace_ust_pid_tracker_lookup(struct ltt_ust_session *session, int pid)
{
	return 0;
}
static inline
ssize_t trace_ust_list_tracker_pids(struct ltt_ust_session *session,
		int32_t **_pids)
{
	return -1;
}
#endif /* HAVE_LIBLTTNG_UST_CTL */

#endif /* _LTT_TRACE_UST_H */
