/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
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

#include <config.h>
#include <limits.h>
#include <urcu/list.h>

#include <lttng/lttng.h>
#include <common/hashtable/hashtable.h>
#include <common/defaults.h>

#include "consumer.h"
#include "ust-ctl.h"

/* UST Stream list */
struct ltt_ust_stream_list {
	unsigned int count;
	struct cds_list_head head;
};

/* Context hash table nodes */
struct ltt_ust_context {
	struct lttng_ust_context ctx;
	struct lttng_ht_node_ulong node;
};

/* UST event */
struct ltt_ust_event {
	unsigned int enabled;
	struct lttng_ust_event attr;
	struct lttng_ht_node_str node;
	struct lttng_ust_filter_bytecode *filter;
};

/* UST stream */
struct ltt_ust_stream {
	int handle;
	char pathname[PATH_MAX];
	/* Format is %s_%d respectively channel name and CPU number. */
	char name[DEFAULT_STREAM_NAME_LEN];
	struct lttng_ust_object_data *obj;
	/* Using a list of streams to keep order. */
	struct cds_list_head list;
};

/* UST channel */
struct ltt_ust_channel {
	unsigned int enabled;
	char name[LTTNG_UST_SYM_NAME_LEN];
	char pathname[PATH_MAX];
	struct lttng_ust_channel attr;
	struct lttng_ht *ctx;
	struct lttng_ht *events;
	struct lttng_ht_node_str node;
};

/* UST Metadata */
struct ltt_ust_metadata {
	int handle;
	struct lttng_ust_object_data *obj;
	char pathname[PATH_MAX];              /* Trace file path name */
	struct lttng_ust_channel attr;
	struct lttng_ust_object_data *stream_obj;
};

/* UST domain global (LTTNG_DOMAIN_UST) */
struct ltt_ust_domain_global {
	struct lttng_ht *channels;
};

/* UST domain pid (LTTNG_DOMAIN_UST_PID) */
struct ltt_ust_domain_pid {
	pid_t pid;
	struct lttng_ht *channels;
	struct lttng_ht_node_ulong node;
};

/* UST domain exec name (LTTNG_DOMAIN_UST_EXEC_NAME) */
struct ltt_ust_domain_exec {
	char exec_name[LTTNG_UST_SYM_NAME_LEN];
	struct lttng_ht *channels;
	struct lttng_ht_node_str node;
};

/* UST session */
struct ltt_ust_session {
	int id;    /* Unique identifier of session */
	int start_trace;
	char pathname[PATH_MAX];
	struct ltt_ust_domain_global domain_global;
	/*
	 * Those two hash tables contains data for a specific UST domain and each
	 * contains a HT of channels. See ltt_ust_domain_exec and
	 * ltt_ust_domain_pid data structures.
	 */
	struct lttng_ht *domain_pid;
	struct lttng_ht *domain_exec;
	/* UID/GID of the user owning the session */
	uid_t uid;
	gid_t gid;
	/*
	 * Two consumer_output object are needed where one is for the current
	 * output object and the second one is the temporary object used to store
	 * URI being set by the lttng_set_consumer_uri call. Once
	 * lttng_enable_consumer is called, the two pointers are swapped.
	 */
	struct consumer_output *consumer;
	struct consumer_output *tmp_consumer;
	/* Sequence number for filters so the tracer knows the ordering. */
	uint64_t filter_seq_num;
};

#ifdef HAVE_LIBLTTNG_UST_CTL

/*
 * Lookup functions. NULL is returned if not found.
 */
struct ltt_ust_event *trace_ust_find_event_by_name(struct lttng_ht *ht,
		char *name);
struct ltt_ust_channel *trace_ust_find_channel_by_name(struct lttng_ht *ht,
		char *name);

/*
 * Create functions malloc() the data structure.
 */
struct ltt_ust_session *trace_ust_create_session(char *path,
		unsigned int session_id, struct lttng_domain *domain);
struct ltt_ust_channel *trace_ust_create_channel(struct lttng_channel *attr,
		char *path);
struct ltt_ust_event *trace_ust_create_event(struct lttng_event *ev);
struct ltt_ust_metadata *trace_ust_create_metadata(char *path);
struct ltt_ust_context *trace_ust_create_context(
		struct lttng_event_context *ctx);

/*
 * Destroy functions free() the data structure and remove from linked list if
 * it's applies.
 */
void trace_ust_destroy_session(struct ltt_ust_session *session);
void trace_ust_destroy_metadata(struct ltt_ust_metadata *metadata);
void trace_ust_destroy_channel(struct ltt_ust_channel *channel);
void trace_ust_destroy_event(struct ltt_ust_event *event);

#else /* HAVE_LIBLTTNG_UST_CTL */

static inline
struct ltt_ust_event *trace_ust_find_event_by_name(struct lttng_ht *ht,
		char *name)
{
	return NULL;
}

static inline
struct ltt_ust_channel *trace_ust_find_channel_by_name(struct lttng_ht *ht,
		char *name)
{
	return NULL;
}

static inline
struct ltt_ust_session *trace_ust_create_session(char *path, pid_t pid,
		struct lttng_domain *domain)
{
	return NULL;
}
static inline
struct ltt_ust_channel *trace_ust_create_channel(struct lttng_channel *attr,
		char *path)
{
	return NULL;
}
static inline
struct ltt_ust_event *trace_ust_create_event(struct lttng_event *ev)
{
	return NULL;
}
static inline
struct ltt_ust_metadata *trace_ust_create_metadata(char *path)
{
	return NULL;
}

static inline
void trace_ust_destroy_session(struct ltt_ust_session *session)
{
}

static inline
void trace_ust_destroy_metadata(struct ltt_ust_metadata *metadata)
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

#endif /* HAVE_LIBLTTNG_UST_CTL */

#endif /* _LTT_TRACE_UST_H */
