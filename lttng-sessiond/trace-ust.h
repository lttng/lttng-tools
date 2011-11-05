/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; only version 2
 * of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef _LTT_TRACE_UST_H
#define _LTT_TRACE_UST_H

#include <config.h>
#include <limits.h>
#include <urcu.h>
#include <urcu/list.h>
#include <lttng/lttng.h>

#include "ust-ctl.h"

#include "../hashtable/rculfhash.h"

/* UST Stream list */
struct ltt_ust_stream_list {
	unsigned int count;
	struct cds_list_head head;
};

/* Context hash table nodes */
struct ltt_ust_context {
	struct lttng_ust_context ctx;
	struct cds_lfht_node node;
};

/* UST event */
struct ltt_ust_event {
	struct lttng_ust_event attr;
	struct cds_lfht *ctx;
	struct cds_lfht_node node;
};

/* UST stream */
struct ltt_ust_stream {
	int handle;
	char pathname[PATH_MAX];
	struct lttng_ust_object_data *obj;
	/* Using a list of streams to keep order. */
	struct cds_list_head list;
};

/* UST channel */
struct ltt_ust_channel {
	char name[LTTNG_UST_SYM_NAME_LEN];
	char pathname[PATH_MAX];
	struct lttng_ust_channel attr;
	struct cds_lfht *ctx;
	struct cds_lfht *events;
	struct cds_lfht_node node;
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
	struct cds_lfht *channels;
};

/* UST domain pid (LTTNG_DOMAIN_UST_PID) */
struct ltt_ust_domain_pid {
	pid_t pid;
	struct cds_lfht *channels;
	struct cds_lfht_node node;
};

/* UST domain exec name (LTTNG_DOMAIN_UST_EXEC_NAME) */
struct ltt_ust_domain_exec {
	char exec_name[LTTNG_UST_SYM_NAME_LEN];
	struct cds_lfht *channels;
	struct cds_lfht_node node;
};

/* UST session */
struct ltt_ust_session {
	int uid;   /* Unique identifier of session */
	int consumer_fds_sent;
	int consumer_fd;
	char pathname[PATH_MAX];
	struct ltt_ust_domain_global domain_global;
	/*
	 * Those two hash tables contains data for a specific UST domain and each
	 * contains a HT of channels. See ltt_ust_domain_exec and
	 * ltt_ust_domain_pid data structures.
	 */
	struct cds_lfht *domain_pid;
	struct cds_lfht *domain_exec;
};

#ifdef HAVE_LIBLTTNG_UST_CTL

/*
 * Lookup functions. NULL is returned if not found.
 */
struct ltt_ust_event *trace_ust_find_event_by_name(struct cds_lfht *ht,
		char *name);
struct ltt_ust_channel *trace_ust_find_channel_by_name(struct cds_lfht *ht,
		char *name);

/*
 * Create functions malloc() the data structure.
 */
struct ltt_ust_session *trace_ust_create_session(char *path, unsigned int uid,
		struct lttng_domain *domain);
struct ltt_ust_channel *trace_ust_create_channel(struct lttng_channel *attr,
		char *path);
struct ltt_ust_event *trace_ust_create_event(struct lttng_event *ev);
struct ltt_ust_metadata *trace_ust_create_metadata(char *path);

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
struct ltt_ust_event *trace_ust_find_event_by_name(struct cds_lfht *ht,
		char *name)
{
	return NULL;
}

static inline
struct ltt_ust_channel *trace_ust_find_channel_by_name(struct cds_lfht *ht,
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

#endif /* HAVE_LIBLTTNG_UST_CTL */

#endif /* _LTT_TRACE_UST_H */
