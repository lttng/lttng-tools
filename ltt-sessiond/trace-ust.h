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

#include <limits.h>
#include <urcu/list.h>

#include <lttng/lttng.h>
#include <lttng-ust.h>

#include "traceable-app.h"

/*
 * UST session list.
 */
struct ltt_ust_session_list {
	unsigned int count;
	struct cds_list_head head;
};

/* UST event list */
struct ltt_ust_event_list {
	unsigned int count;
	struct cds_list_head head;
};

/* UST Channel list */
struct ltt_ust_channel_list {
	unsigned int count;
	struct cds_list_head head;
};

/* UST event */
struct ltt_ust_event {
	int handle;
	int enabled;
	struct lttng_ust_context *ctx;
	struct lttng_ust_event *event;
	struct cds_list_head list;
};

/* UST channel */
struct ltt_ust_channel {
	int handle;
	int enabled;
	char *name;
	char *trace_path;                   /* Trace file path name */
	struct lttng_ust_context *ctx;
	struct lttng_ust_channel *attr;
	struct ltt_ust_event_list events;
	struct cds_list_head list;
};

/* UST Metadata */
struct ltt_ust_metadata {
	int handle;
	char *trace_path;             /* Trace file path name */
	struct lttng_ust_channel *attr;
};

/* UST session */
struct ltt_ust_session {
	int handle;
	int enabled;
	int uconsumer_fds_sent;
	char *path;
	struct ltt_traceable_app *app;
	struct ltt_ust_metadata *metadata;
	struct ltt_ust_channel_list channels;
	struct cds_list_head list;
};

/*
 * Lookup functions. NULL is returned if not found.
 */
struct ltt_ust_event *trace_ust_get_event_by_name(
		char *name, struct ltt_ust_channel *channel);
struct ltt_ust_channel *trace_ust_get_channel_by_name(
		char *name, struct ltt_ust_session *session);
struct ltt_ust_session *trace_ust_get_session_by_pid(pid_t pid,
		struct ltt_ust_session_list *session_list);

/*
 * Create functions malloc() the data structure.
 */
struct ltt_ust_session *trace_ust_create_session(char *path, pid_t pid);
struct ltt_ust_channel *trace_ust_create_channel(char *name, char *path,
		struct lttng_ust_channel *attr);
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

#endif /* _LTT_TRACE_UST_H */
