/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
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

#ifndef _LTT_TRACE_H
#define _LTT_TRACE_H

#include "ltt-sessiond.h"
#include "session.h"
#include "lttng-kernel.h"

/* Kernel event list */
struct ltt_kernel_event_list {
	struct cds_list_head head;
};

/* Channel stream list */
struct ltt_kernel_stream_list {
	struct cds_list_head head;
};

/* Channel list */
struct ltt_kernel_channel_list {
	struct cds_list_head head;
};

/* Kernel event */
struct ltt_kernel_event {
	int fd;
	struct lttng_kernel_event *event;
	struct cds_list_head list;
};

/* Kernel channel */
struct ltt_kernel_channel {
	int fd;
	char *pathname;
	unsigned int stream_count;
	struct lttng_kernel_channel *channel;
	struct ltt_kernel_event_list events_list;
	struct ltt_kernel_stream_list stream_list;
	struct cds_list_head list;
};

/* Metadata */
struct ltt_kernel_metadata {
	int fd;
	char *pathname;
	struct lttng_kernel_channel *conf;
};

/* Channel stream */
struct ltt_kernel_stream {
	int fd;
	char *pathname;
	int state;
	struct cds_list_head list;
};

/* Kernel session */
struct ltt_kernel_session {
	int fd;
	int metadata_stream_fd;
	unsigned int channel_count;
	unsigned int stream_count_global;
	struct ltt_kernel_metadata *metadata;
	struct ltt_kernel_channel_list channel_list;
};

/* UST trace representation */
struct ltt_ust_trace {
	struct cds_list_head list;
	char name[NAME_MAX];
	int shmid;
	pid_t pid;
	struct cds_list_head markers;
};

struct ltt_ust_marker {
	struct cds_list_head list;
	char *name;
	char *channel;
};

int get_trace_count_per_session(struct ltt_session *session);
void get_traces_per_session(struct ltt_session *session, struct lttng_trace *traces);
int ust_create_trace(struct command_ctx *cmd_ctx);
int ust_start_trace(struct command_ctx *cmd_ctx);
int ust_stop_trace(struct command_ctx *cmd_ctx);

#endif /* _LTT_TRACE_H */
