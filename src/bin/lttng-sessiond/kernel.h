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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef _LTT_KERNEL_CTL_H
#define _LTT_KERNEL_CTL_H

#include "session.h"
#include "trace-kernel.h"

/*
 * Default size for the event list when kernel_list_events is called. This size
 * value is based on the initial LTTng 2.0 version set of tracepoints.
 *
 * This is NOT an upper bound because if the real event list size is bigger,
 * dynamic reallocation is performed.
 */
#define KERNEL_EVENT_INIT_LIST_SIZE 64

int kernel_add_channel_context(struct ltt_kernel_channel *chan,
		struct lttng_kernel_context *ctx);
int kernel_add_event_context(struct ltt_kernel_event *event,
		struct lttng_kernel_context *ctx);
int kernel_create_session(struct ltt_session *session, int tracer_fd);
int kernel_create_channel(struct ltt_kernel_session *session,
		struct lttng_channel *chan, char *path);
int kernel_create_event(struct lttng_event *ev, struct ltt_kernel_channel *channel);
int kernel_disable_channel(struct ltt_kernel_channel *chan);
int kernel_disable_event(struct ltt_kernel_event *event);
int kernel_enable_event(struct ltt_kernel_event *event);
int kernel_enable_channel(struct ltt_kernel_channel *chan);
int kernel_open_metadata(struct ltt_kernel_session *session, char *path);
int kernel_open_metadata_stream(struct ltt_kernel_session *session);
int kernel_open_channel_stream(struct ltt_kernel_channel *channel);
int kernel_flush_buffer(struct ltt_kernel_channel *channel);
int kernel_metadata_flush_buffer(int fd);
int kernel_start_session(struct ltt_kernel_session *session);
int kernel_stop_session(struct ltt_kernel_session *session);
ssize_t kernel_list_events(int tracer_fd, struct lttng_event **event_list);
void kernel_wait_quiescent(int fd);
int kernel_calibrate(int fd, struct lttng_kernel_calibrate *calibrate);
int kernel_validate_version(int tracer_fd);

int init_kernel_workarounds(void);

#endif /* _LTT_KERNEL_CTL_H */
