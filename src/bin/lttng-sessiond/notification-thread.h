/*
 * Copyright (C) 2017 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
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

#ifndef NOTIFICATION_THREAD_H
#define NOTIFICATION_THREAD_H

#include <urcu/list.h>
#include <urcu.h>
#include <urcu/rculfhash.h>
#include <lttng/trigger/trigger.h>
#include <common/pipe.h>
#include <common/compat/poll.h>
#include <common/hashtable/hashtable.h>
#include <pthread.h>

struct notification_thread_handle {
	/*
	 * Queue of struct notification command.
	 * event_fd must be WRITE(2) to signal that a new command
	 * has been enqueued.
	 */
	struct {
		int event_fd;
		struct cds_list_head list;
		pthread_mutex_t lock;
	} cmd_queue;
	/*
	 * Read side of pipes used to receive channel status info collected
	 * by the various consumer daemons.
	 */
	struct {
		int ust32_consumer;
		int ust64_consumer;
		int kernel_consumer;
	} channel_monitoring_pipes;
};

struct notification_thread_state {
	int notification_channel_socket;
	struct lttng_poll_event events;
	struct cds_lfht *client_socket_ht;
	struct cds_lfht *channel_triggers_ht;
	struct cds_lfht *channel_state_ht;
	struct cds_lfht *notification_trigger_clients_ht;
	struct cds_lfht *channels_ht;
	struct cds_lfht *triggers_ht;
};

/* notification_thread_data takes ownership of the channel monitor pipes. */
struct notification_thread_handle *notification_thread_handle_create(
		struct lttng_pipe *ust32_channel_monitor_pipe,
		struct lttng_pipe *ust64_channel_monitor_pipe,
		struct lttng_pipe *kernel_channel_monitor_pipe);
void notification_thread_handle_destroy(
		struct notification_thread_handle *handle);

void *thread_notification(void *data);

#endif /* NOTIFICATION_THREAD_H */
