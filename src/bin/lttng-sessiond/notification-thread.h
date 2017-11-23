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
	 * event_pipe must be WRITE(2) to signal that a new command
	 * has been enqueued.
	 */
	struct {
		struct lttng_pipe *event_pipe;
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

/**
 * This thread maintains an internal state associating clients and triggers.
 *
 * In order to speed-up and simplify queries, hash tables providing the
 * following associations are maintained:
 *
 *   - client_socket_ht: associate a client's socket (fd) to its "struct client"
 *             This hash table owns the "struct client" which must thus be
 *             disposed-of on removal from the hash table.
 *
 *   - channel_triggers_ht:
 *             associates a channel key to a list of
 *             struct lttng_trigger_list_nodes. The triggers in this list are
 *             those that have conditions that apply to this channel.
 *             A channel entry is only created when a channel is added; the
 *             list of triggers applying to such a channel is built at that
 *             moment.
 *             This hash table owns the list, but not the triggers themselves.
 *
 *   - channel_state_ht:
 *             associates a pair (channel key, channel domain) to its last
 *             sampled state received from the consumer daemon
 *             (struct channel_state).
 *             This previous sample is kept to implement edge-triggered
 *             conditions as we need to detect the state transitions.
 *             This hash table owns the channel state.
 *
 *   - notification_trigger_clients_ht:
 *             associates notification-emitting triggers to clients
 *             (struct notification_client_list) subscribed to those
 *             conditions.
 *             The condition's hash and match functions are used directly since
 *             all triggers in this hash table have the "notify" action.
 *             This hash table holds no ownership.
 *
 *   - channels_ht:
 *             associates a channel_key to a struct channel_info. The hash table
 *             holds the ownership of the struct channel_info.
 *
 *   - triggers_ht:
 *             associated a condition to a struct lttng_trigger_ht_element.
 *             The hash table holds the ownership of the
 *             lttng_trigger_ht_elements along with the triggers themselves.
 *
 * The thread reacts to the following internal events:
 *   1) creation of a tracing channel,
 *   2) destruction of a tracing channel,
 *   3) registration of a trigger,
 *   4) unregistration of a trigger,
 *   5) reception of a channel monitor sample from the consumer daemon.
 *
 * Events specific to notification-emitting triggers:
 *   6) connection of a notification client,
 *   7) disconnection of a notification client,
 *   8) subscription of a client to a conditions' notifications,
 *   9) unsubscription of a client from a conditions' notifications,
 *
 *
 * 1) Creation of a tracing channel
 *    - notification_trigger_clients_ht is traversed to identify
 *      triggers which apply to this new channel,
 *    - triggers identified are added to the channel_triggers_ht.
 *    - add channel to channels_ht
 *
 * 2) Destruction of a tracing channel
 *    - remove entry from channel_triggers_ht, releasing the list wrapper and
 *      elements,
 *    - remove entry from the channel_state_ht.
 *    - remove channel from channels_ht
 *
 * 3) Registration of a trigger
 *    - if the trigger's action is of type "notify",
 *      - traverse the list of conditions of every client to build a list of
 *        clients which have to be notified when this trigger's condition is met,
 *        - add list of clients (even if it is empty) to the
 *          notification_trigger_clients_ht,
 *    - add trigger to channel_triggers_ht (if applicable),
 *    - add trigger to triggers_ht
 *    - evaluate the trigger's condition right away to react if that condition
 *      is true from the beginning.
 *
 * 4) Unregistration of a trigger
 *    - if the trigger's action is of type "notify",
 *      - remove the trigger from the notification_trigger_clients_ht,
 *    - remove trigger from channel_triggers_ht (if applicable),
 *    - remove trigger from triggers_ht
 *
 * 5) Reception of a channel monitor sample from the consumer daemon
 *    - evaluate the conditions associated with the triggers found in
 *      the channel_triggers_ht,
 *      - if a condition evaluates to "true" and the condition is of type
 *        "notify", query the notification_trigger_clients_ht and send
 *        a notification to the clients.
 *
 * 6) Connection of a client
 *    - add client socket to the client_socket_ht.
 *
 * 7) Disconnection of a client
 *    - remove client socket from the client_socket_ht,
 *    - traverse all conditions to which the client is subscribed and remove
 *      the client from the notification_trigger_clients_ht.
 *
 * 8) Subscription of a client to a condition's notifications
 *    - Add the condition to the client's list of subscribed conditions,
 *    - Look-up notification_trigger_clients_ht and add the client to
 *      list of clients.
 *    - Evaluate the condition for the client that subscribed if the trigger
 *      was already registered.
 *
 * 9) Unsubscription of a client to a condition's notifications
 *    - Remove the condition from the client's list of subscribed conditions,
 *    - Look-up notification_trigger_clients_ht and remove the client
 *      from the list of clients.
 */
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
