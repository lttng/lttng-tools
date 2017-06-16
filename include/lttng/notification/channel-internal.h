/*
 * Copyright (C) 2017 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License, version 2.1 only,
 * as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef LTTNG_NOTIFICATION_CHANNEL_INTERNAL_H
#define LTTNG_NOTIFICATION_CHANNEL_INTERNAL_H

#include <lttng/notification/channel.h>
#include <common/macros.h>
#include <common/dynamic-buffer.h>
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <urcu/list.h>

#define LTTNG_NOTIFICATION_CHANNEL_VERSION_MAJOR 1
#define LTTNG_NOTIFICATION_CHANNEL_VERSION_MINOR 0

enum lttng_notification_channel_message_type {
	LTTNG_NOTIFICATION_CHANNEL_MESSAGE_TYPE_UNKNOWN = -1,
	LTTNG_NOTIFICATION_CHANNEL_MESSAGE_TYPE_HANDSHAKE = 0,
	LTTNG_NOTIFICATION_CHANNEL_MESSAGE_TYPE_SUBSCRIBE = 1,
	LTTNG_NOTIFICATION_CHANNEL_MESSAGE_TYPE_UNSUBSCRIBE = 2,
	LTTNG_NOTIFICATION_CHANNEL_MESSAGE_TYPE_COMMAND_REPLY = 3,
	LTTNG_NOTIFICATION_CHANNEL_MESSAGE_TYPE_NOTIFICATION = 4,
	LTTNG_NOTIFICATION_CHANNEL_MESSAGE_TYPE_NOTIFICATION_DROPPED = 5,
};

struct lttng_notification_channel_message {
	/* enum lttng_notification_channel_message_type */
	int8_t type;
	/* Size of the payload following this field. */
	uint32_t size;
	char payload[];
} LTTNG_PACKED;

struct lttng_notification_channel_command_handshake {
	uint8_t major;
	uint8_t minor;
} LTTNG_PACKED;

struct lttng_notification_channel_command_reply {
	/* enum lttng_notification_channel_status */
	int8_t status;
} LTTNG_PACKED;

struct pending_notification {
	/* NULL means "notification dropped". */
	struct lttng_notification *notification;
	struct cds_list_head node;
};

/*
 * The notification channel protocol is bidirectional and accomodates
 * synchronous and asynchronous communication modes:
 *
 *   - Synchronous: commands emitted by the client to which a reply is expected
 *     (e.g. subscribing/unsubscribing to conditions),
 *   - Asynchronous: notifications which are sent by the lttng_endpoint to the
 *     client as one of the subscribed condition has occurred.
 *
 * The nature of this hybrid communication mode means that asynchronous messages
 * (e.g. notifications) may be interleaved between synchronous messages (e.g. a
 * command and its reply).
 *
 * Notifications that are received between a command and its reply and enqueued
 * in the pending_notifications list.
 */
struct lttng_notification_channel {
	pthread_mutex_t lock;
	int socket;
	struct {
		/* Count of pending notifications. */
		unsigned int count;
		/* List of struct pending_notification. */
		struct cds_list_head list;
	} pending_notifications;
	struct lttng_dynamic_buffer reception_buffer;
	/* Sessiond notification protocol version. */
	struct {
		bool set;
		int8_t major, minor;
	} version;
};

#endif /* LTTNG_NOTIFICATION_CHANNEL_INTERNAL_H */
