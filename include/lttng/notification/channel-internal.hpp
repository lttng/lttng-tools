/*
 * Copyright (C) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_NOTIFICATION_CHANNEL_INTERNAL_H
#define LTTNG_NOTIFICATION_CHANNEL_INTERNAL_H

#include <common/macros.hpp>
#include <common/make-unique-wrapper.hpp>
#include <common/payload.hpp>

#include <lttng/notification/channel.h>

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <urcu/list.h>

/*
 * Protocol version change log:
 * - v1.0
 *   - Initial implementation of the notification channel protocol,
 *   - Supported conditions are LOW/HIGH buffer usage conditions,
 * - v1.1
 *   - New condition type "LTTNG_CONDITION_TYPE_SESSION_CONSUMED_SIZE" added,
 *   - New condition type "LTTNG_CONDITION_TYPE_SESSION_ROTATION_ONGOING" added,
 *   - New condition type "LTTNG_CONDITION_TYPE_SESSION_ROTATION_COMPLETED" added,
 */
#define LTTNG_NOTIFICATION_CHANNEL_VERSION_MAJOR 1
#define LTTNG_NOTIFICATION_CHANNEL_VERSION_MINOR 1

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
	/* Number of FDs sent. */
	uint32_t fds;
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
 * The notification channel protocol is bidirectional and accommodates
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
	using uptr = std::unique_ptr<
		lttng_notification_channel,
		lttng::memory::create_deleter_class<lttng_notification_channel,
						    lttng_notification_channel_destroy>::deleter>;

	pthread_mutex_t lock;
	int socket;
	struct {
		/* Count of pending notifications. */
		unsigned int count;
		/* List of struct pending_notification. */
		struct cds_list_head list;
	} pending_notifications;
	struct lttng_payload reception_payload;
	/* Sessiond notification protocol version. */
	struct {
		bool set;
		int8_t major, minor;
	} version;
};

#endif /* LTTNG_NOTIFICATION_CHANNEL_INTERNAL_H */
