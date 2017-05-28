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

#include <lttng/notification/notification-internal.h>
#include <lttng/notification/channel-internal.h>
#include <lttng/condition/condition-internal.h>
#include <lttng/endpoint.h>
#include <common/defaults.h>
#include <common/error.h>
#include <common/dynamic-buffer.h>
#include <common/utils.h>
#include <common/defaults.h>
#include <assert.h>
#include "lttng-ctl-helper.h"

static
int handshake(struct lttng_notification_channel *channel);

/*
 * Populates the reception buffer with the next complete message.
 * The caller must acquire the client's lock.
 */
static
int receive_message(struct lttng_notification_channel *channel)
{
	ssize_t ret;
	struct lttng_notification_channel_message msg;

	ret = lttng_dynamic_buffer_set_size(&channel->reception_buffer, 0);
	if (ret) {
		goto error;
	}

	ret = lttcomm_recv_unix_sock(channel->socket, &msg, sizeof(msg));
	if (ret <= 0) {
		ret = -1;
		goto error;
	}

	if (msg.size > DEFAULT_MAX_NOTIFICATION_CLIENT_MESSAGE_PAYLOAD_SIZE) {
		ret = -1;
		goto error;
	}

	/* Add message header at buffer's start. */
	ret = lttng_dynamic_buffer_append(&channel->reception_buffer, &msg,
			sizeof(msg));
	if (ret) {
		goto error;
	}

	/* Reserve space for the payload. */
	ret = lttng_dynamic_buffer_set_size(&channel->reception_buffer,
			channel->reception_buffer.size + msg.size);
	if (ret) {
		goto error;
	}

	/* Receive message payload. */
	ret = lttcomm_recv_unix_sock(channel->socket,
			channel->reception_buffer.data + sizeof(msg), msg.size);
	if (ret < (ssize_t) msg.size) {
		ret = -1;
		goto error;
	}
	ret = 0;
end:
	return ret;
error:
	if (lttng_dynamic_buffer_set_size(&channel->reception_buffer, 0)) {
		ret = -1;
	}
	goto end;
}

static
enum lttng_notification_channel_message_type get_current_message_type(
		struct lttng_notification_channel *channel)
{
	struct lttng_notification_channel_message *msg;

	assert(channel->reception_buffer.size >= sizeof(*msg));

	msg = (struct lttng_notification_channel_message *)
			channel->reception_buffer.data;
	return (enum lttng_notification_channel_message_type) msg->type;
}

static
struct lttng_notification *create_notification_from_current_message(
		struct lttng_notification_channel *channel)
{
	ssize_t ret;
	struct lttng_notification *notification = NULL;
	struct lttng_buffer_view view;

	if (channel->reception_buffer.size <=
			sizeof(struct lttng_notification_channel_message)) {
		goto end;
	}

	view = lttng_buffer_view_from_dynamic_buffer(&channel->reception_buffer,
			sizeof(struct lttng_notification_channel_message), -1);

	ret = lttng_notification_create_from_buffer(&view, &notification);
	if (ret != channel->reception_buffer.size -
			sizeof(struct lttng_notification_channel_message)) {
		lttng_notification_destroy(notification);
		notification = NULL;
		goto end;
	}
end:
	return notification;
}

struct lttng_notification_channel *lttng_notification_channel_create(
		struct lttng_endpoint *endpoint)
{
	int fd, ret;
	bool is_in_tracing_group = false, is_root = false;
	char *sock_path = NULL;
	struct lttng_notification_channel *channel = NULL;

	if (!endpoint ||
			endpoint != lttng_session_daemon_notification_endpoint) {
		goto end;
	}

	sock_path = zmalloc(LTTNG_PATH_MAX);
	if (!sock_path) {
		goto end;
	}

	channel = zmalloc(sizeof(struct lttng_notification_channel));
	if (!channel) {
		goto end;
	}
	channel->socket = -1;
	pthread_mutex_init(&channel->lock, NULL);
	lttng_dynamic_buffer_init(&channel->reception_buffer);
	CDS_INIT_LIST_HEAD(&channel->pending_notifications.list);

	is_root = (getuid() == 0);
	if (!is_root) {
		is_in_tracing_group = lttng_check_tracing_group();
	}

	if (is_root || is_in_tracing_group) {
		lttng_ctl_copy_string(sock_path,
				DEFAULT_GLOBAL_NOTIFICATION_CHANNEL_UNIX_SOCK,
				LTTNG_PATH_MAX);
		ret = lttcomm_connect_unix_sock(sock_path);
		if (ret >= 0) {
			fd = ret;
			goto set_fd;
		}
	}

	/* Fallback to local session daemon. */
	ret = snprintf(sock_path, LTTNG_PATH_MAX,
			DEFAULT_HOME_NOTIFICATION_CHANNEL_UNIX_SOCK,
			utils_get_home_dir());
	if (ret < 0 || ret >= LTTNG_PATH_MAX) {
		goto error;
	}

	ret = lttcomm_connect_unix_sock(sock_path);
	if (ret < 0) {
		goto error;
	}
	fd = ret;

set_fd:
	channel->socket = fd;

	ret = handshake(channel);
	if (ret) {
		goto error;
	}
end:
	free(sock_path);
	return channel;
error:
	lttng_notification_channel_destroy(channel);
	channel = NULL;
	goto end;
}

enum lttng_notification_channel_status
lttng_notification_channel_get_next_notification(
		struct lttng_notification_channel *channel,
		struct lttng_notification **_notification)
{
	int ret;
	struct lttng_notification *notification = NULL;
	enum lttng_notification_channel_status status =
			LTTNG_NOTIFICATION_CHANNEL_STATUS_OK;

	if (!channel || !_notification) {
		status = LTTNG_NOTIFICATION_CHANNEL_STATUS_INVALID;
		goto end;
	}

	if (channel->pending_notifications.count) {
		struct pending_notification *pending_notification;

		assert(!cds_list_empty(&channel->pending_notifications.list));

		/* Deliver one of the pending notifications. */
		pending_notification = cds_list_first_entry(
				&channel->pending_notifications.list,
				struct pending_notification,
				node);
		notification = pending_notification->notification;
		if (!notification) {
			status = LTTNG_NOTIFICATION_CHANNEL_STATUS_NOTIFICATIONS_DROPPED;
		}
		cds_list_del(&pending_notification->node);
		channel->pending_notifications.count--;
		free(pending_notification);
		goto end;
	}

	pthread_mutex_lock(&channel->lock);

	ret = receive_message(channel);
	if (ret) {
		status = LTTNG_NOTIFICATION_CHANNEL_STATUS_ERROR;
		goto end_unlock;
	}

	switch (get_current_message_type(channel)) {
	case LTTNG_NOTIFICATION_CHANNEL_MESSAGE_TYPE_NOTIFICATION:
		notification = create_notification_from_current_message(
				channel);
		if (!notification) {
			status = LTTNG_NOTIFICATION_CHANNEL_STATUS_ERROR;
			goto end_unlock;
		}
		break;
	case LTTNG_NOTIFICATION_CHANNEL_MESSAGE_TYPE_NOTIFICATION_DROPPED:
		/* No payload to consume. */
		status = LTTNG_NOTIFICATION_CHANNEL_STATUS_NOTIFICATIONS_DROPPED;
		break;
	default:
		/* Protocol error. */
		status = LTTNG_NOTIFICATION_CHANNEL_STATUS_ERROR;
		goto end_unlock;
	}

end_unlock:
	pthread_mutex_unlock(&channel->lock);
end:
	if (_notification) {
		*_notification = notification;
	}
	return status;
}

static
int enqueue_dropped_notification(
		struct lttng_notification_channel *channel)
{
	int ret = 0;
	struct pending_notification *pending_notification;
	struct cds_list_head *last_element =
			channel->pending_notifications.list.prev;

	pending_notification = caa_container_of(last_element,
			struct pending_notification, node);
	if (!pending_notification->notification) {
		/*
		 * The last enqueued notification indicates dropped
		 * notifications; there is nothing to do as we group
		 * dropped notifications together.
		 */
		goto end;
	}

	if (channel->pending_notifications.count >=
			DEFAULT_CLIENT_MAX_QUEUED_NOTIFICATIONS_COUNT &&
			pending_notification->notification) {
		/*
		 * Discard the last enqueued notification to indicate
		 * that notifications were dropped at this point.
		 */
		lttng_notification_destroy(
				pending_notification->notification);
		pending_notification->notification = NULL;
		goto end;
	}

	pending_notification = zmalloc(sizeof(*pending_notification));
	if (!pending_notification) {
		ret = -1;
		goto end;
	}
	CDS_INIT_LIST_HEAD(&pending_notification->node);
	cds_list_add(&pending_notification->node,
			&channel->pending_notifications.list);
	channel->pending_notifications.count++;
end:
	return ret;
}

static
int enqueue_notification_from_current_message(
		struct lttng_notification_channel *channel)
{
	int ret = 0;
	struct lttng_notification *notification;
	struct pending_notification *pending_notification;

	if (channel->pending_notifications.count >=
			DEFAULT_CLIENT_MAX_QUEUED_NOTIFICATIONS_COUNT) {
		/* Drop the notification. */
		ret = enqueue_dropped_notification(channel);
		goto end;
	}

	pending_notification = zmalloc(sizeof(*pending_notification));
	if (!pending_notification) {
		ret = -1;
		goto error;
	}
	CDS_INIT_LIST_HEAD(&pending_notification->node);

	notification = create_notification_from_current_message(channel);
	if (!notification) {
		ret = -1;
		goto error;
	}

	pending_notification->notification = notification;
	cds_list_add(&pending_notification->node,
			&channel->pending_notifications.list);
	channel->pending_notifications.count++;
end:
	return ret;
error:
	free(pending_notification);
	goto end;
}

static
int receive_command_reply(struct lttng_notification_channel *channel,
		enum lttng_notification_channel_status *status)
{
	int ret;
	struct lttng_notification_channel_command_reply *reply;

	while (true) {
		enum lttng_notification_channel_message_type msg_type;

		ret = receive_message(channel);
		if (ret) {
			goto end;
		}

		msg_type = get_current_message_type(channel);
		switch (msg_type) {
		case LTTNG_NOTIFICATION_CHANNEL_MESSAGE_TYPE_COMMAND_REPLY:
			goto exit_loop;
		case LTTNG_NOTIFICATION_CHANNEL_MESSAGE_TYPE_NOTIFICATION:
			ret = enqueue_notification_from_current_message(
					channel);
			if (ret) {
				goto end;
			}
			break;
		case LTTNG_NOTIFICATION_CHANNEL_MESSAGE_TYPE_NOTIFICATION_DROPPED:
			ret = enqueue_dropped_notification(channel);
			if (ret) {
				goto end;
			}
			break;
		case LTTNG_NOTIFICATION_CHANNEL_MESSAGE_TYPE_HANDSHAKE:
		{
			struct lttng_notification_channel_command_handshake *handshake;

			handshake = (struct lttng_notification_channel_command_handshake *)
					(channel->reception_buffer.data +
					sizeof(struct lttng_notification_channel_message));
			channel->version.major = handshake->major;
			channel->version.minor = handshake->minor;
			channel->version.set = true;
			break;
		}
		default:
			ret = -1;
			goto end;
		}
	}

exit_loop:
	if (channel->reception_buffer.size <
			(sizeof(struct lttng_notification_channel_message) +
			sizeof(*reply))) {
		/* Invalid message received. */
		ret = -1;
		goto end;
	}

	reply = (struct lttng_notification_channel_command_reply *)
			(channel->reception_buffer.data +
			sizeof(struct lttng_notification_channel_message));
	*status = (enum lttng_notification_channel_status) reply->status;
end:
	return ret;
}

static
int handshake(struct lttng_notification_channel *channel)
{
	ssize_t ret;
	enum lttng_notification_channel_status status =
			LTTNG_NOTIFICATION_CHANNEL_STATUS_OK;
	struct lttng_notification_channel_command_handshake handshake = {
		.major = LTTNG_NOTIFICATION_CHANNEL_VERSION_MAJOR,
		.minor = LTTNG_NOTIFICATION_CHANNEL_VERSION_MINOR,
	};
	struct lttng_notification_channel_message msg_header = {
		.type = LTTNG_NOTIFICATION_CHANNEL_MESSAGE_TYPE_HANDSHAKE,
		.size = sizeof(handshake),
	};
	char send_buffer[sizeof(msg_header) + sizeof(handshake)];

	memcpy(send_buffer, &msg_header, sizeof(msg_header));
	memcpy(send_buffer + sizeof(msg_header), &handshake, sizeof(handshake));

	pthread_mutex_lock(&channel->lock);

	ret = lttcomm_send_creds_unix_sock(channel->socket, send_buffer,
			sizeof(send_buffer));
	if (ret < 0) {
		goto end_unlock;
	}

	/* Receive handshake info from the sessiond. */
	ret = receive_command_reply(channel, &status);
	if (ret < 0) {
		goto end_unlock;
	}

	if (!channel->version.set) {
		ret = -1;
		goto end_unlock;
	}

	if (channel->version.major != LTTNG_NOTIFICATION_CHANNEL_VERSION_MAJOR) {
		ret = -1;
		goto end_unlock;
	}

end_unlock:
	pthread_mutex_unlock(&channel->lock);
	return ret;
}

static
enum lttng_notification_channel_status send_condition_command(
		struct lttng_notification_channel *channel,
		enum lttng_notification_channel_message_type type,
		const struct lttng_condition *condition)
{
	int socket;
	ssize_t command_size, ret;
	enum lttng_notification_channel_status status =
			LTTNG_NOTIFICATION_CHANNEL_STATUS_OK;
	char *command_buffer = NULL;
	struct lttng_notification_channel_message cmd_message = {
		.type = type,
	};

	if (!channel) {
		status = LTTNG_NOTIFICATION_CHANNEL_STATUS_INVALID;
		goto end;
	}

	assert(type == LTTNG_NOTIFICATION_CHANNEL_MESSAGE_TYPE_SUBSCRIBE ||
		type == LTTNG_NOTIFICATION_CHANNEL_MESSAGE_TYPE_UNSUBSCRIBE);

	pthread_mutex_lock(&channel->lock);
	socket = channel->socket;
	if (!lttng_condition_validate(condition)) {
		status = LTTNG_NOTIFICATION_CHANNEL_STATUS_INVALID;
		goto end_unlock;
	}

	ret = lttng_condition_serialize(condition, NULL);
	if (ret < 0) {
		status = LTTNG_NOTIFICATION_CHANNEL_STATUS_INVALID;
		goto end_unlock;
	}
	assert(ret < UINT32_MAX);
	cmd_message.size = (uint32_t) ret;
	command_size = ret + sizeof(
			struct lttng_notification_channel_message);
	command_buffer = zmalloc(command_size);
	if (!command_buffer) {
		goto end_unlock;
	}

	memcpy(command_buffer, &cmd_message, sizeof(cmd_message));
	ret = lttng_condition_serialize(condition,
			command_buffer + sizeof(cmd_message));
	if (ret < 0) {
		goto end_unlock;
	}

	ret = lttcomm_send_unix_sock(socket, command_buffer, command_size);
	if (ret < 0) {
		status = LTTNG_NOTIFICATION_CHANNEL_STATUS_ERROR;
		goto end_unlock;
	}

	ret = receive_command_reply(channel, &status);
	if (ret < 0) {
		status = LTTNG_NOTIFICATION_CHANNEL_STATUS_ERROR;
		goto end_unlock;
	}
end_unlock:
	pthread_mutex_unlock(&channel->lock);
end:
	free(command_buffer);
	return status;
}

enum lttng_notification_channel_status lttng_notification_channel_subscribe(
		struct lttng_notification_channel *channel,
		const struct lttng_condition *condition)
{
	return send_condition_command(channel,
			LTTNG_NOTIFICATION_CHANNEL_MESSAGE_TYPE_SUBSCRIBE,
			condition);
}

enum lttng_notification_channel_status lttng_notification_channel_unsubscribe(
		struct lttng_notification_channel *channel,
		const struct lttng_condition *condition)
{
	return send_condition_command(channel,
			LTTNG_NOTIFICATION_CHANNEL_MESSAGE_TYPE_UNSUBSCRIBE,
			condition);
}

void lttng_notification_channel_destroy(
		struct lttng_notification_channel *channel)
{
	if (!channel) {
		return;
	}

	if (channel->socket >= 0) {
		(void) lttcomm_close_unix_sock(channel->socket);
	}
	pthread_mutex_destroy(&channel->lock);
	lttng_dynamic_buffer_reset(&channel->reception_buffer);
	free(channel);
}
