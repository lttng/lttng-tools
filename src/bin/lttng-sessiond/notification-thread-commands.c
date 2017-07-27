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

#include <lttng/trigger/trigger.h>
#include <lttng/lttng-error.h>
#include "notification-thread.h"
#include "notification-thread-commands.h"
#include <common/error.h>
#include <unistd.h>
#include <stdint.h>
#include <inttypes.h>

static
void init_notification_thread_command(struct notification_thread_command *cmd)
{
	memset(cmd, 0, sizeof(*cmd));
	CDS_INIT_LIST_HEAD(&cmd->cmd_list_node);
	lttng_waiter_init(&cmd->reply_waiter);
}

static
int run_command_wait(struct notification_thread_handle *handle,
		struct notification_thread_command *cmd)
{
	int ret;
	uint64_t notification_counter = 1;

	pthread_mutex_lock(&handle->cmd_queue.lock);
	/* Add to queue. */
	cds_list_add_tail(&cmd->cmd_list_node,
			&handle->cmd_queue.list);
	/* Wake-up thread. */
	ret = write(lttng_pipe_get_writefd(handle->cmd_queue.event_pipe),
			&notification_counter, sizeof(notification_counter));
	if (ret < 0) {
		PERROR("write to notification thread's queue event fd");
		/*
		 * Remove the command from the list so the notification
		 * thread does not process it.
		 */
		cds_list_del(&cmd->cmd_list_node);
		goto error_unlock_queue;
	}
	pthread_mutex_unlock(&handle->cmd_queue.lock);

	lttng_waiter_wait(&cmd->reply_waiter);
	return 0;
error_unlock_queue:
	pthread_mutex_unlock(&handle->cmd_queue.lock);
	return -1;
}

enum lttng_error_code notification_thread_command_register_trigger(
		struct notification_thread_handle *handle,
		struct lttng_trigger *trigger)
{
	int ret;
	enum lttng_error_code ret_code;
	struct notification_thread_command cmd;

	init_notification_thread_command(&cmd);

	cmd.type = NOTIFICATION_COMMAND_TYPE_REGISTER_TRIGGER;
	cmd.parameters.trigger = trigger;

	ret = run_command_wait(handle, &cmd);
	if (ret) {
		ret_code = LTTNG_ERR_UNK;
		goto end;
	}
	ret_code = cmd.reply_code;
end:
	return ret_code;
}

enum lttng_error_code notification_thread_command_unregister_trigger(
		struct notification_thread_handle *handle,
		struct lttng_trigger *trigger)
{
	int ret;
	enum lttng_error_code ret_code;
	struct notification_thread_command cmd;

	init_notification_thread_command(&cmd);

	cmd.type = NOTIFICATION_COMMAND_TYPE_UNREGISTER_TRIGGER;
	cmd.parameters.trigger = trigger;

	ret = run_command_wait(handle, &cmd);
	if (ret) {
		ret_code = LTTNG_ERR_UNK;
		goto end;
	}
	ret_code = cmd.reply_code;
end:
	return ret_code;
}

enum lttng_error_code notification_thread_command_add_channel(
		struct notification_thread_handle *handle,
		char *session_name, uid_t uid, gid_t gid,
		char *channel_name, uint64_t key,
		enum lttng_domain_type domain, uint64_t capacity)
{
	int ret;
	enum lttng_error_code ret_code;
	struct notification_thread_command cmd;

	init_notification_thread_command(&cmd);

	cmd.type = NOTIFICATION_COMMAND_TYPE_ADD_CHANNEL;
	cmd.parameters.add_channel.session_name = session_name;
	cmd.parameters.add_channel.uid = uid;
	cmd.parameters.add_channel.gid = gid;
	cmd.parameters.add_channel.channel_name = channel_name;
	cmd.parameters.add_channel.key.key = key;
	cmd.parameters.add_channel.key.domain = domain;
	cmd.parameters.add_channel.capacity = capacity;

	ret = run_command_wait(handle, &cmd);
	if (ret) {
		ret_code = LTTNG_ERR_UNK;
		goto end;
	}
	ret_code = cmd.reply_code;
end:
	return ret_code;
}

enum lttng_error_code notification_thread_command_remove_channel(
		struct notification_thread_handle *handle,
		uint64_t key, enum lttng_domain_type domain)
{
	int ret;
	enum lttng_error_code ret_code;
	struct notification_thread_command cmd;

	init_notification_thread_command(&cmd);

	cmd.type = NOTIFICATION_COMMAND_TYPE_REMOVE_CHANNEL;
	cmd.parameters.remove_channel.key = key;
	cmd.parameters.remove_channel.domain = domain;

	ret = run_command_wait(handle, &cmd);
	if (ret) {
		ret_code = LTTNG_ERR_UNK;
		goto end;
	}
	ret_code = cmd.reply_code;
end:
	return ret_code;
}

void notification_thread_command_quit(
		struct notification_thread_handle *handle)
{
	int ret;
	struct notification_thread_command cmd;

	init_notification_thread_command(&cmd);

	cmd.type = NOTIFICATION_COMMAND_TYPE_QUIT;
	ret = run_command_wait(handle, &cmd);
	assert(!ret && cmd.reply_code == LTTNG_OK);
}
