/*
 * SPDX-FileCopyrightText: 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "notification-thread-commands.hpp"
#include "notification-thread.hpp"

#include <common/error.hpp>

#include <lttng/lttng-error.h>
#include <lttng/trigger/trigger.h>

#include <inttypes.h>
#include <stdint.h>
#include <unistd.h>

notification_thread_command::notification_thread_command()
{
	CDS_INIT_LIST_HEAD(&cmd_list_node);
	/* memset is used since  */
	::memset(&parameters, 0, sizeof(parameters));
	::memset(&reply, 0, sizeof(reply));
}

static int run_command_wait(struct notification_thread_handle *handle,
			    struct notification_thread_command *cmd)
{
	int ret;
	uint64_t notification_counter = 1;

	lttng::synchro::waiter command_completion_waiter;
	cmd->command_completed_waker.emplace(command_completion_waiter.get_waker());

	pthread_mutex_lock(&handle->cmd_queue.lock);
	/* Add to queue. */
	cds_list_add_tail(&cmd->cmd_list_node, &handle->cmd_queue.list);
	/* Wake-up thread. */
	ret = lttng_write(
		handle->cmd_queue.event_fd, &notification_counter, sizeof(notification_counter));
	if (ret != sizeof(notification_counter)) {
		PERROR("write to notification thread's queue event fd");
		/*
		 * Remove the command from the list so the notification
		 * thread does not process it.
		 */
		cds_list_del(&cmd->cmd_list_node);
		goto error_unlock_queue;
	}
	pthread_mutex_unlock(&handle->cmd_queue.lock);

	command_completion_waiter.wait();
	;
	return 0;
error_unlock_queue:
	pthread_mutex_unlock(&handle->cmd_queue.lock);
	return -1;
}

static struct notification_thread_command *
notification_thread_command_copy(const struct notification_thread_command *original_cmd)
{
	struct notification_thread_command *new_cmd;

	try {
		new_cmd = new notification_thread_command;
	} catch (const std::bad_alloc& e) {
		ERR("Failed to allocate notification_thread_command: %s", e.what());
		return nullptr;
	}

	*new_cmd = *original_cmd;
	return new_cmd;
}

static int run_command_no_wait(struct notification_thread_handle *handle,
			       const struct notification_thread_command *in_cmd)
{
	int ret;
	uint64_t notification_counter = 1;
	struct notification_thread_command *new_cmd = notification_thread_command_copy(in_cmd);

	if (!new_cmd) {
		goto error;
	}
	new_cmd->is_async = true;

	pthread_mutex_lock(&handle->cmd_queue.lock);
	/* Add to queue. */
	cds_list_add_tail(&new_cmd->cmd_list_node, &handle->cmd_queue.list);
	/* Wake-up thread. */
	ret = lttng_write(
		handle->cmd_queue.event_fd, &notification_counter, sizeof(notification_counter));
	if (ret != sizeof(notification_counter)) {
		PERROR("write to notification thread's queue event fd");
		/*
		 * Remove the command from the list so the notification
		 * thread does not process it.
		 */
		cds_list_del(&new_cmd->cmd_list_node);
		goto error_unlock_queue;
	}

	pthread_mutex_unlock(&handle->cmd_queue.lock);
	return 0;
error_unlock_queue:

	delete new_cmd;
	pthread_mutex_unlock(&handle->cmd_queue.lock);
error:
	return -1;
}

enum lttng_error_code
notification_thread_command_register_trigger(struct notification_thread_handle *handle,
					     struct lttng_trigger *trigger,
					     bool is_trigger_anonymous)
{
	int ret;
	enum lttng_error_code ret_code;
	notification_thread_command cmd;

	LTTNG_ASSERT(trigger);

	cmd.type = NOTIFICATION_COMMAND_TYPE_REGISTER_TRIGGER;
	lttng_trigger_get(trigger);
	cmd.parameters.register_trigger.trigger = trigger;
	cmd.parameters.register_trigger.is_trigger_anonymous = is_trigger_anonymous;

	ret = run_command_wait(handle, &cmd);
	if (ret) {
		ret_code = LTTNG_ERR_UNK;
		goto end;
	}
	ret_code = cmd.reply_code;
end:
	return ret_code;
}

enum lttng_error_code
notification_thread_command_unregister_trigger(struct notification_thread_handle *handle,
					       const struct lttng_trigger *trigger)
{
	int ret;
	enum lttng_error_code ret_code;
	notification_thread_command cmd;

	cmd.type = NOTIFICATION_COMMAND_TYPE_UNREGISTER_TRIGGER;
	cmd.parameters.unregister_trigger.trigger = trigger;

	ret = run_command_wait(handle, &cmd);
	if (ret) {
		ret_code = LTTNG_ERR_UNK;
		goto end;
	}
	ret_code = cmd.reply_code;
end:
	return ret_code;
}

enum lttng_error_code
notification_thread_command_add_session(struct notification_thread_handle *handle,
					uint64_t session_id,
					const char *session_name,
					uid_t session_uid,
					gid_t session_gid)
{
	int ret;
	enum lttng_error_code ret_code;
	notification_thread_command cmd;

	cmd.type = NOTIFICATION_COMMAND_TYPE_ADD_SESSION;
	cmd.parameters.add_session.session_id = session_id;
	cmd.parameters.add_session.session_name = session_name;
	cmd.parameters.add_session.session_uid = session_uid;
	cmd.parameters.add_session.session_gid = session_gid;

	ret = run_command_wait(handle, &cmd);
	if (ret) {
		ret_code = LTTNG_ERR_UNK;
		goto end;
	}
	ret_code = cmd.reply_code;
end:
	return ret_code;
}

enum lttng_error_code
notification_thread_command_remove_session(struct notification_thread_handle *handle,
					   uint64_t session_id)
{
	int ret;
	enum lttng_error_code ret_code;
	notification_thread_command cmd;

	cmd.type = NOTIFICATION_COMMAND_TYPE_REMOVE_SESSION;
	cmd.parameters.remove_session.session_id = session_id;

	ret = run_command_wait(handle, &cmd);
	if (ret) {
		ret_code = LTTNG_ERR_UNK;
		goto end;
	}
	ret_code = cmd.reply_code;
end:
	return ret_code;
}

enum lttng_error_code
notification_thread_command_add_channel(struct notification_thread_handle *handle,
					uint64_t session_id,
					char *channel_name,
					uint64_t key,
					enum lttng_domain_type domain,
					uint64_t capacity)
{
	int ret;
	enum lttng_error_code ret_code;
	notification_thread_command cmd;

	cmd.type = NOTIFICATION_COMMAND_TYPE_ADD_CHANNEL;
	cmd.parameters.add_channel.session.id = session_id;
	cmd.parameters.add_channel.channel.name = channel_name;
	cmd.parameters.add_channel.channel.key = key;
	cmd.parameters.add_channel.channel.domain = domain;
	cmd.parameters.add_channel.channel.capacity = capacity;

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
	struct notification_thread_handle *handle, uint64_t key, enum lttng_domain_type domain)
{
	int ret;
	enum lttng_error_code ret_code;
	notification_thread_command cmd;

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

enum lttng_error_code
notification_thread_command_session_rotation_ongoing(struct notification_thread_handle *handle,
						     uint64_t session_id,
						     uint64_t trace_archive_chunk_id)
{
	int ret;
	enum lttng_error_code ret_code;
	notification_thread_command cmd;

	cmd.type = NOTIFICATION_COMMAND_TYPE_SESSION_ROTATION_ONGOING;
	cmd.parameters.session_rotation.session_id = session_id;
	cmd.parameters.session_rotation.trace_archive_chunk_id = trace_archive_chunk_id;

	ret = run_command_wait(handle, &cmd);
	if (ret) {
		ret_code = LTTNG_ERR_UNK;
		goto end;
	}
	ret_code = cmd.reply_code;
end:
	return ret_code;
}

enum lttng_error_code notification_thread_command_session_rotation_completed(
	struct notification_thread_handle *handle,
	uint64_t session_id,
	uint64_t trace_archive_chunk_id,
	struct lttng_trace_archive_location *location)
{
	int ret;
	enum lttng_error_code ret_code;
	notification_thread_command cmd;

	cmd.type = NOTIFICATION_COMMAND_TYPE_SESSION_ROTATION_COMPLETED;
	cmd.parameters.session_rotation.session_id = session_id;
	cmd.parameters.session_rotation.trace_archive_chunk_id = trace_archive_chunk_id;
	cmd.parameters.session_rotation.location = location;

	ret = run_command_wait(handle, &cmd);
	if (ret) {
		ret_code = LTTNG_ERR_UNK;
		goto end;
	}
	ret_code = cmd.reply_code;
end:
	return ret_code;
}

enum lttng_error_code
notification_thread_command_add_tracer_event_source(struct notification_thread_handle *handle,
						    int tracer_event_source_fd,
						    enum lttng_domain_type domain)
{
	int ret;
	enum lttng_error_code ret_code;
	notification_thread_command cmd;

	LTTNG_ASSERT(tracer_event_source_fd >= 0);

	cmd.type = NOTIFICATION_COMMAND_TYPE_ADD_TRACER_EVENT_SOURCE;
	cmd.parameters.tracer_event_source.tracer_event_source_fd = tracer_event_source_fd;
	cmd.parameters.tracer_event_source.domain = domain;

	ret = run_command_wait(handle, &cmd);
	if (ret) {
		ret_code = LTTNG_ERR_UNK;
		goto end;
	}

	ret_code = cmd.reply_code;
end:
	return ret_code;
}

enum lttng_error_code
notification_thread_command_remove_tracer_event_source(struct notification_thread_handle *handle,
						       int tracer_event_source_fd)
{
	int ret;
	enum lttng_error_code ret_code;
	notification_thread_command cmd;

	cmd.type = NOTIFICATION_COMMAND_TYPE_REMOVE_TRACER_EVENT_SOURCE;
	cmd.parameters.tracer_event_source.tracer_event_source_fd = tracer_event_source_fd;

	ret = run_command_wait(handle, &cmd);
	if (ret) {
		ret_code = LTTNG_ERR_UNK;
		goto end;
	}

	ret_code = cmd.reply_code;
end:
	return ret_code;
}

enum lttng_error_code notification_thread_command_list_triggers(
	struct notification_thread_handle *handle, uid_t uid, struct lttng_triggers **triggers)
{
	int ret;
	enum lttng_error_code ret_code;
	notification_thread_command cmd;

	LTTNG_ASSERT(handle);
	LTTNG_ASSERT(triggers);

	cmd.type = NOTIFICATION_COMMAND_TYPE_LIST_TRIGGERS;
	cmd.parameters.list_triggers.uid = uid;

	ret = run_command_wait(handle, &cmd);
	if (ret) {
		ret_code = LTTNG_ERR_UNK;
		goto end;
	}

	ret_code = cmd.reply_code;
	*triggers = cmd.reply.list_triggers.triggers;

end:
	return ret_code;
}

void notification_thread_command_quit(struct notification_thread_handle *handle)
{
	int ret;
	notification_thread_command cmd;

	cmd.type = NOTIFICATION_COMMAND_TYPE_QUIT;
	ret = run_command_wait(handle, &cmd);
	LTTNG_ASSERT(!ret && cmd.reply_code == LTTNG_OK);
}

int notification_thread_client_communication_update(
	struct notification_thread_handle *handle,
	notification_client_id id,
	enum client_transmission_status transmission_status)
{
	notification_thread_command cmd;

	cmd.type = NOTIFICATION_COMMAND_TYPE_CLIENT_COMMUNICATION_UPDATE;
	cmd.parameters.client_communication_update.id = id;
	cmd.parameters.client_communication_update.status = transmission_status;
	return run_command_no_wait(handle, &cmd);
}

enum lttng_error_code
notification_thread_command_get_trigger(struct notification_thread_handle *handle,
					const struct lttng_trigger *trigger,
					struct lttng_trigger **real_trigger)
{
	int ret;
	enum lttng_error_code ret_code;
	notification_thread_command cmd;

	cmd.type = NOTIFICATION_COMMAND_TYPE_GET_TRIGGER;
	cmd.parameters.get_trigger.trigger = trigger;
	ret = run_command_wait(handle, &cmd);
	if (ret) {
		ret_code = LTTNG_ERR_UNK;
		goto end;
	}

	ret_code = cmd.reply_code;
	*real_trigger = cmd.reply.get_trigger.trigger;

end:
	return ret_code;
}

/*
 * Takes ownership of the payload if present.
 */
struct lttng_event_notifier_notification *lttng_event_notifier_notification_create(
	uint64_t tracer_token, enum lttng_domain_type domain, char *payload, size_t payload_size)
{
	struct lttng_event_notifier_notification *notification = nullptr;

	LTTNG_ASSERT(domain != LTTNG_DOMAIN_NONE);
	LTTNG_ASSERT((payload && payload_size) || (!payload && !payload_size));

	notification = zmalloc<lttng_event_notifier_notification>();
	if (notification == nullptr) {
		ERR("Error allocating notification");
		goto end;
	}

	notification->tracer_token = tracer_token;
	notification->type = domain;
	notification->capture_buffer = payload;
	notification->capture_buf_size = payload_size;

end:
	return notification;
}

void lttng_event_notifier_notification_destroy(
	struct lttng_event_notifier_notification *notification)
{
	if (!notification) {
		return;
	}

	free(notification->capture_buffer);
	free(notification);
}
