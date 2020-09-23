/*
 * Copyright (C) 2020 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "action-executor.h"
#include "cmd.h"
#include "health-sessiond.h"
#include "lttng-sessiond.h"
#include "notification-thread-internal.h"
#include "session.h"
#include "thread.h"
#include <common/macros.h>
#include <common/optional.h>
#include <lttng/action/action-internal.h>
#include <lttng/action/group.h>
#include <lttng/action/notify.h>
#include <lttng/action/rotate-session.h>
#include <lttng/action/snapshot-session.h>
#include <lttng/action/start-session.h>
#include <lttng/action/stop-session.h>
#include <lttng/condition/evaluation.h>
#include <lttng/lttng-error.h>
#include <lttng/trigger/trigger-internal.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <urcu/list.h>

#define THREAD_NAME "Action Executor"
#define MAX_QUEUED_WORK_COUNT 8192

struct action_work_item {
	uint64_t id;
	struct lttng_trigger *trigger;
	struct lttng_evaluation *evaluation;
	struct notification_client_list *client_list;
	LTTNG_OPTIONAL(struct lttng_credentials) object_creds;
	struct cds_list_head list_node;
};

struct action_executor {
	struct lttng_thread *thread;
	struct notification_thread_handle *notification_thread_handle;
	struct {
		uint64_t pending_count;
		struct cds_list_head list;
		pthread_cond_t cond;
		pthread_mutex_t lock;
	} work;
	bool should_quit;
	uint64_t next_work_item_id;
};

/*
 * Only return non-zero on a fatal error that should shut down the action
 * executor.
 */
typedef int (*action_executor_handler)(struct action_executor *executor,
		const struct action_work_item *,
		const struct lttng_action *action);

static int action_executor_notify_handler(struct action_executor *executor,
		const struct action_work_item *,
		const struct lttng_action *);
static int action_executor_start_session_handler(struct action_executor *executor,
		const struct action_work_item *,
		const struct lttng_action *);
static int action_executor_stop_session_handler(struct action_executor *executor,
		const struct action_work_item *,
		const struct lttng_action *);
static int action_executor_rotate_session_handler(struct action_executor *executor,
		const struct action_work_item *,
		const struct lttng_action *);
static int action_executor_snapshot_session_handler(struct action_executor *executor,
		const struct action_work_item *,
		const struct lttng_action *);
static int action_executor_group_handler(struct action_executor *executor,
		const struct action_work_item *,
		const struct lttng_action *);
static int action_executor_generic_handler(struct action_executor *executor,
		const struct action_work_item *,
		const struct lttng_action *);

static const action_executor_handler action_executors[] = {
	[LTTNG_ACTION_TYPE_NOTIFY] = action_executor_notify_handler,
	[LTTNG_ACTION_TYPE_START_SESSION] = action_executor_start_session_handler,
	[LTTNG_ACTION_TYPE_STOP_SESSION] = action_executor_stop_session_handler,
	[LTTNG_ACTION_TYPE_ROTATE_SESSION] = action_executor_rotate_session_handler,
	[LTTNG_ACTION_TYPE_SNAPSHOT_SESSION] = action_executor_snapshot_session_handler,
	[LTTNG_ACTION_TYPE_GROUP] = action_executor_group_handler,
};

static const char *action_type_names[] = {
	[LTTNG_ACTION_TYPE_NOTIFY] = "Notify",
	[LTTNG_ACTION_TYPE_START_SESSION] = "Start session",
	[LTTNG_ACTION_TYPE_STOP_SESSION] = "Stop session",
	[LTTNG_ACTION_TYPE_ROTATE_SESSION] = "Rotate session",
	[LTTNG_ACTION_TYPE_SNAPSHOT_SESSION] = "Snapshot session",
	[LTTNG_ACTION_TYPE_GROUP] = "Group",
};

static const char *get_action_name(const struct lttng_action *action)
{
	return action_type_names[lttng_action_get_type(action)];
}

/* Check if this trigger allowed to interect with a given session. */
static bool is_trigger_allowed_for_session(const struct lttng_trigger *trigger,
		struct ltt_session *session)
{
	bool is_allowed = false;
	const struct lttng_credentials session_creds = {
		.uid = session->uid,
		.gid = session->gid,
	};
	/* Can never be NULL. */
	const struct lttng_credentials *trigger_creds =
			lttng_trigger_get_credentials(trigger);

	is_allowed = (trigger_creds->uid == session_creds.uid) ||
			(trigger_creds->uid == 0);
	if (!is_allowed) {
		WARN("Trigger is not allowed to interact with session `%s`: session uid = %ld, session gid = %ld, trigger uid = %ld, trigger gid = %ld",
				session->name,
				(long int) session->uid,
				(long int) session->gid,
				(long int) trigger_creds->uid,
				(long int) trigger_creds->gid);
	}

	return is_allowed;
}

static int client_handle_transmission_status(
		struct notification_client *client,
		enum client_transmission_status status,
		void *user_data)
{
	int ret = 0;
	struct action_executor *executor = user_data;
	bool update_communication = true;

	switch (status) {
	case CLIENT_TRANSMISSION_STATUS_COMPLETE:
		DBG("Successfully sent full notification to client, client_id = %" PRIu64,
				client->id);
		update_communication = false;
		break;
	case CLIENT_TRANSMISSION_STATUS_QUEUED:
		DBG("Queued notification in client outgoing buffer, client_id = %" PRIu64,
				client->id);
		break;
	case CLIENT_TRANSMISSION_STATUS_FAIL:
		DBG("Communication error occurred while sending notification to client, client_id = %" PRIu64,
				client->id);
		break;
	default:
		ERR("Fatal error encoutered while sending notification to client, client_id = %" PRIu64,
				client->id);
		ret = -1;
		goto end;
	}

	if (!update_communication) {
		goto end;
	}

	/* Safe to read client's id without locking as it is immutable. */
	ret = notification_thread_client_communication_update(
			executor->notification_thread_handle, client->id,
			status);
end:
	return ret;
}

static int action_executor_notify_handler(struct action_executor *executor,
		const struct action_work_item *work_item,
		const struct lttng_action *action)
{
	return notification_client_list_send_evaluation(work_item->client_list,
			lttng_trigger_get_const_condition(work_item->trigger),
			work_item->evaluation,
			lttng_trigger_get_credentials(work_item->trigger),
			LTTNG_OPTIONAL_GET_PTR(work_item->object_creds),
			client_handle_transmission_status,
			executor);
}

static int action_executor_start_session_handler(struct action_executor *executor,
		const struct action_work_item *work_item,
		const struct lttng_action *action)
{
	int ret = 0;
	const char *session_name;
	enum lttng_action_status action_status;
	struct ltt_session *session;
	enum lttng_error_code cmd_ret;

	action_status = lttng_action_start_session_get_session_name(
			action, &session_name);
	if (action_status != LTTNG_ACTION_STATUS_OK) {
		ERR("Failed to get session name from `%s` action",
				get_action_name(action));
		ret = -1;
		goto end;
	}

	session_lock_list();
	session = session_find_by_name(session_name);
	if (!session) {
		DBG("Failed to find session `%s` by name while executing `%s` action of trigger `%p`",
				session_name, get_action_name(action),
		    work_item->trigger);
		goto error_unlock_list;
	}

	session_lock(session);
	if (!is_trigger_allowed_for_session(work_item->trigger, session)) {
		goto error_dispose_session;
	}

	cmd_ret = cmd_start_trace(session);
	switch (cmd_ret) {
	case LTTNG_OK:
		DBG("Successfully started session `%s` on behalf of trigger `%p`",
				session_name, work_item->trigger);
		break;
	case LTTNG_ERR_TRACE_ALREADY_STARTED:
		DBG("Attempted to start session `%s` on behalf of trigger `%p` but it was already started",
				session_name, work_item->trigger);
		break;
	default:
		WARN("Failed to start session `%s` on behalf of trigger `%p`: %s",
				session_name, work_item->trigger,
				lttng_strerror(-cmd_ret));
		break;
	}

error_dispose_session:
	session_unlock(session);
	session_put(session);
error_unlock_list:
	session_unlock_list();
end:
	return ret;
}

static int action_executor_stop_session_handler(struct action_executor *executor,
		const struct action_work_item *work_item,
		const struct lttng_action *action)
{
	int ret = 0;
	const char *session_name;
	enum lttng_action_status action_status;
	struct ltt_session *session;
	enum lttng_error_code cmd_ret;

	action_status = lttng_action_stop_session_get_session_name(
			action, &session_name);
	if (action_status != LTTNG_ACTION_STATUS_OK) {
		ERR("Failed to get session name from `%s` action",
				get_action_name(action));
		ret = -1;
		goto end;
	}

	session_lock_list();
	session = session_find_by_name(session_name);
	if (!session) {
		DBG("Failed to find session `%s` by name while executing `%s` action of trigger `%p`",
				session_name, get_action_name(action),
		    work_item->trigger);
		goto error_unlock_list;
	}

	session_lock(session);
	if (!is_trigger_allowed_for_session(work_item->trigger, session)) {
		goto error_dispose_session;
	}

	cmd_ret = cmd_stop_trace(session);
	switch (cmd_ret) {
	case LTTNG_OK:
		DBG("Successfully stopped session `%s` on behalf of trigger `%p`",
				session_name, work_item->trigger);
		break;
	case LTTNG_ERR_TRACE_ALREADY_STOPPED:
		DBG("Attempted to stop session `%s` on behalf of trigger `%p` but it was already stopped",
				session_name, work_item->trigger);
		break;
	default:
		WARN("Failed to stop session `%s` on behalf of trigger `%p`: %s",
				session_name, work_item->trigger,
				lttng_strerror(-cmd_ret));
		break;
	}

error_dispose_session:
	session_unlock(session);
	session_put(session);
error_unlock_list:
	session_unlock_list();
end:
	return ret;
}

static int action_executor_rotate_session_handler(struct action_executor *executor,
		const struct action_work_item *work_item,
		const struct lttng_action *action)
{
	int ret = 0;
	const char *session_name;
	enum lttng_action_status action_status;
	struct ltt_session *session;
	enum lttng_error_code cmd_ret;

	action_status = lttng_action_rotate_session_get_session_name(
			action, &session_name);
	if (action_status != LTTNG_ACTION_STATUS_OK) {
		ERR("Failed to get session name from `%s` action",
				get_action_name(action));
		ret = -1;
		goto end;
	}

	session_lock_list();
	session = session_find_by_name(session_name);
	if (!session) {
		DBG("Failed to find session `%s` by name while executing `%s` action of trigger `%p`",
				session_name, get_action_name(action),
		    work_item->trigger);
		goto error_unlock_list;
	}

	session_lock(session);
	if (!is_trigger_allowed_for_session(work_item->trigger, session)) {
		goto error_dispose_session;
	}

	cmd_ret = cmd_rotate_session(session, NULL, false,
			LTTNG_TRACE_CHUNK_COMMAND_TYPE_MOVE_TO_COMPLETED);
	switch (cmd_ret) {
	case LTTNG_OK:
		DBG("Successfully started rotation of session `%s` on behalf of trigger `%p`",
				session_name, work_item->trigger);
		break;
	case LTTNG_ERR_ROTATION_PENDING:
		DBG("Attempted to start a rotation of session `%s` on behalf of trigger `%p` but a rotation is already ongoing",
				session_name, work_item->trigger);
		break;
	case LTTNG_ERR_ROTATION_MULTIPLE_AFTER_STOP:
	case LTTNG_ERR_ROTATION_AFTER_STOP_CLEAR:
		DBG("Attempted to start a rotation of session `%s` on behalf of trigger `%p` but a rotation has already been completed since the last stop or clear",
				session_name, work_item->trigger);
		break;
	default:
		WARN("Failed to start a rotation of session `%s` on behalf of trigger `%p`: %s",
				session_name, work_item->trigger,
				lttng_strerror(-cmd_ret));
		break;
	}

error_dispose_session:
	session_unlock(session);
	session_put(session);
error_unlock_list:
	session_unlock_list();
end:
	return ret;
}

static int action_executor_snapshot_session_handler(struct action_executor *executor,
		const struct action_work_item *work_item,
		const struct lttng_action *action)
{
	int ret = 0;
	const char *session_name;
	enum lttng_action_status action_status;
	struct ltt_session *session;
	const struct lttng_snapshot_output default_snapshot_output = {
		.max_size = UINT64_MAX,
	};
	const struct lttng_snapshot_output *snapshot_output =
			&default_snapshot_output;
	enum lttng_error_code cmd_ret;

	action_status = lttng_action_snapshot_session_get_session_name(
			action, &session_name);
	if (action_status != LTTNG_ACTION_STATUS_OK) {
		ERR("Failed to get session name from `%s` action",
				get_action_name(action));
		ret = -1;
		goto end;
	}

	action_status = lttng_action_snapshot_session_get_output(
			action, &snapshot_output);
	if (action_status != LTTNG_ACTION_STATUS_OK &&
			action_status != LTTNG_ACTION_STATUS_UNSET) {
		ERR("Failed to get output from `%s` action",
				get_action_name(action));
		ret = -1;
		goto end;
	}

	session_lock_list();
	session = session_find_by_name(session_name);
	if (!session) {
		DBG("Failed to find session `%s` by name while executing `%s` action of trigger `%p`",
				session_name, get_action_name(action),
		    work_item->trigger);
		goto error_unlock_list;
	}


	session_lock(session);
	if (!is_trigger_allowed_for_session(work_item->trigger, session)) {
		goto error_dispose_session;
	}

	cmd_ret = cmd_snapshot_record(session, snapshot_output, 0);
	switch (cmd_ret) {
	case LTTNG_OK:
		DBG("Successfully recorded snapshot of session `%s` on behalf of trigger `%p`",
				session_name, work_item->trigger);
		break;
	default:
		WARN("Failed to record snapshot of session `%s` on behalf of trigger `%p`: %s",
				session_name, work_item->trigger,
				lttng_strerror(-cmd_ret));
		break;
	}

error_dispose_session:
	session_unlock(session);
	session_put(session);
error_unlock_list:
	session_unlock_list();
end:
	return ret;
}

static int action_executor_group_handler(struct action_executor *executor,
		const struct action_work_item *work_item,
		const struct lttng_action *action_group)
{
	int ret = 0;
	unsigned int i, count;
	enum lttng_action_status action_status;

	action_status = lttng_action_group_get_count(action_group, &count);
	if (action_status != LTTNG_ACTION_STATUS_OK) {
		/* Fatal error. */
		ERR("Failed to get count of action in action group");
		ret = -1;
		goto end;
	}

	DBG("Action group has %u action%s", count, count != 1 ? "s" : "");
	for (i = 0; i < count; i++) {
		const struct lttng_action *action =
				lttng_action_group_get_at_index(
						action_group, i);

		ret = action_executor_generic_handler(
				executor, work_item, action);
		if (ret) {
			ERR("Stopping the execution of the action group of trigger `%p` following a fatal error",
					work_item->trigger);
			goto end;
		}
	}
end:
	return ret;
}

static int action_executor_generic_handler(struct action_executor *executor,
		const struct action_work_item *work_item,
		const struct lttng_action *action)
{
	DBG("Executing action `%s` of trigger `%p` action work item %" PRIu64,
			get_action_name(action),
			work_item->trigger,
			work_item->id);

	return action_executors[lttng_action_get_type(action)](
			executor, work_item, action);
}

static int action_work_item_execute(struct action_executor *executor,
		struct action_work_item *work_item)
{
	int ret;
	const struct lttng_action *action =
			lttng_trigger_get_const_action(work_item->trigger);

	DBG("Starting execution of action work item %" PRIu64 " of trigger `%p`",
			work_item->id, work_item->trigger);
	ret = action_executor_generic_handler(executor, work_item, action);
	DBG("Completed execution of action work item %" PRIu64 " of trigger `%p`",
			work_item->id, work_item->trigger);
	return ret;
}

static void action_work_item_destroy(struct action_work_item *work_item)
{
	lttng_trigger_put(work_item->trigger);
	lttng_evaluation_destroy(work_item->evaluation);
	notification_client_list_put(work_item->client_list);
	free(work_item);
}

static void *action_executor_thread(void *_data)
{
	struct action_executor *executor = _data;

	assert(executor);

	health_register(health_sessiond, HEALTH_SESSIOND_TYPE_ACTION_EXECUTOR);

	rcu_register_thread();
	rcu_thread_online();

	DBG("Entering work execution loop");
	pthread_mutex_lock(&executor->work.lock);
	while (!executor->should_quit) {
		int ret;
		struct action_work_item *work_item;

		health_code_update();
		if (executor->work.pending_count == 0) {
			health_poll_entry();
			DBG("No work items enqueued, entering wait");
			pthread_cond_wait(&executor->work.cond,
					&executor->work.lock);
			DBG("Woke-up from wait");
			health_poll_exit();
			continue;
		}

		/* Pop item from front of the listwith work lock held. */
		work_item = cds_list_first_entry(&executor->work.list,
				struct action_work_item, list_node);
		cds_list_del(&work_item->list_node);
		executor->work.pending_count--;

		/*
		 * Work can be performed without holding the work lock,
		 * allowing new items to be queued.
		 */
		pthread_mutex_unlock(&executor->work.lock);
		ret = action_work_item_execute(executor, work_item);
		action_work_item_destroy(work_item);
		if (ret) {
			/* Fatal error. */
			break;
		}

		health_code_update();
		pthread_mutex_lock(&executor->work.lock);
	}

	if (executor->should_quit) {
		pthread_mutex_unlock(&executor->work.lock);
	}
	DBG("Left work execution loop");

	health_code_update();

	rcu_thread_offline();
	rcu_unregister_thread();
	health_unregister(health_sessiond);

	return NULL;
}

static bool shutdown_action_executor_thread(void *_data)
{
	struct action_executor *executor = _data;

	executor->should_quit = true;
	pthread_cond_signal(&executor->work.cond);
	return true;
}

static void clean_up_action_executor_thread(void *_data)
{
	struct action_executor *executor = _data;

	assert(cds_list_empty(&executor->work.list));

	pthread_mutex_destroy(&executor->work.lock);
	pthread_cond_destroy(&executor->work.cond);
	free(executor);
}

struct action_executor *action_executor_create(
		struct notification_thread_handle *handle)
{
	struct action_executor *executor = zmalloc(sizeof(*executor));

	if (!executor) {
		goto end;
	}

	CDS_INIT_LIST_HEAD(&executor->work.list);
	pthread_cond_init(&executor->work.cond, NULL);
	pthread_mutex_init(&executor->work.lock, NULL);
	executor->notification_thread_handle = handle;

	executor->thread = lttng_thread_create(THREAD_NAME,
			action_executor_thread, shutdown_action_executor_thread,
			clean_up_action_executor_thread, executor);
end:
	return executor;
}

void action_executor_destroy(struct action_executor *executor)
{
	struct action_work_item *work_item, *tmp;

	/* TODO Wait for work list to drain? */
	lttng_thread_shutdown(executor->thread);
	pthread_mutex_lock(&executor->work.lock);
	if (executor->work.pending_count != 0) {
		WARN("%" PRIu64
			" trigger action%s still queued for execution and will be discarded",
				executor->work.pending_count,
				executor->work.pending_count == 1 ? " is" :
								    "s are");
	}

	cds_list_for_each_entry_safe (
			work_item, tmp, &executor->work.list, list_node) {
		WARN("Discarding action work item %" PRIu64
				" associated to trigger `%p`",
				work_item->id, work_item->trigger);
		cds_list_del(&work_item->list_node);
		action_work_item_destroy(work_item);
	}
	pthread_mutex_unlock(&executor->work.lock);
	lttng_thread_put(executor->thread);
}

/* RCU read-lock must be held by the caller. */
enum action_executor_status action_executor_enqueue(
		struct action_executor *executor,
		struct lttng_trigger *trigger,
		struct lttng_evaluation *evaluation,
		const struct lttng_credentials *object_creds,
		struct notification_client_list *client_list)
{
	enum action_executor_status executor_status = ACTION_EXECUTOR_STATUS_OK;
	const uint64_t work_item_id = executor->next_work_item_id++;
	struct action_work_item *work_item;
	bool signal = false;

	pthread_mutex_lock(&executor->work.lock);
	/* Check for queue overflow. */
	if (executor->work.pending_count >= MAX_QUEUED_WORK_COUNT) {
		/* Most likely spammy, remove if it is the case. */
		DBG("Refusing to enqueue action for trigger `%p` as work item %" PRIu64
		    " (overflow)",
				trigger, work_item_id);
		executor_status = ACTION_EXECUTOR_STATUS_OVERFLOW;
		goto error_unlock;
	}

	work_item = zmalloc(sizeof(*work_item));
	if (!work_item) {
		PERROR("Failed to allocate action executor work item on behalf of trigger `%p`",
				trigger);
		executor_status = ACTION_EXECUTOR_STATUS_ERROR;
		goto error_unlock;
	}

	lttng_trigger_get(trigger);
	if (client_list) {
		const bool reference_acquired =
				notification_client_list_get(client_list);

		assert(reference_acquired);
	}

	*work_item = (typeof(*work_item)){
			.id = work_item_id,
			.trigger = trigger,
			/* Ownership transferred to the work item. */
			.evaluation = evaluation,
			.object_creds = {
				.is_set = !!object_creds,
				.value = object_creds ? *object_creds :
					(typeof(work_item->object_creds.value)) {},
			},
			.client_list = client_list,
			.list_node = CDS_LIST_HEAD_INIT(work_item->list_node),
	};

	evaluation = NULL;
	cds_list_add_tail(&work_item->list_node, &executor->work.list);
	executor->work.pending_count++;
	DBG("Enqueued action for trigger `%p` as work item %" PRIu64,
			trigger, work_item_id);
	signal = true;

error_unlock:
	pthread_mutex_unlock(&executor->work.lock);
	if (signal) {
		pthread_cond_signal(&executor->work.cond);
	}

	lttng_evaluation_destroy(evaluation);
	return executor_status;
}
