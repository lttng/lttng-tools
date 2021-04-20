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
#include <common/dynamic-array.h>
#include <common/macros.h>
#include <common/optional.h>
#include <lttng/action/action-internal.h>
#include <lttng/action/group-internal.h>
#include <lttng/action/group.h>
#include <lttng/action/notify-internal.h>
#include <lttng/action/notify.h>
#include <lttng/action/rotate-session.h>
#include <lttng/action/snapshot-session.h>
#include <lttng/action/start-session.h>
#include <lttng/action/stop-session.h>
#include <lttng/condition/evaluation.h>
#include <lttng/condition/event-rule-matches-internal.h>
#include <lttng/lttng-error.h>
#include <lttng/trigger/trigger-internal.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <urcu/list.h>

#define THREAD_NAME "Action Executor"
#define MAX_QUEUED_WORK_COUNT 8192

/*
 * A work item is composed of a dynamic array of sub-items which
 * represent a flattened, and augmented, version of a trigger's actions.
 *
 * We cannot rely solely on the trigger's actions since each action can have an
 * execution context we need to comply with.
 *
 * The notion of execution context is required since for some actions the
 * associated object are referenced by name and not by id. This can lead to
 * a number of ambiguities when executing an action work item.
 *
 * For example, let's take a simple trigger such as:
 *   - condition: ust event a
 *   - action: start session S
 *
 * At time T, session S exists.
 * At T + 1, the event A is hit.
 * At T + 2, the tracer event notification is received and the work item is
 * queued. Here session S have an id of 1.
 * At T + 3, the session S is destroyed and a new session S is created, with a
 * resulting id of 200.
 * At T +4, the work item is popped from the queue and begin execution and will
 * start session S with an id of 200 instead of the session S id 1 that was
 * present at the queuing phase.
 *
 * The context to be respected is the one when the work item is queued. If the
 * execution context is not the same at the moment of execution, we skip the
 * execution of that sub-item.
 *
 * It is the same policy in regards to the validity of the associated
 * trigger object at the moment of execution, if the trigger is found to be
 * unregistered, the execution is skipped.
 */

struct action_work_item {
	uint64_t id;

	/*
	 * The actions to be executed with their respective execution context.
	 * See struct `action_work_subitem`.
	 */
	struct lttng_dynamic_array *subitems;

	/* Execution context data */
	struct lttng_trigger *trigger;
	struct lttng_evaluation *evaluation;
	struct notification_client_list *client_list;
	LTTNG_OPTIONAL(struct lttng_credentials) object_creds;
	struct cds_list_head list_node;
};

struct action_work_subitem {
	struct lttng_action *action;
	struct {
		/* Used by actions targeting a session. */
		LTTNG_OPTIONAL(uint64_t) session_id;
	} context;
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
		struct action_work_subitem *item);

static int action_executor_notify_handler(struct action_executor *executor,
		const struct action_work_item *,
		struct action_work_subitem *);
static int action_executor_start_session_handler(
		struct action_executor *executor,
		const struct action_work_item *,
		struct action_work_subitem *);
static int action_executor_stop_session_handler(
		struct action_executor *executor,
		const struct action_work_item *,
		struct action_work_subitem *);
static int action_executor_rotate_session_handler(
		struct action_executor *executor,
		const struct action_work_item *,
		struct action_work_subitem *);
static int action_executor_snapshot_session_handler(
		struct action_executor *executor,
		const struct action_work_item *,
		struct action_work_subitem *);
static int action_executor_group_handler(struct action_executor *executor,
		const struct action_work_item *,
		struct action_work_subitem *);
static int action_executor_generic_handler(struct action_executor *executor,
		const struct action_work_item *,
		struct action_work_subitem *);

static const action_executor_handler action_executors[] = {
	[LTTNG_ACTION_TYPE_NOTIFY] = action_executor_notify_handler,
	[LTTNG_ACTION_TYPE_START_SESSION] = action_executor_start_session_handler,
	[LTTNG_ACTION_TYPE_STOP_SESSION] = action_executor_stop_session_handler,
	[LTTNG_ACTION_TYPE_ROTATE_SESSION] = action_executor_rotate_session_handler,
	[LTTNG_ACTION_TYPE_SNAPSHOT_SESSION] = action_executor_snapshot_session_handler,
	[LTTNG_ACTION_TYPE_GROUP] = action_executor_group_handler,
};

/* Forward declaration */
static int add_action_to_subitem_array(struct lttng_action *action,
		struct lttng_dynamic_array *subitems);

static int populate_subitem_array_from_trigger(struct lttng_trigger *trigger,
		struct lttng_dynamic_array *subitems);

static void action_work_subitem_destructor(void *element)
{
	struct action_work_subitem *subitem = element;

	lttng_action_put(subitem->action);
}

static const char *get_action_name(const struct lttng_action *action)
{
	const enum lttng_action_type action_type = lttng_action_get_type(action);

	assert(action_type != LTTNG_ACTION_TYPE_UNKNOWN);

	return lttng_action_type_string(action_type);
}

/* Check if this trigger allowed to interect with a given session. */
static bool is_trigger_allowed_for_session(const struct lttng_trigger *trigger,
		struct ltt_session *session)
{
	bool is_allowed = false;
	const struct lttng_credentials session_creds = {
		.uid = LTTNG_OPTIONAL_INIT_VALUE(session->uid),
		.gid = LTTNG_OPTIONAL_INIT_VALUE(session->gid),
	};
	/* Can never be NULL. */
	const struct lttng_credentials *trigger_creds =
			lttng_trigger_get_credentials(trigger);

	is_allowed = (lttng_credentials_is_equal_uid(trigger_creds, &session_creds)) ||
			(lttng_credentials_get_uid(trigger_creds) == 0);
	if (!is_allowed) {
		WARN("Trigger is not allowed to interact with session `%s`: session uid = %ld, session gid = %ld, trigger uid = %ld",
				session->name,
				(long int) session->uid,
				(long int) session->gid,
				(long int) lttng_credentials_get_uid(trigger_creds));
	}

	return is_allowed;
}

static const char *get_trigger_name(const struct lttng_trigger *trigger)
{
	const char *trigger_name;
	enum lttng_trigger_status trigger_status;

	trigger_status = lttng_trigger_get_name(trigger, &trigger_name);
	assert(trigger_status == LTTNG_TRIGGER_STATUS_OK);

	return trigger_name;
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
		struct action_work_subitem *item)
{
	return notification_client_list_send_evaluation(work_item->client_list,
			work_item->trigger,
			work_item->evaluation,
			work_item->object_creds.is_set ?
					&(work_item->object_creds.value) :
					NULL,
			client_handle_transmission_status, executor);
}

static int action_executor_start_session_handler(
		struct action_executor *executor,
		const struct action_work_item *work_item,
		struct action_work_subitem *item)
{
	int ret = 0;
	const char *session_name;
	enum lttng_action_status action_status;
	struct ltt_session *session;
	enum lttng_error_code cmd_ret;
	struct lttng_action *action = item->action;

	action_status = lttng_action_start_session_get_session_name(
			action, &session_name);
	if (action_status != LTTNG_ACTION_STATUS_OK) {
		ERR("Failed to get session name from `%s` action",
				get_action_name(action));
		ret = -1;
		goto end;
	}

	/*
	 * Validate if at the moment of the action was queued the session
	 * existed. If not skip the action altogether.
	 */
	if (!item->context.session_id.is_set) {
		DBG("Session `%s` was not present at the moment the work item was enqueued for %s` action of trigger `%s`",
				session_name, get_action_name(action),
				get_trigger_name(work_item->trigger));
		lttng_action_increase_execution_failure_count(action);
		ret = 0;
		goto end;
	}

	session_lock_list();
	session = session_find_by_name(session_name);
	if (!session) {
		DBG("Failed to find session `%s` by name while executing `%s` action of trigger `%s`",
				session_name, get_action_name(action),
				get_trigger_name(work_item->trigger));
		goto error_unlock_list;
	}

	/*
	 * Check if the session id is the same as when the work item was
	 * enqueued.
	 */
	if (session->id != LTTNG_OPTIONAL_GET(item->context.session_id)) {
		DBG("Session id for session `%s` (id: %" PRIu64
				" is not the same that was sampled (id: %" PRIu64
				" at the moment the work item was enqueued for %s` action of trigger `%s`",
				session_name, session->id,
				LTTNG_OPTIONAL_GET(item->context.session_id),
				get_action_name(action),
				get_trigger_name(work_item->trigger));
		ret = 0;
		goto error_unlock_list;
	}

	session_lock(session);
	if (!is_trigger_allowed_for_session(work_item->trigger, session)) {
		goto error_dispose_session;
	}

	cmd_ret = cmd_start_trace(session);
	switch (cmd_ret) {
	case LTTNG_OK:
		DBG("Successfully started session `%s` on behalf of trigger `%s`",
				session_name, get_trigger_name(work_item->trigger));
		break;
	case LTTNG_ERR_TRACE_ALREADY_STARTED:
		DBG("Attempted to start session `%s` on behalf of trigger `%s` but it was already started",
				session_name, get_trigger_name(work_item->trigger));
		break;
	default:
		WARN("Failed to start session `%s` on behalf of trigger `%s`: %s",
				session_name, get_trigger_name(work_item->trigger),
				lttng_strerror(-cmd_ret));
		lttng_action_increase_execution_failure_count(action);
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

static int action_executor_stop_session_handler(
		struct action_executor *executor,
		const struct action_work_item *work_item,
		struct action_work_subitem *item)
{
	int ret = 0;
	const char *session_name;
	enum lttng_action_status action_status;
	struct ltt_session *session;
	enum lttng_error_code cmd_ret;
	struct lttng_action *action = item->action;

	action_status = lttng_action_stop_session_get_session_name(
			action, &session_name);
	if (action_status != LTTNG_ACTION_STATUS_OK) {
		ERR("Failed to get session name from `%s` action",
				get_action_name(action));
		ret = -1;
		goto end;
	}

	/*
	 * Validate if, at the moment the action was queued, the target session
	 * existed. If not, skip the action altogether.
	 */
	if (!item->context.session_id.is_set) {
		DBG("Session `%s` was not present at the moment the work item was enqueued for %s` action of trigger `%s`",
				session_name, get_action_name(action),
				get_trigger_name(work_item->trigger));
		lttng_action_increase_execution_failure_count(action);
		ret = 0;
		goto end;
	}

	session_lock_list();
	session = session_find_by_name(session_name);
	if (!session) {
		DBG("Failed to find session `%s` by name while executing `%s` action of trigger `%s`",
				session_name, get_action_name(action),
				get_trigger_name(work_item->trigger));
		lttng_action_increase_execution_failure_count(action);
		goto error_unlock_list;
	}

	/*
	 * Check if the session id is the same as when the work item was
	 * enqueued
	 */
	if (session->id != LTTNG_OPTIONAL_GET(item->context.session_id)) {
		DBG("Session id for session `%s` (id: %" PRIu64
				" is not the same that was sampled (id: %" PRIu64
				" at the moment the work item was enqueued for %s` action of trigger `%s`",
				session_name, session->id,
				LTTNG_OPTIONAL_GET(item->context.session_id),
				get_action_name(action),
				get_trigger_name(work_item->trigger));
		ret = 0;
		goto error_unlock_list;
	}

	session_lock(session);
	if (!is_trigger_allowed_for_session(work_item->trigger, session)) {
		goto error_dispose_session;
	}

	cmd_ret = cmd_stop_trace(session);
	switch (cmd_ret) {
	case LTTNG_OK:
		DBG("Successfully stopped session `%s` on behalf of trigger `%s`",
				session_name, get_trigger_name(work_item->trigger));
		break;
	case LTTNG_ERR_TRACE_ALREADY_STOPPED:
		DBG("Attempted to stop session `%s` on behalf of trigger `%s` but it was already stopped",
				session_name, get_trigger_name(work_item->trigger));
		break;
	default:
		WARN("Failed to stop session `%s` on behalf of trigger `%s`: %s",
				session_name, get_trigger_name(work_item->trigger),
				lttng_strerror(-cmd_ret));
		lttng_action_increase_execution_failure_count(action);
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

static int action_executor_rotate_session_handler(
		struct action_executor *executor,
		const struct action_work_item *work_item,
		struct action_work_subitem *item)
{
	int ret = 0;
	const char *session_name;
	enum lttng_action_status action_status;
	struct ltt_session *session;
	enum lttng_error_code cmd_ret;
	struct lttng_action *action = item->action;

	action_status = lttng_action_rotate_session_get_session_name(
			action, &session_name);
	if (action_status != LTTNG_ACTION_STATUS_OK) {
		ERR("Failed to get session name from `%s` action",
				get_action_name(action));
		ret = -1;
		goto end;
	}

	/*
	 * Validate if, at the moment the action was queued, the target session
	 * existed. If not, skip the action altogether.
	 */
	if (!item->context.session_id.is_set) {
		DBG("Session `%s` was not present at the moment the work item was enqueued for %s` action of trigger `%s`",
				session_name, get_action_name(action),
				get_trigger_name(work_item->trigger));
		lttng_action_increase_execution_failure_count(action);
		ret = 0;
		goto end;
	}

	session_lock_list();
	session = session_find_by_name(session_name);
	if (!session) {
		DBG("Failed to find session `%s` by name while executing `%s` action of trigger `%s`",
				session_name, get_action_name(action),
				get_trigger_name(work_item->trigger));
		lttng_action_increase_execution_failure_count(action);
		goto error_unlock_list;
	}

	/*
	 * Check if the session id is the same as when the work item was
	 * enqueued.
	 */
	if (session->id != LTTNG_OPTIONAL_GET(item->context.session_id)) {
		DBG("Session id for session `%s` (id: %" PRIu64
		    " is not the same that was sampled (id: %" PRIu64
		    " at the moment the work item was enqueued for %s` action of trigger `%s`",
				session_name, session->id,
				LTTNG_OPTIONAL_GET(item->context.session_id),
				get_action_name(action),
				get_trigger_name(work_item->trigger));
		ret = 0;
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
		DBG("Successfully started rotation of session `%s` on behalf of trigger `%s`",
				session_name, get_trigger_name(work_item->trigger));
		break;
	case LTTNG_ERR_ROTATION_PENDING:
		DBG("Attempted to start a rotation of session `%s` on behalf of trigger `%s` but a rotation is already ongoing",
				session_name, get_trigger_name(work_item->trigger));
		lttng_action_increase_execution_failure_count(action);
		break;
	case LTTNG_ERR_ROTATION_MULTIPLE_AFTER_STOP:
	case LTTNG_ERR_ROTATION_AFTER_STOP_CLEAR:
		DBG("Attempted to start a rotation of session `%s` on behalf of trigger `%s` but a rotation has already been completed since the last stop or clear",
				session_name, get_trigger_name(work_item->trigger));
		break;
	default:
		WARN("Failed to start a rotation of session `%s` on behalf of trigger `%s`: %s",
				session_name, get_trigger_name(work_item->trigger),
				lttng_strerror(-cmd_ret));
		lttng_action_increase_execution_failure_count(action);
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

static int action_executor_snapshot_session_handler(
		struct action_executor *executor,
		const struct action_work_item *work_item,
		struct action_work_subitem *item)
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
	struct lttng_action *action = item->action;

	/*
	 * Validate if, at the moment the action was queued, the target session
	 * existed. If not, skip the action altogether.
	 */
	if (!item->context.session_id.is_set) {
		DBG("Session was not present at the moment the work item was enqueued for %s` action of trigger `%s`",
				get_action_name(action),
				get_trigger_name(work_item->trigger));
		lttng_action_increase_execution_failure_count(action);
		ret = 0;
		goto end;
	}

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
		DBG("Failed to find session `%s` by name while executing `%s` action of trigger `%s`",
				session_name, get_action_name(action),
				get_trigger_name(work_item->trigger));
		lttng_action_increase_execution_failure_count(action);
		goto error_unlock_list;
	}

	/*
	 * Check if the session id is the same as when the work item was
	 * enqueued.
	 */
	if (session->id != LTTNG_OPTIONAL_GET(item->context.session_id)) {
		DBG("Session id for session `%s` (id: %" PRIu64
		    " is not the same that was sampled (id: %" PRIu64
		    " at the moment the work item was enqueued for %s` action of trigger `%s`",
				session_name, session->id,
				LTTNG_OPTIONAL_GET(item->context.session_id),
				get_action_name(action),
				get_trigger_name(work_item->trigger));
		ret = 0;
		goto error_unlock_list;
	}

	session_lock(session);
	if (!is_trigger_allowed_for_session(work_item->trigger, session)) {
		goto error_dispose_session;
	}

	cmd_ret = cmd_snapshot_record(session, snapshot_output, 0);
	switch (cmd_ret) {
	case LTTNG_OK:
		DBG("Successfully recorded snapshot of session `%s` on behalf of trigger `%s`",
				session_name, get_trigger_name(work_item->trigger));
		break;
	default:
		WARN("Failed to record snapshot of session `%s` on behalf of trigger `%s`: %s",
				session_name, get_trigger_name(work_item->trigger),
				lttng_strerror(-cmd_ret));
		lttng_action_increase_execution_failure_count(action);
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
		struct action_work_subitem *item)
{
	ERR("Execution of a group action by the action executor should never occur");
	abort();
}

static int action_executor_generic_handler(struct action_executor *executor,
		const struct action_work_item *work_item,
		struct action_work_subitem *item)
{
	int ret;
	struct lttng_action *action = item->action;
	const enum lttng_action_type action_type = lttng_action_get_type(action);

	assert(action_type != LTTNG_ACTION_TYPE_UNKNOWN);

	lttng_action_increase_execution_request_count(action);
	if (!lttng_action_should_execute(action)) {
		DBG("Policy prevented execution of action `%s` of trigger `%s` action work item %" PRIu64,
				get_action_name(action),
				get_trigger_name(work_item->trigger),
				work_item->id);
		ret = 0;
		goto end;
	}

	lttng_action_increase_execution_count(action);
	DBG("Executing action `%s` of trigger `%s` action work item %" PRIu64,
			get_action_name(action),
			get_trigger_name(work_item->trigger),
			work_item->id);
	ret = action_executors[action_type](executor, work_item, item);
end:
	return ret;
}

static int action_work_item_execute(struct action_executor *executor,
		struct action_work_item *work_item)
{
	int ret;
	size_t count, i;

	DBG("Starting execution of action work item %" PRIu64 " of trigger `%s`",
			work_item->id, get_trigger_name(work_item->trigger));

	count = lttng_dynamic_array_get_count(work_item->subitems);
	for (i = 0; i < count; i++) {
		struct action_work_subitem *item;

		item = lttng_dynamic_array_get_element(work_item->subitems, i);
		ret = action_executor_generic_handler(
				executor, work_item, item);
		if (ret) {
			goto end;
		}
	}
end:
	DBG("Completed execution of action work item %" PRIu64 " of trigger `%s`",
			work_item->id, get_trigger_name(work_item->trigger));
	return ret;
}

static void action_work_item_destroy(struct action_work_item *work_item)
{
	lttng_trigger_put(work_item->trigger);
	lttng_evaluation_destroy(work_item->evaluation);
	notification_client_list_put(work_item->client_list);
	lttng_dynamic_array_reset(work_item->subitems);
	free(work_item);
}

static void *action_executor_thread(void *_data)
{
	struct action_executor *executor = _data;

	assert(executor);

	health_register(the_health_sessiond,
			HEALTH_SESSIOND_TYPE_ACTION_EXECUTOR);

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

		/* Pop item from front of the list with work lock held. */
		work_item = cds_list_first_entry(&executor->work.list,
				struct action_work_item, list_node);
		cds_list_del(&work_item->list_node);
		executor->work.pending_count--;

		/*
		 * Work can be performed without holding the work lock,
		 * allowing new items to be queued.
		 */
		pthread_mutex_unlock(&executor->work.lock);

		/* Execute item only if a trigger is registered. */
		lttng_trigger_lock(work_item->trigger);
		if (!lttng_trigger_is_registered(work_item->trigger)) {
			const char *trigger_name = NULL;
			uid_t trigger_owner_uid;
			enum lttng_trigger_status trigger_status;

			trigger_status = lttng_trigger_get_name(
					work_item->trigger, &trigger_name);
			switch (trigger_status) {
			case LTTNG_TRIGGER_STATUS_OK:
				break;
			case LTTNG_TRIGGER_STATUS_UNSET:
				trigger_name = "(unset)";
				break;
			default:
				abort();
			}

			trigger_status = lttng_trigger_get_owner_uid(
					work_item->trigger, &trigger_owner_uid);
			assert(trigger_status == LTTNG_TRIGGER_STATUS_OK);

			DBG("Work item skipped since the associated trigger is no longer registered: work item id = %" PRIu64 ", trigger name = '%s', trigger owner uid = %d",
					work_item->id, trigger_name,
					(int) trigger_owner_uid);
			ret = 0;
			goto skip_execute;
		}

		ret = action_work_item_execute(executor, work_item);

	skip_execute:
		lttng_trigger_unlock(work_item->trigger);
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
	health_unregister(the_health_sessiond);

	return NULL;
}

static bool shutdown_action_executor_thread(void *_data)
{
	struct action_executor *executor = _data;

	pthread_mutex_lock(&executor->work.lock);
	executor->should_quit = true;
	pthread_cond_signal(&executor->work.cond);
	pthread_mutex_unlock(&executor->work.lock);
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
				" associated to trigger `%s`",
				work_item->id, get_trigger_name(work_item->trigger));
		cds_list_del(&work_item->list_node);
		action_work_item_destroy(work_item);
	}
	pthread_mutex_unlock(&executor->work.lock);
	lttng_thread_put(executor->thread);
}

/* RCU read-lock must be held by the caller. */
enum action_executor_status action_executor_enqueue_trigger(
		struct action_executor *executor,
		struct lttng_trigger *trigger,
		struct lttng_evaluation *evaluation,
		const struct lttng_credentials *object_creds,
		struct notification_client_list *client_list)
{
	int ret;
	enum action_executor_status executor_status = ACTION_EXECUTOR_STATUS_OK;
	const uint64_t work_item_id = executor->next_work_item_id++;
	struct action_work_item *work_item;
	bool signal = false;
	struct lttng_dynamic_array *subitems = NULL;

	assert(trigger);

	/* Build the array of action work subitems for the passed trigger. */
	subitems = zmalloc(sizeof(*subitems));
	if (!subitems) {
		PERROR("Failed to allocate action executor subitems array: trigger name = `%s`",
				get_trigger_name(trigger));
		executor_status = ACTION_EXECUTOR_STATUS_ERROR;
		goto error_unlock;
	}

	lttng_dynamic_array_init(subitems, sizeof(struct action_work_subitem),
			action_work_subitem_destructor);

	ret = populate_subitem_array_from_trigger(trigger, subitems);
	if (ret) {
		ERR("Failed to populate work item sub items on behalf of trigger: trigger name = `%s`",
				get_trigger_name(trigger));
		executor_status = ACTION_EXECUTOR_STATUS_ERROR;
		goto error_unlock;
	}

	pthread_mutex_lock(&executor->work.lock);
	/* Check for queue overflow. */
	if (executor->work.pending_count >= MAX_QUEUED_WORK_COUNT) {
		/* Most likely spammy, remove if it is the case. */
		DBG("Refusing to enqueue action for trigger (overflow): trigger name = `%s`, work item id = %" PRIu64,
				get_trigger_name(trigger), work_item_id);
		executor_status = ACTION_EXECUTOR_STATUS_OVERFLOW;
		goto error_unlock;
	}

	work_item = zmalloc(sizeof(*work_item));
	if (!work_item) {
		PERROR("Failed to allocate action executor work item: trigger name = '%s'",
				get_trigger_name(trigger));
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
			/* Ownership transferred to the work item. */
			.subitems = subitems,
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
	subitems = NULL;
	cds_list_add_tail(&work_item->list_node, &executor->work.list);
	executor->work.pending_count++;
	DBG("Enqueued action for trigger: trigger name = `%s`, work item id = %" PRIu64,
			get_trigger_name(trigger), work_item_id);
	signal = true;

error_unlock:
	if (signal) {
		pthread_cond_signal(&executor->work.cond);
	}
	pthread_mutex_unlock(&executor->work.lock);

	lttng_evaluation_destroy(evaluation);
	if (subitems) {
		lttng_dynamic_array_reset(subitems);
		free(subitems);
	}
	return executor_status;
}

static int add_action_to_subitem_array(struct lttng_action *action,
		struct lttng_dynamic_array *subitems)
{
	int ret;
	enum lttng_action_type type = lttng_action_get_type(action);
	const char *session_name = NULL;
	enum lttng_action_status status;
	struct action_work_subitem subitem = {
		.action = NULL,
		.context = {
			.session_id = LTTNG_OPTIONAL_INIT_UNSET,
		},
	};

	assert(action);
	assert(subitems);

	if (type == LTTNG_ACTION_TYPE_GROUP) {
		unsigned int count, i;

		status = lttng_action_list_get_count(action, &count);
		assert(status == LTTNG_ACTION_STATUS_OK);

		for (i = 0; i < count; i++) {
			struct lttng_action *inner_action = NULL;

			inner_action = lttng_action_list_borrow_mutable_at_index(
					action, i);
			assert(inner_action);
			ret = add_action_to_subitem_array(
					inner_action, subitems);
			if (ret) {
				goto end;
			}
		}

		/*
		 * Go directly to the end since there is no need to add the
		 * group action by itself to the subitems array.
		 */
		goto end;
	}

	/* Gather execution context. */
	switch (type) {
	case LTTNG_ACTION_TYPE_NOTIFY:
		break;
	case LTTNG_ACTION_TYPE_START_SESSION:
		status = lttng_action_start_session_get_session_name(
				action, &session_name);
		assert(status == LTTNG_ACTION_STATUS_OK);
		break;
	case LTTNG_ACTION_TYPE_STOP_SESSION:
		status = lttng_action_stop_session_get_session_name(
				action, &session_name);
		assert(status == LTTNG_ACTION_STATUS_OK);
		break;
	case LTTNG_ACTION_TYPE_ROTATE_SESSION:
		status = lttng_action_rotate_session_get_session_name(
				action, &session_name);
		assert(status == LTTNG_ACTION_STATUS_OK);
		break;
	case LTTNG_ACTION_TYPE_SNAPSHOT_SESSION:
		status = lttng_action_snapshot_session_get_session_name(
				action, &session_name);
		assert(status == LTTNG_ACTION_STATUS_OK);
		break;
	case LTTNG_ACTION_TYPE_GROUP:
	case LTTNG_ACTION_TYPE_UNKNOWN:
		/* Fallthrough */
	default:
		abort();
		break;
	}

	/*
	 * Fetch the session execution context info as needed.
	 * Note that we could decide to not add an action for which we know the
	 * execution will not happen (i.e no session exists for that name). For
	 * now we leave the decision to skip to the action executor for sake of
	 * simplicity and consistency.
	 */
	if (session_name != NULL) {
		struct ltt_session *session = NULL;

		session_lock_list();
		session = session_find_by_name(session_name);
		if (session) {
			LTTNG_OPTIONAL_SET(&subitem.context.session_id,
					session->id);
			session_put(session);
		}

		session_unlock_list();
	}

	/* Get a reference to the action. */
	lttng_action_get(action);
	subitem.action = action;

	ret = lttng_dynamic_array_add_element(subitems, &subitem);
	if (ret) {
		ERR("Failed to add work subitem to the subitem array");
		lttng_action_put(action);
		ret = -1;
		goto end;
	}

end:
	return ret;
}

static int populate_subitem_array_from_trigger(struct lttng_trigger *trigger,
		struct lttng_dynamic_array *subitems)
{
	struct lttng_action *action;

	action = lttng_trigger_get_action(trigger);
	assert(action);

	return add_action_to_subitem_array(action, subitems);
}
