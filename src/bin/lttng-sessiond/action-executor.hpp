/*
 * Copyright (C) 2020 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef ACTION_EXECUTOR_H
#define ACTION_EXECUTOR_H

struct action_executor;
struct notification_thread_handle;
struct lttng_evaluation;
struct lttng_trigger;
struct notification_client_list;
struct lttng_credentials;

enum action_executor_status {
	ACTION_EXECUTOR_STATUS_OK,
	ACTION_EXECUTOR_STATUS_OVERFLOW,
	ACTION_EXECUTOR_STATUS_ERROR,
	ACTION_EXECUTOR_STATUS_INVALID,
};

struct action_executor *action_executor_create(struct notification_thread_handle *handle);

void action_executor_destroy(struct action_executor *executor);

/*
 * Enqueue a job on an action executor's work queue to perform the actions
 * associated with a trigger.
 *
 * A reference to `trigger` is acquired.
 * A reference to `list` is acquired.
 *
 * This function assumes the ownership of the `evaluation` both on success and
 * failure: the caller should no longer access it once the function returns.
 */
enum action_executor_status
action_executor_enqueue_trigger(struct action_executor *executor,
				struct lttng_trigger *trigger,
				struct lttng_evaluation *evaluation,
				const struct lttng_credentials *object_creds,
				struct notification_client_list *list);

#endif /* ACTION_EXECUTOR_H */
