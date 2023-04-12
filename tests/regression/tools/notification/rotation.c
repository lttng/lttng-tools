/*
 * rotation.c
 *
 * Tests suite for LTTng notification API (rotation notifications)
 *
 * Copyright (C) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 *
 */

#include <lttng/lttng.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <tap/tap.h>
#include <unistd.h>

#define TEST_COUNT 36

struct session {
	const char *name;
	const char *output_path;
};

uint64_t expected_rotation_id = UINT64_MAX;

static int test_condition(struct lttng_condition *condition, const char *type_name)
{
	int ret = 0;
	const char *out_session_name;
	const char *const session_name = "test session name";
	enum lttng_condition_status status;

	status = lttng_condition_session_rotation_get_session_name(condition, &out_session_name);
	ok(status == LTTNG_CONDITION_STATUS_UNSET,
	   "Getting unset name of %s condition fails with LTTNG_CONDITION_STATUS_UNSET",
	   type_name);

	status = lttng_condition_session_rotation_set_session_name(condition, session_name);
	ok(status == LTTNG_CONDITION_STATUS_OK,
	   "Setting session name \"%s\" of %s condition succeeds",
	   session_name,
	   type_name);

	status = lttng_condition_session_rotation_get_session_name(condition, &out_session_name);
	ok(status == LTTNG_CONDITION_STATUS_OK, "Getting name of %s condition succeeds", type_name);

	ok(out_session_name && !strcmp(session_name, out_session_name),
	   "Session name returned by %s condition matches the expected name",
	   type_name);
	return ret;
}

static int setup_rotation_trigger(const struct session *session,
				  struct lttng_notification_channel *notification_channel)
{
	int ret;
	struct lttng_condition *rotation_ongoing_condition = NULL;
	struct lttng_condition *rotation_completed_condition = NULL;
	struct lttng_action *notify = NULL;
	struct lttng_trigger *rotation_ongoing_trigger = NULL;
	struct lttng_trigger *rotation_completed_trigger = NULL;
	enum lttng_condition_status condition_status;
	enum lttng_notification_channel_status notification_channel_status;
	enum lttng_error_code ret_code;

	notify = lttng_action_notify_create();
	if (!notify) {
		ret = -1;
		goto end;
	}

	/* Create rotation ongoing and completed conditions. */
	rotation_ongoing_condition = lttng_condition_session_rotation_ongoing_create();
	ok(rotation_ongoing_condition, "Create session rotation ongoing condition");
	if (!rotation_ongoing_condition) {
		ret = -1;
		goto end;
	}
	ret = test_condition(rotation_ongoing_condition, "rotation ongoing");
	if (ret) {
		goto end;
	}
	condition_status = lttng_condition_session_rotation_set_session_name(
		rotation_ongoing_condition, session->name);
	if (condition_status != LTTNG_CONDITION_STATUS_OK) {
		ret = -1;
		diag("Failed to set session name on session rotation ongoing condition");
		goto end;
	}

	rotation_completed_condition = lttng_condition_session_rotation_completed_create();
	ok(rotation_completed_condition, "Create session rotation completed condition");
	if (!rotation_completed_condition) {
		ret = -1;
		goto end;
	}
	ret = test_condition(rotation_completed_condition, "rotation completed");
	if (ret) {
		diag("Failed to set session name on session rotation completed condition");
		goto end;
	}
	condition_status = lttng_condition_session_rotation_set_session_name(
		rotation_completed_condition, session->name);
	if (condition_status != LTTNG_CONDITION_STATUS_OK) {
		ret = -1;
		goto end;
	}

	notification_channel_status = lttng_notification_channel_subscribe(
		notification_channel, rotation_ongoing_condition);
	ok(notification_channel_status == LTTNG_NOTIFICATION_CHANNEL_STATUS_OK,
	   "Subscribe to session rotation ongoing notifications");
	if (notification_channel_status != LTTNG_NOTIFICATION_CHANNEL_STATUS_OK) {
		ret = -1;
		goto end;
	}
	notification_channel_status = lttng_notification_channel_subscribe(
		notification_channel, rotation_completed_condition);
	ok(notification_channel_status == LTTNG_NOTIFICATION_CHANNEL_STATUS_OK,
	   "Subscribe to session rotation completed notifications");
	if (notification_channel_status != LTTNG_NOTIFICATION_CHANNEL_STATUS_OK) {
		ret = -1;
		goto end;
	}

	/* Create rotation ongoing and completed triggers. */
	rotation_ongoing_trigger = lttng_trigger_create(rotation_ongoing_condition, notify);
	ok(rotation_ongoing_trigger, "Create a rotation ongoing notification trigger");
	if (!rotation_ongoing_trigger) {
		ret = -1;
		goto end;
	}

	rotation_completed_trigger = lttng_trigger_create(rotation_completed_condition, notify);
	ok(rotation_completed_trigger, "Create a rotation completed notification trigger");
	if (!rotation_completed_trigger) {
		ret = -1;
		goto end;
	}

	/* Register rotation ongoing and completed triggers. */
	ret_code = lttng_register_trigger_with_automatic_name(rotation_ongoing_trigger);
	ok(ret_code == LTTNG_OK, "Registered session rotation ongoing trigger");
	if (ret_code != LTTNG_OK) {
		ret = -ret_code;
		goto end;
	}

	ret_code = lttng_register_trigger_with_automatic_name(rotation_completed_trigger);
	ok(ret_code == LTTNG_OK, "Registered session rotation completed trigger");
	if (ret_code != LTTNG_OK) {
		ret = -ret_code;
		goto end;
	}

end:
	lttng_trigger_destroy(rotation_ongoing_trigger);
	lttng_trigger_destroy(rotation_completed_trigger);
	lttng_condition_destroy(rotation_ongoing_condition);
	lttng_condition_destroy(rotation_completed_condition);
	lttng_action_destroy(notify);
	return ret;
}

static int test_notification(struct lttng_notification_channel *notification_channel,
			     const struct session *session,
			     const char *expected_notification_type_name,
			     enum lttng_condition_type expected_condition_type)
{
	int ret = 0;
	bool notification_pending;
	enum lttng_notification_channel_status notification_channel_status;
	enum lttng_condition_status condition_status;
	enum lttng_evaluation_status evaluation_status;
	enum lttng_trace_archive_location_status location_status;
	enum lttng_condition_type condition_type;
	struct lttng_notification *notification = NULL;
	const struct lttng_condition *condition;
	const struct lttng_evaluation *evaluation;
	const char *session_name = NULL;
	const struct lttng_trace_archive_location *location = NULL;
	uint64_t rotation_id = UINT64_MAX;
	const char *chunk_path = NULL;

	notification_channel_status = lttng_notification_channel_has_pending_notification(
		notification_channel, &notification_pending);
	ok(notification_channel_status == LTTNG_NOTIFICATION_CHANNEL_STATUS_OK,
	   "Check for %s notification pending on notification channel",
	   expected_notification_type_name);
	if (notification_channel_status != LTTNG_NOTIFICATION_CHANNEL_STATUS_OK) {
		ret = -1;
		goto end;
	}

	ok(notification_pending,
	   "Session %s notification is pending on notification channel",
	   expected_notification_type_name);
	if (!notification_pending) {
		ret = -1;
		goto end;
	}

	notification_channel_status = lttng_notification_channel_get_next_notification(
		notification_channel, &notification);
	ok(notification_channel_status == LTTNG_NOTIFICATION_CHANNEL_STATUS_OK && notification,
	   "Get %s notification from notification channel",
	   expected_notification_type_name);
	if (notification_channel_status != LTTNG_NOTIFICATION_CHANNEL_STATUS_OK || !notification) {
		ret = -1;
		goto end;
	}

	condition = lttng_notification_get_condition(notification);
	if (!condition) {
		diag("Failed to get notification condition");
		ret = -1;
		goto end;
	}

	condition_type = lttng_condition_get_type(condition);
	ok(condition_type == expected_condition_type,
	   "Notification condition obtained from notification channel is of type \"%s\"",
	   expected_notification_type_name);
	if (condition_type != expected_condition_type) {
		ret = -1;
		goto end;
	}

	condition_status =
		lttng_condition_session_rotation_get_session_name(condition, &session_name);
	ok(condition_status == LTTNG_CONDITION_STATUS_OK && session_name &&
		   !strcmp(session_name, session->name),
	   "Condition obtained from notification has the correct session name assigned");
	if (condition_status != LTTNG_CONDITION_STATUS_OK || !session_name) {
		ret = -1;
		goto end;
	}

	evaluation = lttng_notification_get_evaluation(notification);
	if (!evaluation) {
		diag("Failed to get notification evaluation");
		ret = -1;
		goto end;
	}
	condition_type = lttng_evaluation_get_type(evaluation);
	ok(condition_type == expected_condition_type,
	   "Condition evaluation obtained from notification channel is of type \"%s\"",
	   expected_notification_type_name);
	if (condition_type != expected_condition_type) {
		ret = -1;
		goto end;
	}

	evaluation_status = lttng_evaluation_session_rotation_get_id(evaluation, &rotation_id);
	ok(evaluation_status == LTTNG_EVALUATION_STATUS_OK,
	   "Get %s id from notification evaluation",
	   expected_notification_type_name);
	if (evaluation_status != LTTNG_EVALUATION_STATUS_OK) {
		ret = -1;
		goto end;
	}

	if (expected_condition_type != LTTNG_CONDITION_TYPE_SESSION_ROTATION_COMPLETED) {
		/*
		 * Remaining tests only apply to "session rotation completed"
		 * notifications.
		 */
		goto end;
	}

	evaluation_status =
		lttng_evaluation_session_rotation_completed_get_location(evaluation, &location);
	ok(evaluation_status == LTTNG_EVALUATION_STATUS_OK && location,
	   "Get session %s chunk location from evaluation",
	   expected_notification_type_name);
	if (evaluation_status != LTTNG_EVALUATION_STATUS_OK || !location) {
		ret = -1;
		goto end;
	}

	ok(lttng_trace_archive_location_get_type(location) ==
		   LTTNG_TRACE_ARCHIVE_LOCATION_TYPE_LOCAL,
	   "Location returned from the session rotation completed notification is of type 'local'");

	location_status =
		lttng_trace_archive_location_local_get_absolute_path(location, &chunk_path);
	ok(location_status == LTTNG_TRACE_ARCHIVE_LOCATION_STATUS_OK && chunk_path,
	   "Retrieved path from location returned by the session rotation completed notification");
	diag("Chunk available at %s", chunk_path ? chunk_path : "NULL");

	ok(chunk_path && !strncmp(session->output_path, chunk_path, strlen(session->output_path)),
	   "Returned path from location starts with the output path");

end:
	lttng_notification_destroy(notification);
	return ret;
}

static int
test_rotation_ongoing_notification(struct lttng_notification_channel *notification_channel,
				   struct session *session)
{
	return test_notification(notification_channel,
				 session,
				 "rotation ongoing",
				 LTTNG_CONDITION_TYPE_SESSION_ROTATION_ONGOING);
}

static int
test_rotation_completed_notification(struct lttng_notification_channel *notification_channel,
				     struct session *session)
{
	return test_notification(notification_channel,
				 session,
				 "rotation completed",
				 LTTNG_CONDITION_TYPE_SESSION_ROTATION_COMPLETED);
}

int main(int argc, const char *argv[])
{
	int ret = 0;
	struct session session = { 0 };
	struct lttng_notification_channel *notification_channel = NULL;
	struct lttng_rotation_handle *rotation_handle = NULL;
	enum lttng_rotation_status rotation_status;
	enum lttng_rotation_state rotation_state = LTTNG_ROTATION_STATE_NO_ROTATION;

	if (argc != 3) {
		puts("Usage: rotation SESSION_NAME SESSION_OUTPUT_PATH");
		ret = 1;
		goto error;
	}

	session.name = argv[1];
	session.output_path = argv[2];

	plan_tests(TEST_COUNT);

	notification_channel =
		lttng_notification_channel_create(lttng_session_daemon_notification_endpoint);
	if (!notification_channel) {
		diag("Failed to create notification channel");
		ret = -1;
		goto error;
	}

	ret = setup_rotation_trigger(&session, notification_channel);
	if (ret) {
		goto error;
	}

	/* Start rotation and wait for its completion. */
	ret = lttng_rotate_session(session.name, NULL, &rotation_handle);
	ok(ret >= 0 && rotation_handle, "Start rotation of session \"%s\"", session.name);
	if (ret < 0 || !rotation_handle) {
		goto error;
	}

	do {
		rotation_status = lttng_rotation_handle_get_state(rotation_handle, &rotation_state);
	} while (rotation_state == LTTNG_ROTATION_STATE_ONGOING &&
		 rotation_status == LTTNG_ROTATION_STATUS_OK);
	ok(rotation_status == LTTNG_ROTATION_STATUS_OK &&
		   rotation_state == LTTNG_ROTATION_STATE_COMPLETED,
	   "Complete rotation of session \"%s\"",
	   session.name);

	/*
	 * After a rotation has completed, we can expect two notifications to
	 * be queued:
	 *  - Session rotation ongoing
	 *  - Session rotation completed
	 */
	ret = test_rotation_ongoing_notification(notification_channel, &session);
	if (ret) {
		goto error;
	}

	ret = test_rotation_completed_notification(notification_channel, &session);
	if (ret) {
		goto error;
	}
error:
	lttng_notification_channel_destroy(notification_channel);
	lttng_rotation_handle_destroy(rotation_handle);
	return exit_status();
}
