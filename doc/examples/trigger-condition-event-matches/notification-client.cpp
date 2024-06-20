/*
 * Copyright (C) 2020 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 *
 */

#include <common/macros.hpp>

#include <lttng/lttng.h>

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

static int print_capture(const struct lttng_condition *condition,
			 const struct lttng_event_field_value *capture,
			 unsigned int indent_level);
static int print_array(const struct lttng_condition *condition,
		       const struct lttng_event_field_value *array,
		       unsigned int indent_level);

static void indent(unsigned int indentation_level)
{
	unsigned int i;
	for (i = 0; i < indentation_level; i++) {
		printf(" ");
	}
}

static void print_one_event_expr(const struct lttng_event_expr *event_expr)
{
	enum lttng_event_expr_type type;

	type = lttng_event_expr_get_type(event_expr);

	switch (type) {
	case LTTNG_EVENT_EXPR_TYPE_EVENT_PAYLOAD_FIELD:
	{
		const char *name;

		name = lttng_event_expr_event_payload_field_get_name(event_expr);
		printf("%s", name);

		break;
	}

	case LTTNG_EVENT_EXPR_TYPE_CHANNEL_CONTEXT_FIELD:
	{
		const char *name;

		name = lttng_event_expr_channel_context_field_get_name(event_expr);
		printf("$ctx.%s", name);

		break;
	}

	case LTTNG_EVENT_EXPR_TYPE_APP_SPECIFIC_CONTEXT_FIELD:
	{
		const char *provider_name;
		const char *type_name;

		provider_name =
			lttng_event_expr_app_specific_context_field_get_provider_name(event_expr);
		type_name = lttng_event_expr_app_specific_context_field_get_type_name(event_expr);

		printf("$app.%s:%s", provider_name, type_name);

		break;
	}

	case LTTNG_EVENT_EXPR_TYPE_ARRAY_FIELD_ELEMENT:
	{
		unsigned int index;
		const struct lttng_event_expr *parent_expr;
		enum lttng_event_expr_status status;

		parent_expr = lttng_event_expr_array_field_element_get_parent_expr(event_expr);
		LTTNG_ASSERT(parent_expr != nullptr);

		print_one_event_expr(parent_expr);

		status = lttng_event_expr_array_field_element_get_index(event_expr, &index);
		LTTNG_ASSERT(status == LTTNG_EVENT_EXPR_STATUS_OK);

		printf("[%u]", index);

		break;
	}

	default:
		abort();
	}
}

static bool action_group_contains_notify(const struct lttng_action *action_group)
{
	unsigned int i, count;
	const lttng_action_status status = lttng_action_list_get_count(action_group, &count);

	if (status != LTTNG_ACTION_STATUS_OK) {
		printf("Failed to get action count from action group\n");
		exit(1);
	}

	for (i = 0; i < count; i++) {
		const struct lttng_action *action = lttng_action_list_get_at_index(action_group, i);
		const enum lttng_action_type action_type = lttng_action_get_type(action);

		if (action_type == LTTNG_ACTION_TYPE_NOTIFY) {
			return true;
		}
	}
	return false;
}

static int print_capture(const struct lttng_condition *condition,
			 const struct lttng_event_field_value *capture,
			 unsigned int indent_level)
{
	int ret = 0;
	enum lttng_event_field_value_status event_field_status;
	uint64_t u_val;
	int64_t s_val;
	double d_val;
	const char *string_val = nullptr;

	switch (lttng_event_field_value_get_type(capture)) {
	case LTTNG_EVENT_FIELD_VALUE_TYPE_UNSIGNED_INT:
	{
		event_field_status =
			lttng_event_field_value_unsigned_int_get_value(capture, &u_val);
		if (event_field_status != LTTNG_EVENT_FIELD_VALUE_STATUS_OK) {
			ret = 1;
			goto end;
		}

		printf("[Unsigned int] %" PRIu64, u_val);
		break;
	}
	case LTTNG_EVENT_FIELD_VALUE_TYPE_SIGNED_INT:
	{
		event_field_status = lttng_event_field_value_signed_int_get_value(capture, &s_val);
		if (event_field_status != LTTNG_EVENT_FIELD_VALUE_STATUS_OK) {
			ret = 1;
			goto end;
		}

		printf("[Signed int]  %" PRId64, s_val);
		break;
	}
	case LTTNG_EVENT_FIELD_VALUE_TYPE_UNSIGNED_ENUM:
	{
		event_field_status =
			lttng_event_field_value_unsigned_int_get_value(capture, &u_val);
		if (event_field_status != LTTNG_EVENT_FIELD_VALUE_STATUS_OK) {
			ret = 1;
			goto end;
		}

		printf("[Unsigned enum] %" PRIu64, u_val);
		break;
	}
	case LTTNG_EVENT_FIELD_VALUE_TYPE_SIGNED_ENUM:
	{
		event_field_status = lttng_event_field_value_signed_int_get_value(capture, &s_val);
		if (event_field_status != LTTNG_EVENT_FIELD_VALUE_STATUS_OK) {
			ret = 1;
			goto end;
		}

		printf("[Signed enum] %" PRId64, s_val);
		break;
	}
	case LTTNG_EVENT_FIELD_VALUE_TYPE_REAL:
	{
		event_field_status = lttng_event_field_value_real_get_value(capture, &d_val);
		if (event_field_status != LTTNG_EVENT_FIELD_VALUE_STATUS_OK) {
			ret = 1;
			goto end;
		}

		printf("[Real] %lf", d_val);
		break;
	}
	case LTTNG_EVENT_FIELD_VALUE_TYPE_STRING:
	{
		event_field_status = lttng_event_field_value_string_get_value(capture, &string_val);
		if (event_field_status != LTTNG_EVENT_FIELD_VALUE_STATUS_OK) {
			ret = 1;
			goto end;
		}

		printf("[String] %s", string_val);
		break;
	}
	case LTTNG_EVENT_FIELD_VALUE_TYPE_ARRAY:
		printf("[Array] [\n");
		print_array(condition, capture, indent_level);
		indent(indent_level);
		printf("]\n");
		break;
	case LTTNG_EVENT_FIELD_VALUE_TYPE_UNKNOWN:
	case LTTNG_EVENT_FIELD_VALUE_TYPE_INVALID:
	default:
		ret = 1;
		break;
	}

end:
	return ret;
}

static void print_unavailabe()
{
	printf("Capture unavailable");
}

static int print_array(const struct lttng_condition *condition,
		       const struct lttng_event_field_value *array,
		       unsigned int indent_level)
{
	int ret = 0;
	enum lttng_event_field_value_status event_field_status;
	unsigned int captured_field_count;

	event_field_status = lttng_event_field_value_array_get_length(array, &captured_field_count);
	if (event_field_status != LTTNG_EVENT_FIELD_VALUE_STATUS_OK) {
		ret = 1;
		goto end;
	}

	for (unsigned int i = 0; i < captured_field_count; i++) {
		const struct lttng_event_field_value *captured_field = nullptr;
		const struct lttng_event_expr *expr =
			lttng_condition_event_rule_matches_get_capture_descriptor_at_index(
				condition, i);
		LTTNG_ASSERT(expr);

		indent(indent_level + 1);

		printf("Field: ");
		print_one_event_expr(expr);
		printf(" Value: ");

		event_field_status = lttng_event_field_value_array_get_element_at_index(
			array, i, &captured_field);
		if (event_field_status != LTTNG_EVENT_FIELD_VALUE_STATUS_OK) {
			if (event_field_status == LTTNG_EVENT_FIELD_VALUE_STATUS_UNAVAILABLE) {
				print_unavailabe();
			} else {
				ret = 1;
				goto end;
			}
		} else {
			print_capture(condition, captured_field, indent_level + 1);
		}

		if (i + 1 < captured_field_count) {
			printf(",");
		} else {
			printf(".");
		}
		printf("\n");
	}

end:
	return ret;
}

static int print_captures(struct lttng_notification *notification)
{
	int ret = 0;
	const struct lttng_evaluation *evaluation = lttng_notification_get_evaluation(notification);
	const struct lttng_condition *condition = lttng_notification_get_condition(notification);

	/* Status */
	enum lttng_condition_status condition_status;
	enum lttng_evaluation_event_rule_matches_status evaluation_status;

	const struct lttng_event_field_value *captured_field_array = nullptr;
	unsigned int expected_capture_field_count;

	LTTNG_ASSERT(lttng_evaluation_get_type(evaluation) ==
		     LTTNG_CONDITION_TYPE_EVENT_RULE_MATCHES);

	condition_status = lttng_condition_event_rule_matches_get_capture_descriptor_count(
		condition, &expected_capture_field_count);
	if (condition_status != LTTNG_CONDITION_STATUS_OK) {
		ret = 1;
		goto end;
	}

	if (expected_capture_field_count == 0) {
		ret = 0;
		goto end;
	}

	evaluation_status = lttng_evaluation_event_rule_matches_get_captured_values(
		evaluation, &captured_field_array);
	if (evaluation_status != LTTNG_EVALUATION_EVENT_RULE_MATCHES_STATUS_OK) {
		ret = 1;
		goto end;
	}

	printf("Captured field values:\n");
	print_array(condition, captured_field_array, 1);
end:
	return ret;
}

static int print_notification(struct lttng_notification *notification)
{
	int ret = 0;
	const struct lttng_evaluation *evaluation = lttng_notification_get_evaluation(notification);
	const enum lttng_condition_type type = lttng_evaluation_get_type(evaluation);

	switch (type) {
	case LTTNG_CONDITION_TYPE_SESSION_CONSUMED_SIZE:
		printf("Received consumed size notification\n");
		break;
	case LTTNG_CONDITION_TYPE_BUFFER_USAGE_LOW:
	case LTTNG_CONDITION_TYPE_BUFFER_USAGE_HIGH:
		printf("Received buffer usage notification\n");
		break;
	case LTTNG_CONDITION_TYPE_SESSION_ROTATION_ONGOING:
		printf("Received session rotation ongoing notification\n");
		break;
	case LTTNG_CONDITION_TYPE_SESSION_ROTATION_COMPLETED:
		printf("Received session rotation completed notification\n");
		break;
	case LTTNG_CONDITION_TYPE_EVENT_RULE_MATCHES:
	{
		const char *trigger_name;
		enum lttng_trigger_status trigger_status;
		char time_str[64];
		struct timeval tv;
		time_t the_time;
		const struct lttng_trigger *trigger = nullptr;

		gettimeofday(&tv, nullptr);
		the_time = tv.tv_sec;

		strftime(time_str, sizeof(time_str), "[%m-%d-%Y] %T", localtime(&the_time));
		printf("%s.%ld - ", time_str, tv.tv_usec);

		trigger = lttng_notification_get_trigger(notification);
		if (!trigger) {
			fprintf(stderr, "Failed to retrieve notification's trigger");
			goto end;
		}

		trigger_status = lttng_trigger_get_name(trigger, &trigger_name);
		if (trigger_status != LTTNG_TRIGGER_STATUS_OK) {
			fprintf(stderr, "Failed to retrieve trigger's name");
			goto end;
		}

		printf("Received notification of event rule matches trigger \"%s\"\n",
		       trigger_name);
		ret = print_captures(notification);
		break;
	}
	default:
		fprintf(stderr, "Unknown notification type (%d)\n", type);
	}

end:
	return ret;
}

int main(int argc, char **argv)
{
	int ret;
	struct lttng_triggers *triggers = nullptr;
	unsigned int count, i, j, subcription_count = 0, trigger_count;
	enum lttng_trigger_status trigger_status;
	struct lttng_notification_channel *notification_channel = nullptr;

	if (argc < 2) {
		fprintf(stderr, "Missing trigger name(s)\n");
		fprintf(stderr, "Usage: notification-client TRIGGER_NAME ...");
		ret = -1;
		goto end;
	}

	trigger_count = argc - 1;

	notification_channel =
		lttng_notification_channel_create(lttng_session_daemon_notification_endpoint);
	if (!notification_channel) {
		fprintf(stderr, "Failed to create notification channel\n");
		ret = -1;
		goto end;
	}

	ret = lttng_list_triggers(&triggers);
	if (ret != LTTNG_OK) {
		fprintf(stderr, "Failed to list triggers\n");
		goto end;
	}

	trigger_status = lttng_triggers_get_count(triggers, &count);
	if (trigger_status != LTTNG_TRIGGER_STATUS_OK) {
		fprintf(stderr, "Failed to get trigger count\n");
		ret = -1;
		goto end;
	}

	for (i = 0; i < count; i++) {
		const struct lttng_trigger *trigger = lttng_triggers_get_at_index(triggers, i);
		const struct lttng_condition *condition =
			lttng_trigger_get_const_condition(trigger);
		const struct lttng_action *action = lttng_trigger_get_const_action(trigger);
		const enum lttng_action_type action_type = lttng_action_get_type(action);
		enum lttng_notification_channel_status channel_status;
		const char *trigger_name = nullptr;
		bool subscribe = false;

		lttng_trigger_get_name(trigger, &trigger_name);
		for (j = 0; j < trigger_count; j++) {
			if (!strcmp(trigger_name, argv[j + 1])) {
				subscribe = true;
				break;
			}
		}

		if (!subscribe) {
			continue;
		}

		if ((action_type != LTTNG_ACTION_TYPE_LIST ||
		     !action_group_contains_notify(action)) &&
		    action_type != LTTNG_ACTION_TYPE_NOTIFY) {
			printf("The action of trigger \"%s\" is not \"notify\", skipping.\n",
			       trigger_name);
			continue;
		}

		channel_status =
			lttng_notification_channel_subscribe(notification_channel, condition);
		if (channel_status == LTTNG_NOTIFICATION_CHANNEL_STATUS_ALREADY_SUBSCRIBED) {
			continue;
		}
		if (channel_status) {
			fprintf(stderr,
				"Failed to subscribe to notifications of trigger \"%s\"\n",
				trigger_name);
			ret = -1;
			goto end;
		}

		printf("Subscribed to notifications of trigger \"%s\"\n", trigger_name);
		subcription_count++;
	}

	if (subcription_count == 0) {
		printf("No matching trigger with a notify action found.\n");
		ret = 0;
		goto end;
	}

	for (;;) {
		struct lttng_notification *notification;
		enum lttng_notification_channel_status channel_status;

		channel_status = lttng_notification_channel_get_next_notification(
			notification_channel, &notification);
		switch (channel_status) {
		case LTTNG_NOTIFICATION_CHANNEL_STATUS_NOTIFICATIONS_DROPPED:
			printf("Dropped notification\n");
			break;
		case LTTNG_NOTIFICATION_CHANNEL_STATUS_INTERRUPTED:
			ret = 0;
			goto end;
		case LTTNG_NOTIFICATION_CHANNEL_STATUS_OK:
			ret = print_notification(notification);
			lttng_notification_destroy(notification);
			if (ret) {
				goto end;
			}
			break;
		case LTTNG_NOTIFICATION_CHANNEL_STATUS_CLOSED:
			printf("Notification channel was closed by peer.\n");
			break;
		default:
			fprintf(stderr,
				"A communication error occurred on the notification channel.\n");
			ret = -1;
			goto end;
		}
	}
end:
	lttng_triggers_destroy(triggers);
	lttng_notification_channel_destroy(notification_channel);
	return !!ret;
}
