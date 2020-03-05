/*
 * Copyright (C) 2020 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 *
 */

#include <getopt.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#include <lttng/condition/event-rule.h>
#include <lttng/lttng.h>

#include "utils.h"

static struct option long_options[] =
{
	/* These options set a flag. */
	{"trigger", required_argument, 0, 'i'},
	{"sync-after-notif-register", required_argument, 0, 'a'},
	{0, 0, 0, 0}
};

static bool action_group_contains_notify(
		const struct lttng_action *action_group)
{
	unsigned int i, count;
	enum lttng_action_status status =
			lttng_action_group_get_count(action_group, &count);

	if (status != LTTNG_ACTION_STATUS_OK) {
		printf("Failed to get action count from action group\n");
		exit(1);
	}

	for (i = 0; i < count; i++) {
		const struct lttng_action *action =
				lttng_action_group_get_at_index(
						action_group, i);
		const enum lttng_action_type action_type =
				lttng_action_get_type(action);

		if (action_type == LTTNG_ACTION_TYPE_NOTIFY) {
			return true;
		}
	}
	return false;
}

static bool is_expected_trigger_name(const char *expected_trigger_name,
		struct lttng_notification *notification)
{
	int ret = false;
	const struct lttng_evaluation *evaluation =
			lttng_notification_get_evaluation(notification);
	const enum lttng_condition_type type =
			lttng_evaluation_get_type(evaluation);

	switch (type) {
	case LTTNG_CONDITION_TYPE_SESSION_CONSUMED_SIZE:
	case LTTNG_CONDITION_TYPE_BUFFER_USAGE_LOW:
	case LTTNG_CONDITION_TYPE_BUFFER_USAGE_HIGH:
	case LTTNG_CONDITION_TYPE_SESSION_ROTATION_ONGOING:
	case LTTNG_CONDITION_TYPE_SESSION_ROTATION_COMPLETED:
		break;
	case LTTNG_CONDITION_TYPE_EVENT_RULE_HIT:
	{
		const char *trigger_name;
		enum lttng_evaluation_status evaluation_status;

		evaluation_status =
				lttng_evaluation_event_rule_get_trigger_name(
						evaluation, &trigger_name);
		if (evaluation_status != LTTNG_EVALUATION_STATUS_OK) {
			fprintf(stderr, "Failed to get trigger name of event rule notification\n");
			ret = -1;
			break;
		}

		ret = true;
		break;
	}
	default:
		fprintf(stderr, "Unknown notification type (%d)\n", type);
	}

	return ret;
}

int main(int argc, char **argv)
{
	int ret;
	int option;
	int option_index;
	const char *expected_trigger_name = NULL;
	struct lttng_triggers *triggers = NULL;
	unsigned int count, i, subcription_count = 0;
	enum lttng_trigger_status trigger_status;
	char *after_notif_register_file_path = NULL;
	struct lttng_notification_channel *notification_channel = NULL;

	while ((option = getopt_long(argc, argv, "a:t:",
			long_options, &option_index)) != -1) {
		switch (option) {
		case 'a':
			after_notif_register_file_path = strdup(optarg);
			break;
		case 't':
			expected_trigger_name = strdup(optarg);
			break;
		case '?':
			/* getopt_long already printed an error message. */
		default:
			ret = -1;
			goto end;
		}
	}

	if (optind != argc) {
		ret = -1;
		goto end;
	}


	notification_channel = lttng_notification_channel_create(
			lttng_session_daemon_notification_endpoint);
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
		const struct lttng_trigger *trigger =
				lttng_triggers_get_at_index(triggers, i);
		const struct lttng_condition *condition =
				lttng_trigger_get_const_condition(trigger);
		const struct lttng_action *action =
				lttng_trigger_get_const_action(trigger);
		const enum lttng_action_type action_type =
				lttng_action_get_type(action);
		enum lttng_notification_channel_status channel_status;
		const char *trigger_name = NULL;

		lttng_trigger_get_name(trigger, &trigger_name);
		if (strcmp(trigger_name, expected_trigger_name)) {
			continue;
		}

		if (!((action_type == LTTNG_ACTION_TYPE_GROUP &&
				      action_group_contains_notify(action)) ||
				    action_type == LTTNG_ACTION_TYPE_NOTIFY)) {
			/* "The action of trigger is not notify, skipping. */
			continue;
		}

		channel_status = lttng_notification_channel_subscribe(
				notification_channel, condition);
		if (channel_status) {
			fprintf(stderr, "Failed to subscribe to notifications of trigger \"%s\"\n",
					trigger_name);
			ret = -1;
			goto end;
		}

		subcription_count++;
	}

	if (subcription_count == 0) {
		printf("No matching trigger with a notify action found.\n");
		ret = 0;
		goto end;
	}


	/*
	 * We registered to the notification of our target trigger. We can now
	 * create the sync file to signify that we are ready.
	 */
	ret = create_file(after_notif_register_file_path);
	if (ret != 0) {
		goto end;
	}

	for (;;) {
		struct lttng_notification *notification;
		enum lttng_notification_channel_status channel_status;

		channel_status =
				lttng_notification_channel_get_next_notification(
						notification_channel,
						&notification);
		switch (channel_status) {
		case LTTNG_NOTIFICATION_CHANNEL_STATUS_NOTIFICATIONS_DROPPED:
			printf("Dropped notification\n");
			break;
		case LTTNG_NOTIFICATION_CHANNEL_STATUS_INTERRUPTED:
			ret = 0;
			goto end;
		case LTTNG_NOTIFICATION_CHANNEL_STATUS_OK:
			break;
		case LTTNG_NOTIFICATION_CHANNEL_STATUS_CLOSED:
			printf("Notification channel was closed by peer.\n");
			break;
		default:
			fprintf(stderr, "A communication error occurred on the notification channel.\n");
			ret = -1;
			goto end;
		}

		ret = is_expected_trigger_name(expected_trigger_name,
				notification);
		lttng_notification_destroy(notification);
		if (ret) {
			ret = 0;
			goto end;
		}
	}
end:
	lttng_triggers_destroy(triggers);
	lttng_notification_channel_destroy(notification_channel);
	return !!ret;
}
