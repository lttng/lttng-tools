/*
 * Copyright (C) 2020 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 *
 */

#include "utils.h"

#include <common/error.hpp>

#include <lttng/action/list-internal.hpp>
#include <lttng/condition/event-rule-matches.h>
#include <lttng/lttng.h>

#include <getopt.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

static struct option long_options[] = {
	/* These options set a flag. */
	{ "trigger", required_argument, 0, 't' },
	{ "sync-after-notif-register", required_argument, 0, 'a' },
	/* Default alue for count is 1 */
	{ "count", required_argument, 0, 'b' },
	/*
	 * When end-trigger is present the reception loop is exited only when a
	 * notification matching the end trigger is received.
	 * Otherwise the loop is exited when the count of notification received
	 * for `trigger` math the `count` argument.
	 */
	{ "end-trigger", required_argument, 0, 'c' },
	{ 0, 0, 0, 0 }
};

static bool action_list_contains_notify(const struct lttng_action *action_list)
{
	for (auto sub_action : lttng::ctl::const_action_list_view(action_list)) {
		if (lttng_action_get_type(sub_action) == LTTNG_ACTION_TYPE_NOTIFY) {
			return true;
		}
	}

	return false;
}

/* Only expects named triggers. */
static bool is_trigger_name(const char *expected_trigger_name,
			    struct lttng_notification *notification)
{
	const char *trigger_name = NULL;
	enum lttng_trigger_status trigger_status;
	const struct lttng_trigger *trigger;
	bool names_match;

	trigger = lttng_notification_get_trigger(notification);
	if (!trigger) {
		fprintf(stderr, "Failed to get trigger from notification\n");
		names_match = false;
		goto end;
	}

	trigger_status = lttng_trigger_get_name(trigger, &trigger_name);
	if (trigger_status != LTTNG_TRIGGER_STATUS_OK) {
		fprintf(stderr, "Failed to get name from notification's trigger\n");
		names_match = false;
		goto end;
	}

	names_match = strcmp(expected_trigger_name, trigger_name) == 0;
	if (!names_match) {
		fprintf(stderr,
			"Got an unexpected trigger name: name = '%s', expected name = '%s'\n",
			trigger_name,
			expected_trigger_name);
	}
end:
	return names_match;
}

static int _main(int argc, char **argv)
{
	int ret;
	int option;
	int option_index;
	char *expected_trigger_name = NULL;
	char *end_trigger_name = NULL;
	struct lttng_triggers *triggers = NULL;
	unsigned int count, i, subcription_count = 0;
	enum lttng_trigger_status trigger_status;
	char *after_notif_register_file_path = NULL;
	struct lttng_notification_channel *notification_channel = NULL;
	int expected_notifications = 1, notification_count = 0;

	while ((option = getopt_long(argc, argv, "a:b:c:t:", long_options, &option_index)) != -1) {
		switch (option) {
		case 'a':
			after_notif_register_file_path = strdup(optarg);
			break;
		case 'b':
			expected_notifications = atoi(optarg);
			break;
		case 'c':
			end_trigger_name = strdup(optarg);
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
		ret = -1;
		goto end;
	}

	trigger_status = lttng_triggers_get_count(triggers, &count);
	if (trigger_status != LTTNG_TRIGGER_STATUS_OK) {
		fprintf(stderr, "Failed to get trigger count\n");
		ret = -1;
		goto end;
	}

	/* Look for the trigger we want to subscribe to. */
	for (i = 0; i < count; i++) {
		const struct lttng_trigger *trigger = lttng_triggers_get_at_index(triggers, i);
		const struct lttng_condition *condition =
			lttng_trigger_get_const_condition(trigger);
		const struct lttng_action *action = lttng_trigger_get_const_action(trigger);
		const enum lttng_action_type action_type = lttng_action_get_type(action);
		enum lttng_notification_channel_status channel_status;
		const char *trigger_name = NULL;

		lttng_trigger_get_name(trigger, &trigger_name);
		if (strcmp(trigger_name, expected_trigger_name) != 0) {
			/* Might match the end event trigger */
			if (end_trigger_name != NULL &&
			    strcmp(trigger_name, end_trigger_name) != 0) {
				continue;
			}
		}
		if (!((action_type == LTTNG_ACTION_TYPE_LIST &&
		       action_list_contains_notify(action)) ||
		      action_type == LTTNG_ACTION_TYPE_NOTIFY)) {
			/* "The action of trigger is not notify, skipping. */
			continue;
		}

		channel_status =
			lttng_notification_channel_subscribe(notification_channel, condition);
		if (channel_status) {
			fprintf(stderr,
				"Failed to subscribe to notifications of trigger \"%s\"\n",
				trigger_name);
			ret = -1;
			goto end;
		}

		subcription_count++;
	}

	if (subcription_count == 0) {
		fprintf(stderr, "No matching trigger with a notify action found.\n");
		ret = -1;
		goto end;
	}

	if (end_trigger_name != NULL && subcription_count != 2) {
		fprintf(stderr, "No matching end event trigger with a notify action found.\n");
		ret = -1;
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

		channel_status = lttng_notification_channel_get_next_notification(
			notification_channel, &notification);
		switch (channel_status) {
		case LTTNG_NOTIFICATION_CHANNEL_STATUS_NOTIFICATIONS_DROPPED:
			printf("Dropped notification\n");
			ret = -1;
			goto end;
		case LTTNG_NOTIFICATION_CHANNEL_STATUS_INTERRUPTED:
			ret = -1;
			goto end;
		case LTTNG_NOTIFICATION_CHANNEL_STATUS_OK:
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

		/* Early exit check. */
		if (end_trigger_name != NULL && is_trigger_name(end_trigger_name, notification)) {
			/* Exit the loop immediately. */
			printf("Received end event notification from trigger %s\n",
			       end_trigger_name);
			lttng_notification_destroy(notification);
			goto evaluate_success;
		}

		ret = is_trigger_name(expected_trigger_name, notification);
		lttng_notification_destroy(notification);
		if (!ret) {
			ret = -1;
			goto end;
		}

		printf("Received event notification from trigger %s\n", expected_trigger_name);
		notification_count++;
		if (end_trigger_name == NULL && expected_notifications == notification_count) {
			/*
			 * Here the loop exit is controlled by the number of
			 * notification and not by the reception of the end
			 * event trigger notification. This represent the
			 * default behavior.
			 *
			 */
			goto evaluate_success;
		}
	}

evaluate_success:
	if (expected_notifications == notification_count) {
		/* Success */
		ret = 0;
	} else {
		fprintf(stderr,
			"Expected %d notification got %d\n",
			expected_notifications,
			notification_count);
		ret = 1;
	}

end:
	lttng_triggers_destroy(triggers);
	lttng_notification_channel_destroy(notification_channel);
	free(after_notif_register_file_path);
	free(end_trigger_name);
	free(expected_trigger_name);
	return !!ret;
}

int main(int argc, char **argv)
{
	try {
		return _main(argc, argv);
	} catch (const std::exception& e) {
		ERR_FMT("Unhandled exception caught by notification client: %s", e.what());
		abort();
	}
}
