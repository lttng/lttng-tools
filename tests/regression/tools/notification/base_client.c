/*
 * base_client.c
 *
 * Base client application for testing of LTTng notification API
 *
 * Copyright 2017 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <assert.h>

#include <lttng/action/action.h>
#include <lttng/action/notify.h>
#include <lttng/condition/buffer-usage.h>
#include <lttng/condition/condition.h>
#include <lttng/condition/evaluation.h>
#include <lttng/domain.h>
#include <lttng/endpoint.h>
#include <lttng/notification/channel.h>
#include <lttng/notification/notification.h>
#include <lttng/trigger/trigger.h>

static unsigned int nr_notifications = 0;
static unsigned int nr_expected_notifications = 0;
static const char *session_name = NULL;
static const char *channel_name = NULL;
static double threshold_ratio = 0.0;
static uint64_t threshold_bytes = 0;
static bool is_threshold_ratio = false;
static enum lttng_condition_type buffer_usage_type = LTTNG_CONDITION_TYPE_UNKNOWN;
static enum lttng_domain_type domain_type = LTTNG_DOMAIN_NONE;

int handle_condition(
		const struct lttng_condition *condition,
		const struct lttng_evaluation *condition_evaluation);

int parse_arguments(char **argv) {
	const char *domain_type_string = NULL;
	const char *buffer_usage_type_string = NULL;
	const char *buffer_usage_threshold_type = NULL;
	const char *buffer_usage_threshold_value = NULL;
	const char *nr_expected_notifications_string = NULL;

	session_name = argv[1];
	channel_name = argv[2];
	domain_type_string = argv[3];
	buffer_usage_type_string = argv[4];
	buffer_usage_threshold_type = argv[5];
	buffer_usage_threshold_value = argv[6];
	nr_expected_notifications_string = argv[7];

	/* Parse arguments */
	/* Domain type */
	if (!strcasecmp("LTTNG_DOMAIN_UST", domain_type_string)) {
		domain_type = LTTNG_DOMAIN_UST;
	}
	if (!strcasecmp("LTTNG_DOMAIN_KERNEL", domain_type_string)) {
		domain_type = LTTNG_DOMAIN_KERNEL;
	}
	if (domain_type == LTTNG_DOMAIN_NONE) {
		printf("error: Unknown domain type\n");
		goto error;
	}

	/* Buffer usage condition type */
	if (!strcasecmp("low", buffer_usage_type_string)) {
		buffer_usage_type = LTTNG_CONDITION_TYPE_BUFFER_USAGE_LOW;
	}
	if (!strcasecmp("high", buffer_usage_type_string)) {
		buffer_usage_type = LTTNG_CONDITION_TYPE_BUFFER_USAGE_HIGH;
	}
	if (buffer_usage_type == LTTNG_CONDITION_TYPE_UNKNOWN) {
		printf("error: Unknown condition type\n");
		goto error;
	}

	/* Ratio or bytes ? */
	if (!strcasecmp("bytes", buffer_usage_threshold_type)) {
		is_threshold_ratio = false;
		sscanf(buffer_usage_threshold_value, "%" SCNu64, &threshold_bytes);
	}

	if (!strcasecmp("ratio", buffer_usage_threshold_type)) {
		is_threshold_ratio = true;
		sscanf(buffer_usage_threshold_value, "%lf", &threshold_ratio);
	}

	/* Number of notification to expect */
	sscanf(nr_expected_notifications_string, "%d", &nr_expected_notifications);

	return 0;
error:
	return 1;
}

int main(int argc, char **argv)
{
	int ret = 0;
	enum lttng_condition_status condition_status;
	enum lttng_notification_channel_status nc_status;
	struct lttng_notification_channel *notification_channel = NULL;
	struct lttng_condition *condition = NULL;
	struct lttng_action *action = NULL;
	struct lttng_trigger *trigger = NULL;

	/*
	 * Disable buffering on stdout.
	 * Safety measure to prevent hang on the validation side since
	 * stdout is used for outside synchronization.
	 */
	setbuf(stdout, NULL);

	if (argc < 8) {
		printf("error: Missing arguments for tests\n");
		ret = 1;
		goto end;
	}

	ret = parse_arguments(argv);
	if (ret) {
		printf("error: Could not parse arguments\n");
		goto end;
	}

	/* Setup */
	notification_channel = lttng_notification_channel_create(
			lttng_session_daemon_notification_endpoint);
	if (!notification_channel) {
		printf("error: Could not create notification channel\n");
		ret = 1;
		goto end;
	}

	switch (buffer_usage_type) {
	case LTTNG_CONDITION_TYPE_BUFFER_USAGE_LOW:
		condition = lttng_condition_buffer_usage_low_create();
		break;
	case LTTNG_CONDITION_TYPE_BUFFER_USAGE_HIGH:
		condition = lttng_condition_buffer_usage_high_create();
		break;
	default:
		printf("error: Invalid buffer_usage_type\n");
		ret = 1;
		goto end;
	}

	if (!condition) {
		printf("error: Could not create condition object\n");
		ret = 1;
		goto end;
	}

	if (is_threshold_ratio) {
		condition_status = lttng_condition_buffer_usage_set_threshold_ratio(
				condition, threshold_ratio);
	} else {
		condition_status = lttng_condition_buffer_usage_set_threshold(
				condition, threshold_bytes);
	}

	if (condition_status != LTTNG_CONDITION_STATUS_OK) {
		printf("error: Could not set threshold\n");
		ret = 1;
		goto end;
	}

	condition_status = lttng_condition_buffer_usage_set_session_name(
			condition, session_name);
	if (condition_status != LTTNG_CONDITION_STATUS_OK) {
		printf("error: Could not set session name\n");
		ret = 1;
		goto end;
	}
	condition_status = lttng_condition_buffer_usage_set_channel_name(
			condition, channel_name);
	if (condition_status != LTTNG_CONDITION_STATUS_OK) {
		printf("error: Could not set channel name\n");
		ret = 1;
		goto end;
	}
	condition_status = lttng_condition_buffer_usage_set_domain_type(
			condition, domain_type);
	if (condition_status != LTTNG_CONDITION_STATUS_OK) {
		printf("error: Could not set domain type\n");
		ret = 1;
		goto end;
	}

	action = lttng_action_notify_create();
	if (!action) {
		printf("error: Could not create action notify\n");
		ret = 1;
		goto end;
	}

	trigger = lttng_trigger_create(condition, action);
	if (!trigger) {
		printf("error: Could not create trigger\n");
		ret = 1;
		goto end;
	}

	ret = lttng_register_trigger(trigger);

	/*
	 * An equivalent trigger might already be registered if an other app
	 * registered an equivalent trigger.
	 */
	if (ret < 0 && ret != -LTTNG_ERR_TRIGGER_EXISTS) {
		printf("error: %s\n", lttng_strerror(ret));
		ret = 1;
		goto end;
	}

	nc_status = lttng_notification_channel_subscribe(notification_channel, condition);
	if (nc_status != LTTNG_NOTIFICATION_CHANNEL_STATUS_OK) {
		printf("error: Could not subscribe\n");
		ret = 1;
		goto end;
	}

	/* Tell outside process that the client is ready */
	printf("sync: ready\n");

	for (;;) {
		struct lttng_notification *notification;
		enum lttng_notification_channel_status status;
		const struct lttng_evaluation *notification_evaluation;
		const struct lttng_condition *notification_condition;

		if (nr_notifications == nr_expected_notifications) {
			ret = 0;
			goto end;
		}
		/* Receive the next notification. */
		status = lttng_notification_channel_get_next_notification(
				notification_channel,
				&notification);

		switch (status) {
		case LTTNG_NOTIFICATION_CHANNEL_STATUS_OK:
			break;
		case LTTNG_NOTIFICATION_CHANNEL_STATUS_NOTIFICATIONS_DROPPED:
			ret = 1;
			printf("error: No drop should be observed during this test app\n");
			goto end;
		case LTTNG_NOTIFICATION_CHANNEL_STATUS_CLOSED:
			/*
			 * The notification channel has been closed by the
			 * session daemon. This is typically caused by a session
			 * daemon shutting down (cleanly or because of a crash).
			 */
			printf("error: Notification channel was closed\n");
			ret = 1;
			goto end;
		default:
			/* Unhandled conditions / errors. */
			printf("error: Unknown notification channel status\n");
			ret = 1;
			goto end;
		}

		notification_condition = lttng_notification_get_condition(notification);
		notification_evaluation = lttng_notification_get_evaluation(notification);

		ret = handle_condition(notification_condition, notification_evaluation);
		nr_notifications++;

		lttng_notification_destroy(notification);
		if (ret != 0) {
			goto end;
		}
	}
end:
	if (trigger) {
		lttng_unregister_trigger(trigger);
	}
	if (lttng_notification_channel_unsubscribe(notification_channel, condition)) {
		printf("error: channel unsubscribe error\n");
	}
	lttng_trigger_destroy(trigger);
	lttng_condition_destroy(condition);
	lttng_action_destroy(action);
	lttng_notification_channel_destroy(notification_channel);
	printf("exit: %d\n", ret);
	return ret;
}

int handle_condition(
		const struct lttng_condition *condition,
		const struct lttng_evaluation *evaluation)
{
	int ret = 0;
	const char *string_low = "low";
	const char *string_high = "high";
	const char *string_condition_type = NULL;
	const char *condition_session_name = NULL;
	const char *condition_channel_name = NULL;
	enum lttng_condition_type condition_type;
	enum lttng_domain_type condition_domain_type;
	double buffer_usage_ratio;
	uint64_t buffer_usage_bytes;

	condition_type = lttng_condition_get_type(condition);

	if (condition_type != buffer_usage_type) {
		ret = 1;
		printf("error: condition type and buffer usage type are not the same\n");
		goto end;
	}

	/* Fetch info to test */
	ret = lttng_condition_buffer_usage_get_session_name(condition,
			&condition_session_name);
	if (ret) {
		printf("error: session name could not be fetched\n");
		ret = 1;
		goto end;
	}
	ret = lttng_condition_buffer_usage_get_channel_name(condition,
			&condition_channel_name);
	if (ret) {
		printf("error: channel name could not be fetched\n");
		ret = 1;
		goto end;
	}
	ret = lttng_condition_buffer_usage_get_domain_type(condition,
			&condition_domain_type);
	if (ret) {
		printf("error: domain type could not be fetched\n");
		ret = 1;
		goto end;
	}

	if (strcmp(condition_session_name, session_name) != 0) {
		printf("error: session name differs\n");
		ret = 1;
		goto end;
	}

	if (strcmp(condition_channel_name, channel_name) != 0) {
		printf("error: channel name differs\n");
		ret = 1;
		goto end;
	}

	if (condition_domain_type != domain_type) {
		printf("error: domain type differs\n");
		ret = 1;
		goto end;
	}

	if (is_threshold_ratio) {
		lttng_evaluation_buffer_usage_get_usage_ratio(
				evaluation, &buffer_usage_ratio);
		switch (condition_type) {
		case LTTNG_CONDITION_TYPE_BUFFER_USAGE_LOW:
			if (buffer_usage_ratio > threshold_ratio) {
				printf("error: buffer usage ratio is bigger than set threshold ratio\n");
				ret = 1;
				goto end;
			}
			break;
		case LTTNG_CONDITION_TYPE_BUFFER_USAGE_HIGH:
			if (buffer_usage_ratio < threshold_ratio) {
				printf("error: buffer usage ratio is lower than set threshold ratio\n");
				ret = 1;
				goto end;
			}
			break;
		default:
			printf("error: Unknown condition type\n");
			ret = 1;
			goto end;
		}
	} else {
		lttng_evaluation_buffer_usage_get_usage(
				evaluation, &buffer_usage_bytes);
		switch (condition_type) {
		case LTTNG_CONDITION_TYPE_BUFFER_USAGE_LOW:
			if (buffer_usage_bytes > threshold_bytes) {
				printf("error: buffer usage ratio is bigger than set threshold bytes\n");
				ret = 1;
				goto end;
			}
			break;
		case LTTNG_CONDITION_TYPE_BUFFER_USAGE_HIGH:
			if (buffer_usage_bytes < threshold_bytes) {
				printf("error: buffer usage ratio is lower than set threshold bytes\n");
				ret = 1;
				goto end;
			}
			break;
		default:
			printf("error: Unknown condition type\n");
			ret = 1;
			goto end;
		}
	}

	switch (condition_type) {
	case LTTNG_CONDITION_TYPE_BUFFER_USAGE_LOW:
		string_condition_type = string_low;
		break;
	case LTTNG_CONDITION_TYPE_BUFFER_USAGE_HIGH:
		string_condition_type = string_high;
		break;
	default:
		printf("error: Unknown condition type\n");
		ret = 1;
		goto end;
	}

	printf("notification: %s %d\n", string_condition_type, nr_notifications);
end:
	return ret;
}
