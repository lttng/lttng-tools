/*
 * Copyright (C) 2021 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "event-notifier-error-accounting.h"
#include <lttng/error-query-internal.h>
#include <lttng/trigger/trigger-internal.h>
#include <lttng/action/action-internal.h>

LTTNG_HIDDEN
enum lttng_trigger_status lttng_trigger_add_error_results(
		const struct lttng_trigger *trigger,
		struct lttng_error_query_results *results)
{
	enum lttng_trigger_status status;
	uint64_t discarded_tracer_messages_count;
	enum event_notifier_error_accounting_status error_accounting_status;
	struct lttng_error_query_result *discarded_tracer_messages_counter = NULL;
	const char *trigger_name;
	uid_t trigger_owner;

	status = lttng_trigger_get_name(trigger, &trigger_name);
	trigger_name = status == LTTNG_TRIGGER_STATUS_OK ?
			trigger_name : "(anonymous)";
	status = lttng_trigger_get_owner_uid(trigger,
			&trigger_owner);
	assert(status == LTTNG_TRIGGER_STATUS_OK);

	/* Only add discarded tracer messages count for applicable triggers. */
	if (!lttng_trigger_needs_tracer_notifier(trigger)) {
		status = LTTNG_TRIGGER_STATUS_OK;
		goto end;
	}

	error_accounting_status = event_notifier_error_accounting_get_count(
			trigger, &discarded_tracer_messages_count);
	if (error_accounting_status != EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK) {
		ERR("Failed to retrieve tracer discarded messages count for triger: triggger name = '%s', trigger owner uid = %d",
				trigger_name, (int) trigger_owner);
		status = LTTNG_TRIGGER_STATUS_ERROR;
		goto end;
	}

	discarded_tracer_messages_counter = lttng_error_query_result_counter_create(
			"discarded tracer messages",
			"Count of messages discarded by the tracer due to a communication error with the session daemon",
			discarded_tracer_messages_count);
	if (!discarded_tracer_messages_counter) {
		status = LTTNG_TRIGGER_STATUS_ERROR;
		goto end;
	}

	if (lttng_error_query_results_add_result(
			    results, discarded_tracer_messages_counter)) {
		status = LTTNG_TRIGGER_STATUS_ERROR;
		goto end;
	}

	/* Ownership transferred to the results. */
	discarded_tracer_messages_counter = NULL;

	status = LTTNG_TRIGGER_STATUS_OK;
end:
	lttng_error_query_result_destroy(discarded_tracer_messages_counter);
	return status;
}

LTTNG_HIDDEN
enum lttng_trigger_status lttng_trigger_add_action_error_query_results(
		struct lttng_trigger *trigger,
		struct lttng_error_query_results *results)
{
	enum lttng_trigger_status status;
	const char *trigger_name;
	uid_t trigger_owner;
	enum lttng_action_status action_status;

	status = lttng_trigger_get_name(trigger, &trigger_name);
	trigger_name = status == LTTNG_TRIGGER_STATUS_OK ?
			trigger_name : "(anonymous)";
	status = lttng_trigger_get_owner_uid(trigger,
			&trigger_owner);
	assert(status == LTTNG_TRIGGER_STATUS_OK);

	action_status = lttng_action_add_error_query_results(
			lttng_trigger_get_action(trigger), results);
	switch (action_status) {
	case LTTNG_ACTION_STATUS_OK:
		break;
	default:
		status = LTTNG_TRIGGER_STATUS_ERROR;
		goto end;
	}

	status = LTTNG_TRIGGER_STATUS_OK;
end:
	return status;
}
