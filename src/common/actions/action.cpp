/*
 * Copyright (C) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <common/error.hpp>
#include <common/mi-lttng.hpp>
#include <lttng/action/action-internal.hpp>
#include <lttng/action/list-internal.hpp>
#include <lttng/action/notify-internal.hpp>
#include <lttng/action/rate-policy-internal.hpp>
#include <lttng/action/rotate-session-internal.hpp>
#include <lttng/action/snapshot-session-internal.hpp>
#include <lttng/action/start-session-internal.hpp>
#include <lttng/action/stop-session-internal.hpp>
#include <lttng/error-query-internal.hpp>

const char *lttng_action_type_string(enum lttng_action_type action_type)
{
	switch (action_type) {
	case LTTNG_ACTION_TYPE_UNKNOWN:
		return "UNKNOWN";
	case LTTNG_ACTION_TYPE_LIST:
		return "LIST";
	case LTTNG_ACTION_TYPE_NOTIFY:
		return "NOTIFY";
	case LTTNG_ACTION_TYPE_ROTATE_SESSION:
		return "ROTATE_SESSION";
	case LTTNG_ACTION_TYPE_SNAPSHOT_SESSION:
		return "SNAPSHOT_SESSION";
	case LTTNG_ACTION_TYPE_START_SESSION:
		return "START_SESSION";
	case LTTNG_ACTION_TYPE_STOP_SESSION:
		return "STOP_SESSION";
	default:
		return "???";
	}
}

enum lttng_action_type lttng_action_get_type(const struct lttng_action *action)
{
	return action ? action->type : LTTNG_ACTION_TYPE_UNKNOWN;
}

void lttng_action_init(struct lttng_action *action,
		enum lttng_action_type type,
		action_validate_cb validate,
		action_serialize_cb serialize,
		action_equal_cb equal,
		action_destroy_cb destroy,
		action_get_rate_policy_cb get_rate_policy,
		action_add_error_query_results_cb add_error_query_results,
		action_mi_serialize_cb mi)
{
	urcu_ref_init(&action->ref);
	action->type = type;
	action->validate = validate;
	action->serialize = serialize;
	action->equal = equal;
	action->destroy = destroy;
	action->get_rate_policy = get_rate_policy;
	action->add_error_query_results = add_error_query_results;
	action->mi_serialize = mi;

	action->execution_request_counter = 0;
	action->execution_counter = 0;
	action->execution_failure_counter = 0;
}

static
void action_destroy_ref(struct urcu_ref *ref)
{
	struct lttng_action *action =
			container_of(ref, struct lttng_action, ref);

	action->destroy(action);
}

void lttng_action_get(struct lttng_action *action)
{
	urcu_ref_get(&action->ref);
}

void lttng_action_put(struct lttng_action *action)
{
	if (!action) {
		return;
	}

	LTTNG_ASSERT(action->destroy);
	urcu_ref_put(&action->ref, action_destroy_ref);
}

void lttng_action_destroy(struct lttng_action *action)
{
	lttng_action_put(action);
}

bool lttng_action_validate(struct lttng_action *action)
{
	bool valid;

	if (!action) {
		valid = false;
		goto end;
	}

	if (!action->validate) {
		/* Sub-class guarantees that it can never be invalid. */
		valid = true;
		goto end;
	}

	valid = action->validate(action);
end:
	return valid;
}

int lttng_action_serialize(struct lttng_action *action,
		struct lttng_payload *payload)
{
	int ret;
	struct lttng_action_comm action_comm = {
		.action_type = (int8_t) action->type,
	};

	ret = lttng_dynamic_buffer_append(&payload->buffer, &action_comm,
			sizeof(action_comm));
	if (ret) {
		goto end;
	}

	ret = action->serialize(action, payload);
	if (ret) {
		goto end;
	}
end:
	return ret;
}

ssize_t lttng_action_create_from_payload(struct lttng_payload_view *view,
		struct lttng_action **action)
{
	ssize_t consumed_len, specific_action_consumed_len;
	action_create_from_payload_cb create_from_payload_cb;
	const struct lttng_action_comm *action_comm;
	const struct lttng_payload_view action_comm_view =
			lttng_payload_view_from_view(
					view, 0, sizeof(*action_comm));

	if (!view || !action) {
		consumed_len = -1;
		goto end;
	}

	if (!lttng_payload_view_is_valid(&action_comm_view)) {
		/* Payload not large enough to contain the header. */
		consumed_len = -1;
		goto end;
	}

	action_comm = (const struct lttng_action_comm *) action_comm_view.buffer.data;

	DBG("Create action from payload: action-type=%s",
			lttng_action_type_string((lttng_action_type) action_comm->action_type));

	switch (action_comm->action_type) {
	case LTTNG_ACTION_TYPE_NOTIFY:
		create_from_payload_cb = lttng_action_notify_create_from_payload;
		break;
	case LTTNG_ACTION_TYPE_ROTATE_SESSION:
		create_from_payload_cb =
				lttng_action_rotate_session_create_from_payload;
		break;
	case LTTNG_ACTION_TYPE_SNAPSHOT_SESSION:
		create_from_payload_cb =
				lttng_action_snapshot_session_create_from_payload;
		break;
	case LTTNG_ACTION_TYPE_START_SESSION:
		create_from_payload_cb =
				lttng_action_start_session_create_from_payload;
		break;
	case LTTNG_ACTION_TYPE_STOP_SESSION:
		create_from_payload_cb =
				lttng_action_stop_session_create_from_payload;
		break;
	case LTTNG_ACTION_TYPE_LIST:
		create_from_payload_cb = lttng_action_list_create_from_payload;
		break;
	default:
		ERR("Failed to create action from payload, unhandled action type: action-type=%u (%s)",
				action_comm->action_type,
				lttng_action_type_string(
						(lttng_action_type) action_comm->action_type));
		consumed_len = -1;
		goto end;
	}

	{
		/* Create buffer view for the action-type-specific data. */
		struct lttng_payload_view specific_action_view =
				lttng_payload_view_from_view(view,
						sizeof(struct lttng_action_comm),
						-1);

		specific_action_consumed_len = create_from_payload_cb(
				&specific_action_view, action);
	}
	if (specific_action_consumed_len < 0) {
		ERR("Failed to create specific action from buffer.");
		consumed_len = -1;
		goto end;
	}

	LTTNG_ASSERT(*action);

	consumed_len = sizeof(struct lttng_action_comm) +
		       specific_action_consumed_len;

end:
	return consumed_len;
}

bool lttng_action_is_equal(const struct lttng_action *a,
		const struct lttng_action *b)
{
	bool is_equal = false;

	if (!a || !b) {
		goto end;
	}

	if (a->type != b->type) {
		goto end;
	}

	if (a == b) {
		is_equal = true;
		goto end;
	}

	LTTNG_ASSERT(a->equal);
	is_equal = a->equal(a, b);
end:
	return is_equal;
}

void lttng_action_increase_execution_request_count(struct lttng_action *action)
{
	action->execution_request_counter++;
}

void lttng_action_increase_execution_count(struct lttng_action *action)
{
	action->execution_counter++;
}

void lttng_action_increase_execution_failure_count(struct lttng_action *action)
{
	uatomic_inc(&action->execution_failure_counter);
}

bool lttng_action_should_execute(const struct lttng_action *action)
{
	const struct lttng_rate_policy *policy = NULL;
	bool execute = false;

	if (action->get_rate_policy == NULL) {
		execute = true;
		goto end;
	}

	policy = action->get_rate_policy(action);
	if (policy == NULL) {
		execute = true;
		goto end;
	}

	execute = lttng_rate_policy_should_execute(
			policy, action->execution_request_counter);
end:
	return execute;
}

enum lttng_action_status lttng_action_add_error_query_results(
		const struct lttng_action *action,
		struct lttng_error_query_results *results)
{
	return action->add_error_query_results(action, results);
}

enum lttng_action_status lttng_action_generic_add_error_query_results(
		const struct lttng_action *action,
		struct lttng_error_query_results *results)
{
	enum lttng_action_status action_status;
	struct lttng_error_query_result *error_counter = NULL;
	const uint64_t execution_failure_counter =
			uatomic_read(&action->execution_failure_counter);

	error_counter = lttng_error_query_result_counter_create(
			"total execution failures",
			"Aggregated count of errors encountered when executing the action",
			execution_failure_counter);
	if (!error_counter) {
		action_status = LTTNG_ACTION_STATUS_ERROR;
		goto end;
	}

	if (lttng_error_query_results_add_result(
			    results, error_counter)) {
		action_status = LTTNG_ACTION_STATUS_ERROR;
		goto end;
	}

	/* Ownership transferred to the results. */
	error_counter = NULL;
	action_status = LTTNG_ACTION_STATUS_OK;
end:
	lttng_error_query_result_destroy(error_counter);
	return action_status;
}

enum lttng_error_code lttng_action_mi_serialize(const struct lttng_trigger *trigger,
		const struct lttng_action *action,
		struct mi_writer *writer,
		const struct mi_lttng_error_query_callbacks
				*error_query_callbacks,
		struct lttng_dynamic_array *action_path_indexes)
{
	int ret;
	enum lttng_error_code ret_code;
	struct lttng_action_path *action_path = NULL;
	struct lttng_error_query_results *error_query_results = NULL;

	LTTNG_ASSERT(action);
	LTTNG_ASSERT(writer);

	/* Open action. */
	ret = mi_lttng_writer_open_element(writer, mi_lttng_element_action);
	if (ret) {
		goto mi_error;
	}

	if (action->type == LTTNG_ACTION_TYPE_LIST) {
		/*
		 * Recursion is safe since action lists can't be nested for
		 * the moment.
		 */
		ret_code = lttng_action_list_mi_serialize(trigger, action, writer,
				error_query_callbacks, action_path_indexes);
		if (ret_code != LTTNG_OK) {
			goto end;
		}

		/* Nothing else to do. */
		goto close_action_element;
	}

	LTTNG_ASSERT(action->mi_serialize);
	ret_code = action->mi_serialize(action, writer);
	if (ret_code != LTTNG_OK) {
		goto end;
	}

	/* Error query for the action. */
	if (error_query_callbacks && error_query_callbacks->action_cb) {
		const uint64_t *action_path_indexes_raw_pointer = NULL;
		const size_t action_path_indexes_size =
				lttng_dynamic_array_get_count(
						action_path_indexes);

		if (action_path_indexes_size != 0) {
			action_path_indexes_raw_pointer =
					(const uint64_t *) action_path_indexes
							->buffer.data;
		}

		action_path = lttng_action_path_create(
				action_path_indexes_raw_pointer,
				action_path_indexes_size);
		LTTNG_ASSERT(action_path);

		ret_code = error_query_callbacks->action_cb(
				trigger, action_path, &error_query_results);
		if (ret_code != LTTNG_OK) {
			goto end;
		}

		/* Serialize the error query results. */
		ret_code = lttng_error_query_results_mi_serialize(
				error_query_results, writer);
		if (ret_code != LTTNG_OK) {
			goto end;
		}
	}

close_action_element:
	/* Close action. */
	ret = mi_lttng_writer_close_element(writer);
	if (ret) {
		goto mi_error;
	}

	ret_code = LTTNG_OK;
	goto end;

mi_error:
	ret_code = LTTNG_ERR_MI_IO_FAIL;
end:
	lttng_action_path_destroy(action_path);
	lttng_error_query_results_destroy(error_query_results);
	return ret_code;
}
