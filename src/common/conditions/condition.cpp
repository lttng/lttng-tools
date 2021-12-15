/*
 * Copyright (C) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <common/buffer-view.hpp>
#include <common/dynamic-buffer.hpp>
#include <common/error.hpp>
#include <common/macros.hpp>
#include <common/mi-lttng.hpp>
#include <lttng/condition/buffer-usage-internal.hpp>
#include <lttng/condition/condition-internal.hpp>
#include <lttng/condition/event-rule-matches-internal.hpp>
#include <lttng/condition/session-consumed-size-internal.hpp>
#include <lttng/condition/session-rotation-internal.hpp>
#include <lttng/error-query-internal.hpp>
#include <stdbool.h>

enum lttng_condition_type lttng_condition_get_type(
		const struct lttng_condition *condition)
{
	return condition ? condition->type : LTTNG_CONDITION_TYPE_UNKNOWN;
}

void lttng_condition_destroy(struct lttng_condition *condition)
{
	lttng_condition_put(condition);
}

static void condition_destroy_ref(struct urcu_ref *ref)
{
	struct lttng_condition *condition =
		container_of(ref, struct lttng_condition, ref);

	condition->destroy(condition);
}

void lttng_condition_get(struct lttng_condition *condition)
{
	urcu_ref_get(&condition->ref);
}

void lttng_condition_put(struct lttng_condition *condition)
{
	if (!condition) {
		return;
	}

	LTTNG_ASSERT(condition->destroy);
	urcu_ref_put(&condition->ref, condition_destroy_ref);
}


bool lttng_condition_validate(const struct lttng_condition *condition)
{
	bool valid;

	if (!condition) {
		valid = false;
		goto end;
	}

	if (!condition->validate) {
		/* Sub-class guarantees that it can never be invalid. */
		valid = true;
		goto end;
	}

	valid = condition->validate(condition);
end:
	return valid;
}

int lttng_condition_serialize(const struct lttng_condition *condition,
		struct lttng_payload *payload)
{
	int ret;
	struct lttng_condition_comm condition_comm = {};

	if (!condition) {
		ret = -1;
		goto end;
	}

	condition_comm.condition_type = (int8_t) condition->type;

	ret = lttng_dynamic_buffer_append(&payload->buffer, &condition_comm,
			sizeof(condition_comm));
	if (ret) {
		goto end;
	}

	ret = condition->serialize(condition, payload);
	if (ret) {
		goto end;
	}
end:
	return ret;
}

bool lttng_condition_is_equal(const struct lttng_condition *a,
		const struct lttng_condition *b)
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

	is_equal = a->equal ? a->equal(a, b) : true;
end:
	return is_equal;
}

ssize_t lttng_condition_create_from_payload(
		struct lttng_payload_view *view,
		struct lttng_condition **condition)
{
	ssize_t ret, condition_size = 0;
	condition_create_from_payload_cb create_from_payload = NULL;
	const struct lttng_condition_comm *condition_comm;
	const struct lttng_payload_view condition_comm_view =
			lttng_payload_view_from_view(
					view, 0, sizeof(*condition_comm));

	if (!view || !condition) {
		ret = -1;
		goto end;
	}

	if (!lttng_payload_view_is_valid(&condition_comm_view)) {
		/* Payload not large enough to contain the header. */
		ret = -1;
		goto end;
	}

	DBG("Deserializing condition from buffer");
	condition_comm = (typeof(condition_comm)) condition_comm_view.buffer.data;
	condition_size += sizeof(*condition_comm);

	switch ((enum lttng_condition_type) condition_comm->condition_type) {
	case LTTNG_CONDITION_TYPE_BUFFER_USAGE_LOW:
		create_from_payload = lttng_condition_buffer_usage_low_create_from_payload;
		break;
	case LTTNG_CONDITION_TYPE_BUFFER_USAGE_HIGH:
		create_from_payload = lttng_condition_buffer_usage_high_create_from_payload;
		break;
	case LTTNG_CONDITION_TYPE_SESSION_CONSUMED_SIZE:
		create_from_payload = lttng_condition_session_consumed_size_create_from_payload;
		break;
	case LTTNG_CONDITION_TYPE_SESSION_ROTATION_ONGOING:
		create_from_payload = lttng_condition_session_rotation_ongoing_create_from_payload;
		break;
	case LTTNG_CONDITION_TYPE_SESSION_ROTATION_COMPLETED:
		create_from_payload = lttng_condition_session_rotation_completed_create_from_payload;
		break;
	case LTTNG_CONDITION_TYPE_EVENT_RULE_MATCHES:
		create_from_payload =
				lttng_condition_event_rule_matches_create_from_payload;
		break;
	default:
		ERR("Attempted to create condition of unknown type (%i)",
				(int) condition_comm->condition_type);
		ret = -1;
		goto end;
	}

	if (create_from_payload) {
		struct lttng_payload_view condition_view =
				lttng_payload_view_from_view(view,
					sizeof(*condition_comm), -1);

		ret = create_from_payload(&condition_view, condition);
		if (ret < 0) {
			goto end;
		}
		condition_size += ret;

	} else {
		abort();
	}

	ret = condition_size;
end:
	return ret;
}

void lttng_condition_init(struct lttng_condition *condition,
		enum lttng_condition_type type)
{
	condition->type = type;
	urcu_ref_init(&condition->ref);
}

const char *lttng_condition_type_str(enum lttng_condition_type type)
{
	switch (type) {
	case LTTNG_CONDITION_TYPE_UNKNOWN:
		return "unknown";

	case LTTNG_CONDITION_TYPE_SESSION_CONSUMED_SIZE:
		return "session consumed size";

	case LTTNG_CONDITION_TYPE_BUFFER_USAGE_HIGH:
		return "buffer usage high";

	case LTTNG_CONDITION_TYPE_BUFFER_USAGE_LOW:
		return "buffer usage low";

	case LTTNG_CONDITION_TYPE_SESSION_ROTATION_ONGOING:
		return "session rotation ongoing";

	case LTTNG_CONDITION_TYPE_SESSION_ROTATION_COMPLETED:
		return "session rotation completed";

	case LTTNG_CONDITION_TYPE_EVENT_RULE_MATCHES:
		return "event rule matches";

	default:
		return "???";
	}
}

enum lttng_error_code lttng_condition_mi_serialize(
		const struct lttng_trigger *trigger,
		const struct lttng_condition *condition,
		struct mi_writer *writer,
		const struct mi_lttng_error_query_callbacks *error_query_callbacks)
{
	int ret;
	enum lttng_error_code ret_code;
	struct lttng_error_query_results *error_query_results = NULL;

	LTTNG_ASSERT(condition);
	LTTNG_ASSERT(writer);
	LTTNG_ASSERT(condition->mi_serialize);

	/* Open condition element. */
	ret = mi_lttng_writer_open_element(writer, mi_lttng_element_condition);
	if (ret) {
		goto mi_error;
	}

	/* Serialize underlying condition. */
	ret_code = condition->mi_serialize(condition, writer);
	if (ret_code != LTTNG_OK) {
		goto end;
	}

	/* Serialize error query results for the action. */
	if (error_query_callbacks && error_query_callbacks->action_cb) {
		ret_code = error_query_callbacks->condition_cb(
				trigger, &error_query_results);
		if (ret_code != LTTNG_OK) {
			goto end;
		}

		ret_code = lttng_error_query_results_mi_serialize(
				error_query_results, writer);
		if (ret_code != LTTNG_OK) {
			goto end;
		}
	}

	/* Close condition element. */
	ret = mi_lttng_writer_close_element(writer);
	if (ret) {
		goto mi_error;
	}

	ret_code = LTTNG_OK;
	goto end;

mi_error:
	ret_code = LTTNG_ERR_MI_IO_FAIL;
end:
	lttng_error_query_results_destroy(error_query_results);
	return ret_code;
}
