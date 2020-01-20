/*
 * Copyright (C) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <lttng/condition/condition-internal.h>
#include <lttng/condition/buffer-usage-internal.h>
#include <lttng/condition/event-rule-internal.h>
#include <lttng/condition/session-consumed-size-internal.h>
#include <lttng/condition/session-rotation-internal.h>
#include <common/macros.h>
#include <common/error.h>
#include <common/dynamic-buffer.h>
#include <common/buffer-view.h>
#include <stdbool.h>
#include <assert.h>

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

LTTNG_HIDDEN
void lttng_condition_get(struct lttng_condition *condition)
{
	urcu_ref_get(&condition->ref);
}

LTTNG_HIDDEN
void lttng_condition_put(struct lttng_condition *condition)
{
	if (!condition) {
		return;
	}

	assert(condition->destroy);
	urcu_ref_put(&condition->ref, condition_destroy_ref);
}


LTTNG_HIDDEN
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

LTTNG_HIDDEN
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

LTTNG_HIDDEN
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

LTTNG_HIDDEN
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
	case LTTNG_CONDITION_TYPE_EVENT_RULE_HIT:
		create_from_payload = lttng_condition_event_rule_create_from_payload;
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

LTTNG_HIDDEN
void lttng_condition_init(struct lttng_condition *condition,
		enum lttng_condition_type type)
{
	condition->type = type;
	urcu_ref_init(&condition->ref);
}

LTTNG_HIDDEN
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

	case LTTNG_CONDITION_TYPE_EVENT_RULE_HIT:
		return "event rule hit";

	default:
		return "???";
	}
}
