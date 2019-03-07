/*
 * Copyright (C) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <lttng/condition/condition-internal.h>
#include <lttng/condition/buffer-usage-internal.h>
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
	if (!condition) {
		return;
	}

	assert(condition->destroy);
	condition->destroy(condition);
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
		struct lttng_dynamic_buffer *buf)
{
	int ret;
	struct lttng_condition_comm condition_comm = { 0 };

	if (!condition) {
		ret = -1;
		goto end;
	}

	condition_comm.condition_type = (int8_t) condition->type;

	ret = lttng_dynamic_buffer_append(buf, &condition_comm,
			sizeof(condition_comm));
	if (ret) {
		goto end;
	}

	ret = condition->serialize(condition, buf);
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
ssize_t lttng_condition_create_from_buffer(
		const struct lttng_buffer_view *buffer,
		struct lttng_condition **condition)
{
	ssize_t ret, condition_size = 0;
	const struct lttng_condition_comm *condition_comm;
	condition_create_from_buffer_cb create_from_buffer = NULL;

	if (!buffer || !condition) {
		ret = -1;
		goto end;
	}

	DBG("Deserializing condition from buffer");
	condition_comm = (const struct lttng_condition_comm *) buffer->data;
	condition_size += sizeof(*condition_comm);

	switch ((enum lttng_condition_type) condition_comm->condition_type) {
	case LTTNG_CONDITION_TYPE_BUFFER_USAGE_LOW:
		create_from_buffer = lttng_condition_buffer_usage_low_create_from_buffer;
		break;
	case LTTNG_CONDITION_TYPE_BUFFER_USAGE_HIGH:
		create_from_buffer = lttng_condition_buffer_usage_high_create_from_buffer;
		break;
	case LTTNG_CONDITION_TYPE_SESSION_CONSUMED_SIZE:
		create_from_buffer = lttng_condition_session_consumed_size_create_from_buffer;
		break;
	case LTTNG_CONDITION_TYPE_SESSION_ROTATION_ONGOING:
		create_from_buffer = lttng_condition_session_rotation_ongoing_create_from_buffer;
		break;
	case LTTNG_CONDITION_TYPE_SESSION_ROTATION_COMPLETED:
		create_from_buffer = lttng_condition_session_rotation_completed_create_from_buffer;
		break;
	default:
		ERR("Attempted to create condition of unknown type (%i)",
				(int) condition_comm->condition_type);
		ret = -1;
		goto end;
	}

	if (create_from_buffer) {
		const struct lttng_buffer_view view =
				lttng_buffer_view_from_view(buffer,
					sizeof(*condition_comm), -1);

		ret = create_from_buffer(&view, condition);
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
}
