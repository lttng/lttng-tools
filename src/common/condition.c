/*
 * Copyright (C) 2017 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License, version 2.1 only,
 * as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <lttng/condition/condition-internal.h>
#include <lttng/condition/buffer-usage-internal.h>
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
ssize_t lttng_condition_serialize(const struct lttng_condition *condition,
		char *buf)
{
	ssize_t ret, condition_size;
	struct lttng_condition_comm condition_comm = {
		.condition_type = (int8_t) (condition ?
				condition->type : LTTNG_CONDITION_TYPE_UNKNOWN)
	};

	if (!condition) {
		ret = -1;
		goto end;
	}

	ret = sizeof(struct lttng_condition_comm);
	if (buf) {
		memcpy(buf, &condition_comm, ret);
		buf += ret;
	}

	condition_size = condition->serialize(condition, buf);
	if (condition_size < 0) {
		ret = condition_size;
		goto end;
	}
	ret += condition_size;
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
