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

#include <lttng/trigger/trigger-internal.h>
#include <lttng/condition/condition-internal.h>
#include <lttng/action/action-internal.h>
#include <common/error.h>
#include <assert.h>

LTTNG_HIDDEN
bool lttng_trigger_validate(struct lttng_trigger *trigger)
{
	bool valid;

	if (!trigger) {
		valid = false;
		goto end;
	}

	valid = lttng_condition_validate(trigger->condition) &&
			lttng_action_validate(trigger->action);
end:
	return valid;
}

struct lttng_trigger *lttng_trigger_create(
		struct lttng_condition *condition,
		struct lttng_action *action)
{
	struct lttng_trigger *trigger = NULL;

	if (!condition || !action) {
		goto end;
	}

	trigger = zmalloc(sizeof(struct lttng_trigger));
	if (!trigger) {
		goto end;
	}

	trigger->condition = condition;
	trigger->action = action;
end:
	return trigger;
}

struct lttng_condition *lttng_trigger_get_condition(
		struct lttng_trigger *trigger)
{
	return trigger ? trigger->condition : NULL;
}

struct lttng_action *lttng_trigger_get_action(
		struct lttng_trigger *trigger)
{
	return trigger ? trigger->action : NULL;
}

void lttng_trigger_destroy(struct lttng_trigger *trigger)
{
	if (!trigger) {
		return;
	}

	free(trigger);
}

LTTNG_HIDDEN
ssize_t lttng_trigger_create_from_buffer(
		const struct lttng_buffer_view *src_view,
		struct lttng_trigger **trigger)
{
	ssize_t ret, offset = 0, condition_size, action_size;
	struct lttng_condition *condition = NULL;
	struct lttng_action *action = NULL;
	const struct lttng_trigger_comm *trigger_comm;
	struct lttng_buffer_view condition_view;
	struct lttng_buffer_view action_view;

	if (!src_view || !trigger) {
		ret = -1;
		goto end;
	}

	/* lttng_trigger_comm header */
	trigger_comm = (const struct lttng_trigger_comm *) src_view->data;
	offset += sizeof(*trigger_comm);

	condition_view = lttng_buffer_view_from_view(src_view, offset, -1);

	/* struct lttng_condition */
	condition_size = lttng_condition_create_from_buffer(&condition_view,
			&condition);
	if (condition_size < 0) {
		ret = condition_size;
		goto end;
	}
	offset += condition_size;

	/* struct lttng_action */
	action_view = lttng_buffer_view_from_view(src_view, offset, -1);
	action_size = lttng_action_create_from_buffer(&action_view, &action);
	if (action_size < 0) {
		ret = action_size;
		goto end;
	}
	offset += action_size;

	/* Unexpected size of inner-elements; the buffer is corrupted. */
	if ((ssize_t) trigger_comm->length != condition_size + action_size) {
		ret = -1;
		goto error;
	}

	*trigger = lttng_trigger_create(condition, action);
	if (!*trigger) {
		ret = -1;
		goto error;
	}
	ret = offset;
end:
	return ret;
error:
	lttng_condition_destroy(condition);
	lttng_action_destroy(action);
	return ret;
}

/*
 * Returns the size of a trigger (header + condition + action).
 * Both elements are stored contiguously, see their "*_comm" structure
 * for the detailed format.
 */
LTTNG_HIDDEN
ssize_t lttng_trigger_serialize(struct lttng_trigger *trigger, char *buf)
{
	struct lttng_trigger_comm trigger_comm = { 0 };
	ssize_t action_size, condition_size, offset = 0, ret;

	if (!trigger) {
		ret = -1;
		goto end;
	}

	offset += sizeof(trigger_comm);
	condition_size = lttng_condition_serialize(trigger->condition,
			buf ? (buf + offset) : NULL);
	if (condition_size < 0) {
		ret = -1;
		goto end;
	}
	offset += condition_size;

	action_size = lttng_action_serialize(trigger->action,
			buf ? (buf + offset) : NULL);
	if (action_size < 0) {
		ret = -1;
		goto end;
	}
	offset += action_size;

	if (buf) {
		trigger_comm.length = (uint32_t) (condition_size + action_size);
		memcpy(buf, &trigger_comm, sizeof(trigger_comm));
	}
	ret = offset;
end:
	return ret;
}
