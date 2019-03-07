/*
 * Copyright (C) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
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

LTTNG_HIDDEN
const struct lttng_condition *lttng_trigger_get_const_condition(
		const struct lttng_trigger *trigger)
{
	return trigger->condition;
}

struct lttng_action *lttng_trigger_get_action(
		struct lttng_trigger *trigger)
{
	return trigger ? trigger->action : NULL;
}

LTTNG_HIDDEN
const struct lttng_action *lttng_trigger_get_const_action(
		const struct lttng_trigger *trigger)
{
	return trigger->action;
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
 * Both elements are stored contiguously, see their "*_comm" structure
 * for the detailed format.
 */
LTTNG_HIDDEN
int lttng_trigger_serialize(struct lttng_trigger *trigger,
		struct lttng_dynamic_buffer *buf)
{
	int ret;
	size_t header_offset, size_before_payload;
	struct lttng_trigger_comm trigger_comm = { 0 };
	struct lttng_trigger_comm *header;

	header_offset = buf->size;
	ret = lttng_dynamic_buffer_append(buf, &trigger_comm,
			sizeof(trigger_comm));
	if (ret) {
		goto end;
	}

	size_before_payload = buf->size;
	ret = lttng_condition_serialize(trigger->condition, buf);
	if (ret) {
		goto end;
	}

	ret = lttng_action_serialize(trigger->action, buf);
	if (ret) {
		goto end;
	}

	/* Update payload size. */
	header = (struct lttng_trigger_comm *) ((char *) buf->data + header_offset);
	header->length = buf->size - size_before_payload;
end:
	return ret;
}
