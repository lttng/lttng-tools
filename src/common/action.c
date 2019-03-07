/*
 * Copyright (C) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <lttng/action/action-internal.h>
#include <lttng/action/notify-internal.h>
#include <common/error.h>
#include <assert.h>

enum lttng_action_type lttng_action_get_type(struct lttng_action *action)
{
	return action ? action->type : LTTNG_ACTION_TYPE_UNKNOWN;
}

LTTNG_HIDDEN
enum lttng_action_type lttng_action_get_type_const(
		const struct lttng_action *action)
{
	return action->type;
}

void lttng_action_destroy(struct lttng_action *action)
{
	if (!action) {
		return;
	}

	assert(action->destroy);
	action->destroy(action);
}

LTTNG_HIDDEN
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

LTTNG_HIDDEN
int lttng_action_serialize(struct lttng_action *action,
		struct lttng_dynamic_buffer *buf)
{
	int ret;
	struct lttng_action_comm action_comm = {
		.action_type = (int8_t) action->type,
	};

	ret = lttng_dynamic_buffer_append(buf, &action_comm,
			sizeof(action_comm));
	if (ret) {
		goto end;
	}

	ret = action->serialize(action, buf);
	if (ret) {
		goto end;
	}
end:
	return ret;
}

LTTNG_HIDDEN
ssize_t lttng_action_create_from_buffer(const struct lttng_buffer_view *view,
		struct lttng_action **_action)
{
	ssize_t ret, action_size = sizeof(struct lttng_action_comm);
	struct lttng_action *action;
	const struct lttng_action_comm *action_comm;

	if (!view || !_action) {
		ret = -1;
		goto end;
	}

	action_comm = (const struct lttng_action_comm *) view->data;
	DBG("Deserializing action from buffer");
	switch (action_comm->action_type) {
	case LTTNG_ACTION_TYPE_NOTIFY:
		action = lttng_action_notify_create();
		break;
	default:
		ret = -1;
		goto end;
	}

	if (!action) {
		ret = -1;
		goto end;
	}
	ret = action_size;
	*_action = action;
end:
	return ret;
}
