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

#include <lttng/action/action-internal.h>
#include <lttng/action/notify-internal.h>
#include <common/error.h>
#include <assert.h>

enum lttng_action_type lttng_action_get_type(struct lttng_action *action)
{
	return action ? action->type : LTTNG_ACTION_TYPE_UNKNOWN;
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
ssize_t lttng_action_serialize(struct lttng_action *action, char *buf)
{
	ssize_t ret, action_size;
	struct lttng_action_comm action_comm;

	if (!action) {
		ret = -1;
		goto end;
	}

	action_comm.action_type = (int8_t) action->type;
	ret = sizeof(struct lttng_action_comm);
	if (buf) {
		memcpy(buf, &action_comm, ret);
		buf += ret;
	}

	action_size = action->serialize(action, buf);
	if (action_size < 0) {
		ret = action_size;
		goto end;
	}
	ret += action_size;
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
