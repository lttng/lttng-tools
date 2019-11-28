/*
 * Copyright (C) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <lttng/action/action-internal.h>
#include <lttng/action/notify-internal.h>
#include <common/macros.h>
#include <assert.h>

static
void lttng_action_notify_destroy(struct lttng_action *action)
{
	free(action);
}

static
int lttng_action_notify_serialize(struct lttng_action *action,
		struct lttng_dynamic_buffer *buf)
{
	return 0;
}

struct lttng_action *lttng_action_notify_create(void)
{
	struct lttng_action_notify *notify;

	notify = zmalloc(sizeof(struct lttng_action_notify));
	if (!notify) {
		goto end;
	}

	notify->parent.type = LTTNG_ACTION_TYPE_NOTIFY;
	notify->parent.serialize = lttng_action_notify_serialize;
	notify->parent.destroy = lttng_action_notify_destroy;
end:
	return &notify->parent;
}

ssize_t lttng_action_notify_create_from_buffer(
		const struct lttng_buffer_view *view,
		struct lttng_action **action)
{
	ssize_t consumed_length;

	*action = lttng_action_notify_create();
	if (!*action) {
		consumed_length = -1;
		goto end;
	}

	consumed_length = 0;
end:
	return consumed_length;
}
