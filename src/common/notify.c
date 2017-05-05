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
#include <common/macros.h>
#include <assert.h>

static
void lttng_action_notify_destroy(struct lttng_action *action)
{
	free(action);
}

static
ssize_t lttng_action_notify_serialize(struct lttng_action *action, char *buf)
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
