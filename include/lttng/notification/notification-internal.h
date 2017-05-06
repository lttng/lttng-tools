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

#ifndef LTTNG_NOTIFICATION_INTERNAL_H
#define LTTNG_NOTIFICATION_INTERNAL_H

#include <lttng/notification/notification.h>
#include <common/macros.h>
#include <common/buffer-view.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

struct lttng_notification {
	struct lttng_condition *condition;
	struct lttng_evaluation *evaluation;
	/*
	 * The ownership of the notification's inner-elements depends
	 * on the way it was created. The notification owns both
	 * the condition and evaluation if it was obtained from a notification
	 * channel (i.e. created using lttng_notification_create_from_buffer)
	 * as the user may never access the condition and evaluation,
	 * thus never getting a chance to free them.
	 *
	 * However, when the _private_ lttng_notification_create() function
	 * is used, no ownership of condition and evaluation is assumed by
	 * the notification object. The main reason for this change in
	 * behavior is that internal users of this API only use the object
	 * to use its serialization facilities.
	 */
	bool owns_elements;
};

struct lttng_notification_comm {
	/* Size of the payload following this field. */
	uint32_t length;
	/* Condition and evaluation objects follow. */
	char payload[];
} LTTNG_PACKED;

LTTNG_HIDDEN
struct lttng_notification *lttng_notification_create(
		struct lttng_condition *condition,
		struct lttng_evaluation *evaluation);

LTTNG_HIDDEN
ssize_t lttng_notification_serialize(struct lttng_notification *notification,
		char *buf);

LTTNG_HIDDEN
ssize_t lttng_notification_create_from_buffer(
		const struct lttng_buffer_view *view,
		struct lttng_notification **notification);

#endif /* LTTNG_NOTIFICATION_INTERNAL_H */
