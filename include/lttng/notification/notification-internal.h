/*
 * Copyright (C) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_NOTIFICATION_INTERNAL_H
#define LTTNG_NOTIFICATION_INTERNAL_H

#include <lttng/notification/notification.h>
#include <common/macros.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

struct lttng_payload;
struct lttng_payload_view;

struct lttng_notification {
	struct lttng_trigger *trigger;
	struct lttng_evaluation *evaluation;
};

struct lttng_notification_comm {
	/* Size of the payload following this field. */
	uint32_t length;
	/* Trigger and evaluation objects follow. */
	char payload[];
} LTTNG_PACKED;

LTTNG_HIDDEN
struct lttng_notification *lttng_notification_create(
		struct lttng_trigger *trigger,
		struct lttng_evaluation *evaluation);

LTTNG_HIDDEN
int lttng_notification_serialize(const struct lttng_notification *notification,
		struct lttng_payload *payload);

LTTNG_HIDDEN
ssize_t lttng_notification_create_from_payload(
		struct lttng_payload_view *view,
		struct lttng_notification **notification);

LTTNG_HIDDEN
const struct lttng_condition *lttng_notification_get_const_condition(
		const struct lttng_notification *notification);

LTTNG_HIDDEN
const struct lttng_evaluation *lttng_notification_get_const_evaluation(
		const struct lttng_notification *notification);

LTTNG_HIDDEN
const struct lttng_trigger *lttng_notification_get_const_trigger(
		const struct lttng_notification *notification);

#endif /* LTTNG_NOTIFICATION_INTERNAL_H */
