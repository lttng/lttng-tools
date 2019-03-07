/*
 * Copyright (C) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_TRIGGER_INTERNAL_H
#define LTTNG_TRIGGER_INTERNAL_H

#include <lttng/trigger/trigger.h>
#include <common/macros.h>
#include <common/buffer-view.h>
#include <common/dynamic-buffer.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

struct lttng_trigger {
	struct lttng_condition *condition;
	struct lttng_action *action;
};

struct lttng_trigger_comm {
	/* length excludes its own length. */
	uint32_t length;
	/* A condition and action object follow. */
	char payload[];
} LTTNG_PACKED;

LTTNG_HIDDEN
ssize_t lttng_trigger_create_from_buffer(const struct lttng_buffer_view *view,
		struct lttng_trigger **trigger);

LTTNG_HIDDEN
int lttng_trigger_serialize(struct lttng_trigger *trigger,
		struct lttng_dynamic_buffer *buf);

LTTNG_HIDDEN
const struct lttng_condition *lttng_trigger_get_const_condition(
		const struct lttng_trigger *trigger);

LTTNG_HIDDEN
const struct lttng_action *lttng_trigger_get_const_action(
		const struct lttng_trigger *trigger);

LTTNG_HIDDEN
bool lttng_trigger_validate(struct lttng_trigger *trigger);

#endif /* LTTNG_TRIGGER_INTERNAL_H */
