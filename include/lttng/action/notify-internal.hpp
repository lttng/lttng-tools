/*
 * Copyright (C) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_ACTION_NOTIFY_INTERNAL_H
#define LTTNG_ACTION_NOTIFY_INTERNAL_H

#include <lttng/action/action-internal.hpp>
#include <lttng/action/notify.h>

struct lttng_action_notify {
	struct lttng_action parent;
	struct lttng_rate_policy *policy;
};

ssize_t lttng_action_notify_create_from_payload(struct lttng_payload_view *view,
						struct lttng_action **action);

#endif /* LTTNG_ACTION_NOTIFY_INTERNAL_H */
