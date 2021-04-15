/*
 * Copyright (C) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_ACTION_INTERNAL_H
#define LTTNG_ACTION_INTERNAL_H

#include <lttng/action/action.h>
#include <common/macros.h>
#include <common/buffer-view.h>
#include <common/dynamic-buffer.h>
#include <common/payload-view.h>
#include <common/payload.h>
#include <stdbool.h>
#include <sys/types.h>
#include <urcu/ref.h>

struct lttng_rate_policy;

typedef bool (*action_validate_cb)(struct lttng_action *action);
typedef void (*action_destroy_cb)(struct lttng_action *action);
typedef int (*action_serialize_cb)(struct lttng_action *action,
		struct lttng_payload *payload);
typedef bool (*action_equal_cb)(const struct lttng_action *a,
		const struct lttng_action *b);
typedef ssize_t (*action_create_from_payload_cb)(
		struct lttng_payload_view *view,
		struct lttng_action **action);
typedef const struct lttng_rate_policy *(*action_get_rate_policy_cb)(
		const struct lttng_action *action);

struct lttng_action {
	struct urcu_ref ref;
	enum lttng_action_type type;
	action_validate_cb validate;
	action_serialize_cb serialize;
	action_equal_cb equal;
	action_destroy_cb destroy;
	action_get_rate_policy_cb get_rate_policy;

	/* Internal use only. */

	/* The number of time the actions was enqueued for execution. */
	uint64_t execution_request_counter;
	/*
	 * The number of time the action was actually executed.
	 * Action rate policy can impact on this number.
	 * */
	uint64_t execution_counter;
	/*
	 * The number of time the action execution failed.
	 */
	uint64_t execution_failure_counter;
};

struct lttng_action_comm {
	/* enum lttng_action_type */
	int8_t action_type;
} LTTNG_PACKED;

LTTNG_HIDDEN
void lttng_action_init(struct lttng_action *action,
		enum lttng_action_type type,
		action_validate_cb validate,
		action_serialize_cb serialize,
		action_equal_cb equal,
		action_destroy_cb destroy,
		action_get_rate_policy_cb get_rate_policy);

LTTNG_HIDDEN
bool lttng_action_validate(struct lttng_action *action);

LTTNG_HIDDEN
int lttng_action_serialize(struct lttng_action *action,
		struct lttng_payload *buf);

LTTNG_HIDDEN
ssize_t lttng_action_create_from_payload(struct lttng_payload_view *view,
		struct lttng_action **action);

LTTNG_HIDDEN
bool lttng_action_is_equal(const struct lttng_action *a,
		const struct lttng_action *b);

LTTNG_HIDDEN
void lttng_action_get(struct lttng_action *action);

LTTNG_HIDDEN
void lttng_action_put(struct lttng_action *action);

LTTNG_HIDDEN
const char* lttng_action_type_string(enum lttng_action_type action_type);

LTTNG_HIDDEN
void lttng_action_increase_execution_request_count(struct lttng_action *action);

LTTNG_HIDDEN
void lttng_action_increase_execution_count(struct lttng_action *action);

LTTNG_HIDDEN
void lttng_action_increase_execution_failure_count(struct lttng_action *action);

LTTNG_HIDDEN
bool lttng_action_should_execute(const struct lttng_action *action);

#endif /* LTTNG_ACTION_INTERNAL_H */
