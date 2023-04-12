/*
 * Copyright (C) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_ACTION_INTERNAL_H
#define LTTNG_ACTION_INTERNAL_H

#include <common/buffer-view.hpp>
#include <common/dynamic-buffer.hpp>
#include <common/macros.hpp>
#include <common/payload-view.hpp>
#include <common/payload.hpp>

#include <lttng/lttng.h>

#include <pthread.h>
#include <stdbool.h>
#include <sys/types.h>
#include <urcu/ref.h>

struct lttng_rate_policy;
struct mi_writer;
struct mi_lttng_error_query_callbacks;
struct lttng_trigger;

using action_validate_cb = bool (*)(struct lttng_action *);
using action_destroy_cb = void (*)(struct lttng_action *);
using action_serialize_cb = int (*)(struct lttng_action *, struct lttng_payload *);
using action_equal_cb = bool (*)(const struct lttng_action *, const struct lttng_action *);
using action_create_from_payload_cb = ssize_t (*)(struct lttng_payload_view *,
						  struct lttng_action **);
using action_get_rate_policy_cb = const struct lttng_rate_policy *(*) (const struct lttng_action *);
using action_add_error_query_results_cb = enum lttng_action_status (*)(
	const struct lttng_action *, struct lttng_error_query_results *);
using action_mi_serialize_cb = enum lttng_error_code (*)(const struct lttng_action *,
							 struct mi_writer *);

struct lttng_action {
	struct urcu_ref ref;
	enum lttng_action_type type;
	action_validate_cb validate;
	action_serialize_cb serialize;
	action_equal_cb equal;
	action_destroy_cb destroy;
	action_get_rate_policy_cb get_rate_policy;
	action_add_error_query_results_cb add_error_query_results;
	action_mi_serialize_cb mi_serialize;

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
	 * An unsigned long is used to use a type which makes atomic
	 * operations possible.
	 */
	unsigned long execution_failure_counter;
};

struct lttng_action_comm {
	/* enum lttng_action_type */
	int8_t action_type;
} LTTNG_PACKED;

void lttng_action_init(struct lttng_action *action,
		       enum lttng_action_type type,
		       action_validate_cb validate,
		       action_serialize_cb serialize,
		       action_equal_cb equal,
		       action_destroy_cb destroy,
		       action_get_rate_policy_cb get_rate_policy,
		       action_add_error_query_results_cb add_error_query_results,
		       action_mi_serialize_cb mi);

bool lttng_action_validate(struct lttng_action *action);

int lttng_action_serialize(struct lttng_action *action, struct lttng_payload *buf);

ssize_t lttng_action_create_from_payload(struct lttng_payload_view *view,
					 struct lttng_action **action);

bool lttng_action_is_equal(const struct lttng_action *a, const struct lttng_action *b);

void lttng_action_get(struct lttng_action *action);

void lttng_action_put(struct lttng_action *action);

const char *lttng_action_type_string(enum lttng_action_type action_type);

void lttng_action_increase_execution_request_count(struct lttng_action *action);

void lttng_action_increase_execution_count(struct lttng_action *action);

void lttng_action_increase_execution_failure_count(struct lttng_action *action);

bool lttng_action_should_execute(const struct lttng_action *action);

enum lttng_action_status
lttng_action_add_error_query_results(const struct lttng_action *action,
				     struct lttng_error_query_results *results);

/*
 * For use by the various lttng_action implementation. Implements the default
 * behavior to the generic error "execution failure counter" that all actions
 * (except list, which passes-through) provide.
 */
enum lttng_action_status
lttng_action_generic_add_error_query_results(const struct lttng_action *action,
					     struct lttng_error_query_results *results);
enum lttng_error_code
lttng_action_mi_serialize(const struct lttng_trigger *trigger,
			  const struct lttng_action *action,
			  struct mi_writer *writer,
			  const struct mi_lttng_error_query_callbacks *error_query_callbacks,
			  struct lttng_dynamic_array *action_path_indexes);

#endif /* LTTNG_ACTION_INTERNAL_H */
