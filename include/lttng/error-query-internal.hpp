/*
 * error-query-internal.h
 *
 * Copyright (C) 2021 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_ERROR_QUERY_INTERNAL_H
#define LTTNG_ERROR_QUERY_INTERNAL_H

#include <common/macros.hpp>
#include <common/payload-view.hpp>
#include <common/payload.hpp>

#include <lttng/lttng.h>

struct mi_writer;

enum lttng_error_query_target_type {
	LTTNG_ERROR_QUERY_TARGET_TYPE_TRIGGER,
	LTTNG_ERROR_QUERY_TARGET_TYPE_CONDITION,
	LTTNG_ERROR_QUERY_TARGET_TYPE_ACTION,
};

enum lttng_error_query_target_type
lttng_error_query_get_target_type(const struct lttng_error_query *query);

const struct lttng_trigger *
lttng_error_query_trigger_borrow_target(const struct lttng_error_query *query);

const struct lttng_trigger *
lttng_error_query_condition_borrow_target(const struct lttng_error_query *query);

const struct lttng_trigger *
lttng_error_query_action_borrow_trigger_target(const struct lttng_error_query *query);

struct lttng_action *
lttng_error_query_action_borrow_action_target(const struct lttng_error_query *query,
					      struct lttng_trigger *trigger);

int lttng_error_query_serialize(const struct lttng_error_query *query,
				struct lttng_payload *payload);

ssize_t lttng_error_query_create_from_payload(struct lttng_payload_view *view,
					      struct lttng_error_query **query);

int lttng_error_query_result_serialize(const struct lttng_error_query_result *result,
				       struct lttng_payload *payload);

ssize_t lttng_error_query_result_create_from_payload(struct lttng_payload_view *view,
						     struct lttng_error_query_result **result);

int lttng_error_query_results_serialize(const struct lttng_error_query_results *results,
					struct lttng_payload *payload);

ssize_t lttng_error_query_results_create_from_payload(struct lttng_payload_view *view,
						      struct lttng_error_query_results **results);

struct lttng_error_query_result *
lttng_error_query_result_counter_create(const char *name, const char *description, uint64_t value);

void lttng_error_query_result_destroy(struct lttng_error_query_result *result);

struct lttng_error_query_results *lttng_error_query_results_create();

/* Ownership of `result` is transferred on success. */
int lttng_error_query_results_add_result(struct lttng_error_query_results *results,
					 struct lttng_error_query_result *result);

enum lttng_error_code
lttng_error_query_results_mi_serialize(const struct lttng_error_query_results *results,
				       struct mi_writer *writer);

#endif /* LTTNG_ERROR_QUERY_INTERNAL_H */
