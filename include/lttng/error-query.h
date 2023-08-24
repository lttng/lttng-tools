/*
 * error-query.h
 *
 * Copyright (C) 2021 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_ERROR_QUERY_H
#define LTTNG_ERROR_QUERY_H

#include <lttng/lttng-export.h>
#include <lttng/lttng.h>
#include <lttng/trigger/trigger.h>

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* An error query. */
struct lttng_error_query;

/*
 * A collection of "lttng_error_query_result" returned after executing an error
 * query against an endpoint.
 */
struct lttng_error_query_results;

/* A 'result' is an opaque error type. */
struct lttng_error_query_result;

enum lttng_error_query_status {
	LTTNG_ERROR_QUERY_STATUS_OK = 0,
	/* An error occurred while querying for errors. */
	LTTNG_ERROR_QUERY_STATUS_ERROR = -1,
	/* The target of the query does not make sense for this endpoint. */
	LTTNG_ERROR_QUERY_STATUS_INVALID_QUERY_TARGET = -2,
	LTTNG_ERROR_QUERY_STATUS_INVALID_PARAMETER = -3,
};

enum lttng_error_query_result_type {
	/* A count of errors provided as an unsigned integral value. */
	LTTNG_ERROR_QUERY_RESULT_TYPE_COUNTER = 0,
	LTTNG_ERROR_QUERY_RESULT_TYPE_UNKNOWN = -1,
};

enum lttng_error_query_result_status {
	LTTNG_ERROR_QUERY_RESULT_STATUS_OK = 0,
	LTTNG_ERROR_QUERY_RESULT_STATUS_ERROR = -1,
	LTTNG_ERROR_QUERY_RESULT_STATUS_INVALID_PARAMETER = -2,
};

enum lttng_error_query_results_status {
	LTTNG_ERROR_QUERY_RESULTS_STATUS_OK = 0,
	LTTNG_ERROR_QUERY_RESULTS_STATUS_ERROR = -1,
	LTTNG_ERROR_QUERY_RESULTS_STATUS_INVALID_PARAMETER = -2,
};

/* Create an error query targetting a trigger object. */
LTTNG_EXPORT extern struct lttng_error_query *
lttng_error_query_trigger_create(const struct lttng_trigger *trigger);

/* Create an error query targetting a trigger's condition object. */
LTTNG_EXPORT extern struct lttng_error_query *
lttng_error_query_condition_create(const struct lttng_trigger *trigger);

/*
 * Create an error query targetting an action object.
 *
 * `action_path` is copied internally. The root of the `action_path` is the
 * action of `trigger`.
 */
LTTNG_EXPORT extern struct lttng_error_query *
lttng_error_query_action_create(const struct lttng_trigger *trigger,
				const struct lttng_action_path *action_path);

/* Destroy an error query. */
LTTNG_EXPORT extern void lttng_error_query_destroy(struct lttng_error_query *query);

/*
 * Run an error query against an endpoint.
 *
 * Currently, only the `lttng_session_daemon_command_endpoint` is supported,
 * see `lttng/endpoint.h`.
 */
LTTNG_EXPORT extern enum lttng_error_code
lttng_error_query_execute(const struct lttng_error_query *query,
			  const struct lttng_endpoint *endpoint,
			  struct lttng_error_query_results **results);

/* Get the number of results in a result set. */
LTTNG_EXPORT LTTNG_EXPORT extern enum lttng_error_query_results_status
lttng_error_query_results_get_count(const struct lttng_error_query_results *results,
				    unsigned int *count);

/* Get a result from a result set by index. */
LTTNG_EXPORT extern enum lttng_error_query_results_status
lttng_error_query_results_get_result(const struct lttng_error_query_results *results,
				     const struct lttng_error_query_result **result,
				     unsigned int index);

/* Destroy an error query result set. */
LTTNG_EXPORT extern void
lttng_error_query_results_destroy(struct lttng_error_query_results *results);

/* Get the type of an error query result. */
LTTNG_EXPORT extern enum lttng_error_query_result_type
lttng_error_query_result_get_type(const struct lttng_error_query_result *result);

/* Get the name of result. */
LTTNG_EXPORT extern enum lttng_error_query_result_status
lttng_error_query_result_get_name(const struct lttng_error_query_result *result, const char **name);

/* Get the description of a result. */
LTTNG_EXPORT extern enum lttng_error_query_result_status
lttng_error_query_result_get_description(const struct lttng_error_query_result *result,
					 const char **description);

/* Get the value of an error counter. */
LTTNG_EXPORT extern enum lttng_error_query_result_status
lttng_error_query_result_counter_get_value(const struct lttng_error_query_result *result,
					   uint64_t *value);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_ERROR_QUERY_H */
