/*
 * Copyright (C) 2020 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_LOG_LEVEL_RULE_H
#define LTTNG_LOG_LEVEL_RULE_H

#include <lttng/lttng-export.h>

#ifdef __cplusplus
extern "C" {
#endif

struct lttng_log_level_rule;

enum lttng_log_level_rule_type {
	LTTNG_LOG_LEVEL_RULE_TYPE_UNKNOWN = -1,
	LTTNG_LOG_LEVEL_RULE_TYPE_EXACTLY = 0,
	LTTNG_LOG_LEVEL_RULE_TYPE_AT_LEAST_AS_SEVERE_AS = 1,
};

enum lttng_log_level_rule_status {
	LTTNG_LOG_LEVEL_RULE_STATUS_OK = 0,
	LTTNG_LOG_LEVEL_RULE_STATUS_ERROR = -1,
	LTTNG_LOG_LEVEL_RULE_STATUS_INVALID = -3,
};

/*
 * Returns the type of the log level rule `rule`, or:
 *
 * `LTTNG_LOG_LEVEL_RULE_TYPE_UNKNOWN`:
 *     `rule` is `NULL`.
 */
LTTNG_EXPORT extern enum lttng_log_level_rule_type
lttng_log_level_rule_get_type(const struct lttng_log_level_rule *rule);

/*
 * Creates a log level rule for which a log level must match exactly `level` to
 * be considered.
 *
 * Returns `NULL` if:
 *
 * * There's a memory error.
 *
 * The returned log level rule must be destroyed using
 * lttng_log_level_rule_destroy().
 */
LTTNG_EXPORT extern struct lttng_log_level_rule *lttng_log_level_rule_exactly_create(int level);

/*
 * Sets `level` to the level of the "exactly" log level rule `rule`.
 *
 * Returns:
 *
 * `LTTNG_LOG_LEVEL_RULE_STATUS_OK`:
 *     Success.
 *
 * `LTTNG_LOG_LEVEL_RULE_STATUS_INVALID`:
 *     * `rule` is NULL.
 *     * `level` is NULL.
 *     * The type of `rule` is not `LTTNG_LOG_LEVEL_RULE_TYPE_EXACTLY`.
 */
LTTNG_EXPORT extern enum lttng_log_level_rule_status
lttng_log_level_rule_exactly_get_level(const struct lttng_log_level_rule *rule, int *level);

/*
 * Creates a log level rule for which a log level must be at least as severe as
 * `level` to be considered.
 *
 * Returns `NULL` if:
 *
 * * There's a memory error.
 *
 * The returned log level rule must be destroyed using
 * lttng_log_level_rule_destroy().
 */
LTTNG_EXPORT extern struct lttng_log_level_rule *
lttng_log_level_rule_at_least_as_severe_as_create(int level);

/*
 * Sets `level` to the level of the "at least as severe as" log level rule
 * `rule`.
 *
 * Returns:
 *
 * `LTTNG_LOG_LEVEL_RULE_STATUS_OK`:
 *     Success.
 *
 * `LTTNG_LOG_LEVEL_RULE_STATUS_INVALID`:
 *     * `rule` is NULL.
 *     * `level` is NULL.
 *     * The type of `rule` is not
 *       `LTTNG_LOG_LEVEL_RULE_TYPE_AT_LEAST_AS_SEVERE_AS`.
 */
LTTNG_EXPORT extern enum lttng_log_level_rule_status
lttng_log_level_rule_at_least_as_severe_as_get_level(const struct lttng_log_level_rule *rule,
						     int *level);

/*
 * Destroy the log level rule `log_level_rule` if not `NULL`.
 */
LTTNG_EXPORT extern void lttng_log_level_rule_destroy(struct lttng_log_level_rule *log_level_rule);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_LOG_LEVEL_RULE_H */
