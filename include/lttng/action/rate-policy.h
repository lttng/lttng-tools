/*
 * Copyright (C) 2021 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_RATE_POLICY_H
#define LTTNG_RATE_POLICY_H

#include <lttng/lttng-export.h>

#include <inttypes.h>
#include <sys/types.h>

struct lttng_rate_policy;

#ifdef __cplusplus
extern "C" {
#endif

enum lttng_rate_policy_status {
	LTTNG_RATE_POLICY_STATUS_OK = 0,
	LTTNG_RATE_POLICY_STATUS_ERROR = -1,
	LTTNG_RATE_POLICY_STATUS_UNKNOWN = -2,
	LTTNG_RATE_POLICY_STATUS_INVALID = -3,
	LTTNG_RATE_POLICY_STATUS_UNSET = -4,
	LTTNG_RATE_POLICY_STATUS_UNSUPPORTED = -5,
	LTTNG_RATE_POLICY_STATUS_PERMISSION_DENIED = -6,
};

enum lttng_rate_policy_type {
	LTTNG_RATE_POLICY_TYPE_UNKNOWN = -1,
	LTTNG_RATE_POLICY_TYPE_EVERY_N = 0,
	LTTNG_RATE_POLICY_TYPE_ONCE_AFTER_N = 1,
};

/*
 * Get the type of a rate policy.
 */
LTTNG_EXPORT extern enum lttng_rate_policy_type
lttng_rate_policy_get_type(const struct lttng_rate_policy *policy);

/*
 * Create a rate_policy of type `every n`.
 *
 * A `every n` rate policy will carry the execution of an action only when the
 * action was ready for execution for a multiple of N.
 *
 * Returns a rate_policy object on success, NULL on error.
 * rate_policy objects must be destroyed using the lttng_rate_policy_destroy()
 * function.
 */
LTTNG_EXPORT extern struct lttng_rate_policy *lttng_rate_policy_every_n_create(uint64_t interval);

/*
 * Get the interval of a every N rate policy.
 *
 * Returns LTTNG_RATE_POLICY_STATUS_OK and a sets the interval.
 * on success, LTTNG_RATE_FIRING_POLICY_STATUS_INVALID if an invalid
 * parameter is passed.
 */
LTTNG_EXPORT extern enum lttng_rate_policy_status
lttng_rate_policy_every_n_get_interval(const struct lttng_rate_policy *policy, uint64_t *interval);

/*
 * Create a rate_policy of type `once after N`.
 *
 * A `once after N` rate policy will carry the execution of an action only when
 * the action was ready for execution at least N times and will only be carried
 * one time.
 *
 * Returns a rate_policy object on success, NULL on error.
 * rate_policy objects must be destroyed using the lttng_rate_policy_destroy()
 * function.
 */
LTTNG_EXPORT extern struct lttng_rate_policy *
lttng_rate_policy_once_after_n_create(uint64_t threshold);

/*
 * Get the threshold of a once after N rate policy.
 *
 * Returns LTTNG_RATE_POLICY_STATUS_OK and sets the threshold.
 * on success, LTTNG_RATE_POLICY_STATUS_INVALID if an invalid
 * parameter is passed.
 */
LTTNG_EXPORT extern enum lttng_rate_policy_status
lttng_rate_policy_once_after_n_get_threshold(const struct lttng_rate_policy *policy,
					     uint64_t *threshold);

/*
 * Destroy (frees) a rate policy object.
 */
LTTNG_EXPORT extern void lttng_rate_policy_destroy(struct lttng_rate_policy *policy);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_rate_policy_H */
