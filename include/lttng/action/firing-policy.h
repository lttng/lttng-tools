/*
 * Copyright (C) 2021 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_FIRING_POLICY_H
#define LTTNG_FIRING_POLICY_H

#include <inttypes.h>
#include <sys/types.h>

struct lttng_firing_policy;

#ifdef __cplusplus
extern "C" {
#endif

enum lttng_firing_policy_status {
	LTTNG_FIRING_POLICY_STATUS_OK = 0,
	LTTNG_FIRING_POLICY_STATUS_ERROR = -1,
	LTTNG_FIRING_POLICY_STATUS_UNKNOWN = -2,
	LTTNG_FIRING_POLICY_STATUS_INVALID = -3,
	LTTNG_FIRING_POLICY_STATUS_UNSET = -4,
	LTTNG_FIRING_POLICY_STATUS_UNSUPPORTED = -5,
};

enum lttng_firing_policy_type {
	LTTNG_FIRING_POLICY_TYPE_UNKNOWN = -1,
	LTTNG_FIRING_POLICY_TYPE_EVERY_N = 0,
	LTTNG_FIRING_POLICY_TYPE_ONCE_AFTER_N = 1,
};

/*
 * Get the type of a firing policy.
 */
extern enum lttng_firing_policy_type lttng_firing_policy_get_type(
		const struct lttng_firing_policy *policy);

/*
 * Create a firing_policy of type `every n`.
 *
 * A `every n` firing policy will carry the execution of an action only when the
 * action was ready for execution for a multiple of N.
 *
 * Returns a firing_policy object on success, NULL on error.
 * firing_policy objects must be destroyed using the
 * lttng_firing_policy_destroy() function.
 */
extern struct lttng_firing_policy *lttng_firing_policy_every_n_create(
		uint64_t interval);

/*
 * Get the interval of a every N firing policy.
 *
 * Returns LTTNG_FIRING_POLICY_STATUS_OK and a sets the interval.
 * on success, LTTNG_FIRING_POLICY_STATUS_INVALID if an invalid
 * parameter is passed.
 */
extern enum lttng_firing_policy_status lttng_firing_policy_every_n_get_interval(
		const struct lttng_firing_policy *policy, uint64_t *interval);

/*
 * Create a firing_policy of type `once after N`.
 *
 * A `once after N` firing policy will carry the execution of an action only
 * when the action was ready for execution at least N times and will only be
 * carried one time.
 *
 * Returns a firing_policy object on success, NULL on error.
 * firing_policy objects must be destroyed using the
 * lttng_firing_policy_destroy() function.
 */
extern struct lttng_firing_policy *lttng_firing_policy_once_after_n_create(
		uint64_t threshold);

/*
 * Get the threshold of a once after N firing policy.
 *
 * Returns LTTNG_FIRING_POLICY_STATUS_OK and sets the threshold.
 * on success, LTTNG_FIRING_POLICY_STATUS_INVALID if an invalid
 * parameter is passed.
 */
extern enum lttng_firing_policy_status
lttng_firing_policy_once_after_n_get_threshold(
		const struct lttng_firing_policy *policy, uint64_t *threshold);

/*
 * Destroy (frees) a firing policy object.
 */
extern void lttng_firing_policy_destroy(struct lttng_firing_policy *policy);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_FIRING_POLICY_H */
