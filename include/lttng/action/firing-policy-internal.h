/*
 * Copyright (C) 2021 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_FIRING_POLICY_INTERNAL_H
#define LTTNG_FIRING_POLICY_INTERNAL_H

#include <common/macros.h>
#include <lttng/action/firing-policy.h>
#include <common/payload-view.h>
#include <stdbool.h>

LTTNG_HIDDEN
int lttng_firing_policy_serialize(struct lttng_firing_policy *firing_policy,
		struct lttng_payload *buf);

LTTNG_HIDDEN
ssize_t lttng_firing_policy_create_from_payload(struct lttng_payload_view *view,
		struct lttng_firing_policy **firing_policy);

LTTNG_HIDDEN
bool lttng_firing_policy_is_equal(const struct lttng_firing_policy *a,
		const struct lttng_firing_policy *b);

LTTNG_HIDDEN
const char *lttng_firing_policy_type_string(
		enum lttng_firing_policy_type firing_policy_type);

LTTNG_HIDDEN
struct lttng_firing_policy *lttng_firing_policy_copy(
		const struct lttng_firing_policy *source);

LTTNG_HIDDEN
bool lttng_firing_policy_should_execute(
		const struct lttng_firing_policy *policy, uint64_t counter);

#endif /* LTTNG_FIRING_POLICY */
