/*
 * Copyright (C) 2021 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_RATE_POLICY_INTERNAL_H
#define LTTNG_RATE_POLICY_INTERNAL_H

#include <common/macros.hpp>
#include <common/payload-view.hpp>

#include <lttng/action/rate-policy.h>
#include <lttng/lttng-error.h>

#include <stdbool.h>

struct mi_writer;

int lttng_rate_policy_serialize(struct lttng_rate_policy *rate_policy, struct lttng_payload *buf);

ssize_t lttng_rate_policy_create_from_payload(struct lttng_payload_view *view,
					      struct lttng_rate_policy **rate_policy);

bool lttng_rate_policy_is_equal(const struct lttng_rate_policy *a,
				const struct lttng_rate_policy *b);

const char *lttng_rate_policy_type_string(enum lttng_rate_policy_type rate_policy_type);

struct lttng_rate_policy *lttng_rate_policy_copy(const struct lttng_rate_policy *source);

bool lttng_rate_policy_should_execute(const struct lttng_rate_policy *policy, uint64_t counter);

enum lttng_error_code lttng_rate_policy_mi_serialize(const struct lttng_rate_policy *policy,
						     struct mi_writer *writer);

#endif /* LTTNG_RATE_POLICY */
