/*
 * Copyright (C) 2020 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <assert.h>
#include <stdbool.h>
#include "credentials.h"

bool lttng_credentials_is_equal(const struct lttng_credentials *a,
		const struct lttng_credentials *b)
{
	assert(a);
	assert(b);

	if ((a->uid != b->uid) || (a->gid != b->gid)) {
		return false;
	}

	return true;
};
