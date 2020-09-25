/*
 * Copyright (C) 2020 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <assert.h>
#include <stdbool.h>
#include "credentials.h"

uid_t lttng_credentials_get_uid(const struct lttng_credentials *creds)
{
	return LTTNG_OPTIONAL_GET(creds->uid);
}

gid_t lttng_credentials_get_gid(const struct lttng_credentials *creds)
{
	return LTTNG_OPTIONAL_GET(creds->gid);
}

bool lttng_credentials_is_equal_uid(const struct lttng_credentials *a,
		const struct lttng_credentials *b)
{
	assert(a);
	assert(b);

	/* XOR on the is_set value */
	if (!!a->uid.is_set != !!b->uid.is_set) {
		return false;
	}

	if (!a->uid.is_set && !b->uid.is_set) {
		return true;
	}

	/* Both a and b are set. */
	return a->uid.value == b->uid.value;
}

bool lttng_credentials_is_equal_gid(const struct lttng_credentials *a,
		const struct lttng_credentials *b)
{
	assert(a);
	assert(b);

	/* XOR on the is_set value */
	if (!!a->gid.is_set != !!b->gid.is_set) {
		return false;
	}

	if (!a->gid.is_set && !b->gid.is_set) {
		return true;
	}

	/* Both a and b are set. */
	return a->gid.value == b->gid.value;
}

bool lttng_credentials_is_equal(const struct lttng_credentials *a,
		const struct lttng_credentials *b)
{
	assert(a);
	assert(b);

	return lttng_credentials_is_equal_uid(a, b) &&
			lttng_credentials_is_equal_gid(a, b);
}
