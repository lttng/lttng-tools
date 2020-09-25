/*
 * Copyright (C) 2019 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_CREDENTIALS_H
#define LTTNG_CREDENTIALS_H

#include <sys/types.h>
#include <stdbool.h>

#include "optional.h"

struct lttng_credentials {
	LTTNG_OPTIONAL(uid_t) uid;
	LTTNG_OPTIONAL(gid_t) gid;
};

uid_t lttng_credentials_get_uid(const struct lttng_credentials *creds);
gid_t lttng_credentials_get_gid(const struct lttng_credentials *creds);

bool lttng_credentials_is_equal_uid(const struct lttng_credentials *a,
		const struct lttng_credentials *b);

bool lttng_credentials_is_equal_gid(const struct lttng_credentials *a,
		const struct lttng_credentials *b);

bool lttng_credentials_is_equal(const struct lttng_credentials *a,
		const struct lttng_credentials *b);

#endif /* LTTNG_CREDENTIALS_H */
