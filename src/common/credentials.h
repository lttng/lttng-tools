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

struct lttng_credentials {
	uid_t uid;
	gid_t gid;
};

bool lttng_credentials_is_equal(const struct lttng_credentials *a,
		const struct lttng_credentials *b);

#endif /* LTTNG_CREDENTIALS_H */
