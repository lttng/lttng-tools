/*
 * Copyright (C) 2019 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_CREDENTIALS_H
#define LTTNG_CREDENTIALS_H

#include <sys/types.h>

struct lttng_credentials {
	uid_t uid;
	gid_t gid;
};

#endif /* LTTNG_CREDENTIALS_H */
