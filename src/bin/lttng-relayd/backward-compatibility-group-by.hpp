/*
 * Copyright (C) 2019 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef BACKWARD_COMPATIBILITY_GROUP_BY_H
#define BACKWARD_COMPATIBILITY_GROUP_BY_H

#include <time.h>

char *backward_compat_group_by_session(const char *path,
				       const char *local_session_name,
				       time_t session_creation_time);

#endif /* BACKWARD_COMPATIBILITY_GROUP_BY_H */
