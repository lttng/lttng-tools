/*
 * Copyright (C) 2020 Michael Jeanson <mjeanson@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <string.h>

#include <common/compat/pthread.h>
#include "thread.h"

#define LTTNG_PTHREAD_NAMELEN 16

int lttng_thread_setname(const char *name)
{
	int ret;
	char pthread_name[LTTNG_PTHREAD_NAMELEN];

	/*
	 * Truncations are expected since pthread limits thread names to
	 * a generous 16 characters.
	 */
	strncpy(pthread_name, name, sizeof(pthread_name));
	pthread_name[sizeof(pthread_name) - 1] = '\0';

	ret = lttng_pthread_setname_np(pthread_name);

	return ret;
}

