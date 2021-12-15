/*
 * Copyright (C) 2020 Michael Jeanson <mjeanson@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_THREAD_H
#define LTTNG_THREAD_H

#include <common/macros.hpp>

/*
 * Set the current thread name on platforms that support it. The name can
 * be of arbitrary length and will be truncated to the platform limit,
 * usually 16.
 */
int lttng_thread_setname(const char *name);

#endif /* LTTNG_THREAD_H */
