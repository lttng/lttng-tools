#ifndef LTTNG_COMMON_READWRITE_H
#define LTTNG_COMMON_READWRITE_H

/*
 * Copyright (C) 2013 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <common/macros.hpp>

#include <unistd.h>

/*
 * lttng_read and lttng_write take care of EINTR and partial read/write.
 * Upon success, they return the "count" received as parameter.
 * They can return a negative value if an error occurs.
 * If a value lower than the requested "count" is returned, it means an
 * error occurred.
 * The error can be checked by querying errno.
 */
ssize_t lttng_read(int fd, void *buf, size_t count);
ssize_t lttng_write(int fd, const void *buf, size_t count);

#endif /* LTTNG_COMMON_READWRITE_H */
