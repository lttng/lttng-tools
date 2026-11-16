#ifndef LTTNG_COMMON_READWRITE_H
#define LTTNG_COMMON_READWRITE_H

/*
 * SPDX-FileCopyrightText: 2013 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

/*
 * Like lttng_read() and lttng_write(), but at `offset` from the beginning of
 * the file, without changing the file offset of `fd`.
 *
 * Returns -1 and sets `errno` on error, even after a partial transfer. A
 * return value lower than `count` means that the end of the file was
 * reached.
 */
ssize_t lttng_pread(int fd, void *buf, size_t count, off_t offset);
ssize_t lttng_pwrite(int fd, const void *buf, size_t count, off_t offset);

#endif /* LTTNG_COMMON_READWRITE_H */
