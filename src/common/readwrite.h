#ifndef LTTNG_COMMON_READWRITE_H
#define LTTNG_COMMON_READWRITE_H

/*
 * Copyright (C) 2013 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License, version 2.1 only,
 * as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <unistd.h>
#include <common/macros.h>

/*
 * lttng_read and lttng_write take care of EINTR and partial read/write.
 * Upon success, they return the "count" received as parameter.
 * They can return a negative value if an error occurs.
 * If a value lower than the requested "count" is returned, it means an
 * error occurred.
 * The error can be checked by querying errno.
 */
LTTNG_HIDDEN
ssize_t lttng_read(int fd, void *buf, size_t count);
LTTNG_HIDDEN
ssize_t lttng_write(int fd, const void *buf, size_t count);

#endif /* LTTNG_COMMON_READWRITE_H */
