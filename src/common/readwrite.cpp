/*
 * SPDX-FileCopyrightText: 2013 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#define _LGPL_SOURCE
#include "readwrite.hpp"

#include <common/compat/errno.hpp>

#include <limits.h>
#include <unistd.h>

namespace {
template <typename IOFunctionType>
ssize_t complete_io(const size_t count, const IOFunctionType& io_function)
{
	if (count > SSIZE_MAX) {
		errno = EINVAL;
		return -1;
	}

	size_t io_length = 0;

	while (io_length < count) {
		const auto ret = io_function(io_length);

		if (ret < 0 && errno == EINTR) {
			continue;
		} else if (ret < 0) {
			return -1;
		} else if (ret == 0) {
			break;
		}

		io_length += ret;
		LTTNG_ASSERT(io_length <= count);
	}

	return static_cast<ssize_t>(io_length);
}
} /* namespace */

/*
 * lttng_read and lttng_write take care of EINTR and partial read/write.
 * Upon success, they return the "count" received as parameter.
 * They can return a negative value if an error occurs.
 * If a value lower than the requested "count" is returned, it means an
 * error occurred.
 * The error can be checked by querying errno.
 */
ssize_t lttng_read(int fd, void *buf, size_t count)
{
	size_t i = 0;
	ssize_t ret;

	LTTNG_ASSERT(buf);

	/*
	 * Deny a read count that can be bigger then the returned value max size.
	 * This makes the function to never return an overflow value.
	 */
	if (count > SSIZE_MAX) {
		return -EINVAL;
	}

	do {
		ret = read(fd, (char *) buf + i, count - i);
		if (ret < 0) {
			if (errno == EINTR) {
				continue; /* retry operation */
			} else {
				goto error;
			}
		}
		i += ret;
		LTTNG_ASSERT(i <= count);
	} while (count - i > 0 && ret > 0);
	return i;

error:
	if (i == 0) {
		return -1;
	} else {
		return i;
	}
}

ssize_t lttng_write(int fd, const void *buf, size_t count)
{
	size_t i = 0;
	ssize_t ret;

	LTTNG_ASSERT(buf);

	/*
	 * Deny a write count that can be bigger then the returned value max size.
	 * This makes the function to never return an overflow value.
	 */
	if (count > SSIZE_MAX) {
		return -EINVAL;
	}

	do {
		ret = write(fd, (char *) buf + i, count - i);
		if (ret < 0) {
			if (errno == EINTR) {
				continue; /* retry operation */
			} else {
				goto error;
			}
		}
		i += ret;
		LTTNG_ASSERT(i <= count);
	} while (count - i > 0 && ret > 0);
	return i;

error:
	if (i == 0) {
		return -1;
	} else {
		return i;
	}
}

ssize_t lttng_pread(const int fd, void *const buf, const size_t count, const off_t offset)
{
	LTTNG_ASSERT(buf);

	return complete_io(count, [=](const size_t io_length) {
		return pread(fd,
			     static_cast<char *>(buf) + io_length,
			     count - io_length,
			     offset + static_cast<off_t>(io_length));
	});
}

ssize_t lttng_pwrite(const int fd, const void *const buf, const size_t count, const off_t offset)
{
	LTTNG_ASSERT(buf);

	return complete_io(count, [=](const size_t io_length) {
		return pwrite(fd,
			      static_cast<const char *>(buf) + io_length,
			      count - io_length,
			      offset + static_cast<off_t>(io_length));
	});
}
