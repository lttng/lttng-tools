/*
 * Copyright (C) 2023 Michael Jeanson <mjeanson@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef _LTTNG_IO_HINT_H
#define _LTTNG_IO_HINT_H

#include <sys/types.h>

namespace lttng {
namespace io {

void hint_flush_range_dont_need_sync(int fd, off_t offset, off_t nbytes);
void hint_flush_range_sync(int fd, off_t offset, off_t nbytes);
void hint_flush_range_async(int fd, off_t offset, off_t nbytes);

} /* namespace io */
} /* namespace lttng */

#endif
