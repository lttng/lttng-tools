/*
 * Copyright (C) 2020 Michael Jeanson <mjeanson@efficios.com>
 *
 * SPDX-License-Identifier: BSL-1.0
 *
 */

#ifndef MSGPACK_LTTNG_CONFIG_H
#define MSGPACK_LTTNG_CONFIG_H

#include <limits.h>
#include <common/compat/endian.hpp>

#if BYTE_ORDER == LITTLE_ENDIAN
#define MSGPACK_ENDIAN_LITTLE_BYTE 1
#define MSGPACK_ENDIAN_BIG_BYTE 0
#elif BYTE_ORDER == BIG_ENDIAN
#define MSGPACK_ENDIAN_LITTLE_BYTE 0
#define MSGPACK_ENDIAN_BIG_BYTE 1
#endif

#endif
