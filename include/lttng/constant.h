/*
 * Copyright (C) 2014 David Goulet <dgoulet@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_CONSTANT_H
#define LTTNG_CONSTANT_H

#ifndef LTTNG_DEPRECATED
#if defined(__GNUC__) && ((__GNUC__ == 4) && (__GNUC_MINOR__ >= 5) || __GNUC__ >= 5)
#define LTTNG_DEPRECATED(msg) __attribute__((deprecated(msg)))
#else
#define LTTNG_DEPRECATED(msg) __attribute__((deprecated))
#endif /* defined __GNUC__ */
#endif /* LTTNG_DEPRECATED */

#include <limits.h>
/*
 * Necessary to include the fixed width type limits on glibc versions older
 * than 2.18 when building with a C++ compiler.
 */
#ifndef __STDC_LIMIT_MACROS
#define __STDC_LIMIT_MACROS
#include <stdint.h>
#undef __STDC_LIMIT_MACROS
#else /* #ifndef __STDC_LIMIT_MACROS */
#include <stdint.h>
#endif /* #else #ifndef __STDC_LIMIT_MACROS */
#include <sys/types.h>

/*
 * Event symbol length. Copied from LTTng kernel ABI.
 */
#define LTTNG_SYMBOL_NAME_LEN 256

/*
 * PROC(5) mentions that PID_MAX_LIMIT may not exceed 2^22 on 64-bit HW.
 * We prefer to use 32-bits for simplicity's sake.
 */
#define LTTNG_MAX_PID	  INT32_MAX
#define LTTNG_MAX_PID_STR "2147483647"

#define LTTNG_NAME_MAX 255

/*
 * POSIX guarantees that a host name will not exceed 255 characters.
 * Moreover, RFC 1035 limits the length of a fully qualified domain name (FQDN)
 * to 255 characters.
 *
 * 256 is used to include a trailing NULL character.
 */
#define LTTNG_HOST_NAME_MAX 256

#define LTTNG_PATH_MAX 4096

#endif /* LTTNG_CONSTANT_H */
