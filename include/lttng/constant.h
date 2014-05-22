/*
 * Copyright (C) 2014 - David Goulet <dgoulet@efficios.com>
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

#ifndef LTTNG_CONSTANT_H
#define LTTNG_CONSTANT_H

#ifndef LTTNG_DEPRECATED
#if defined (__GNUC__) \
	&& ((__GNUC_MAJOR__ == 4) && (__GNUC_MINOR__ >= 5)  \
			|| __GNUC_MAJOR__ >= 5)
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
#define LTTNG_SYMBOL_NAME_LEN             256

#endif /* LTTNG_CONSTANT_H */
