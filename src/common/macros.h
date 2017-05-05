/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *                      Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _MACROS_H
#define _MACROS_H

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <common/compat/string.h>

/*
 * Takes a pointer x and transform it so we can use it to access members
 * without a function call. Here an example:
 *
 *    #define GET_SIZE(x) LTTNG_REF(x)->size
 *
 *    struct { int size; } s;
 *
 *    printf("size : %d\n", GET_SIZE(&s));
 *
 * For this example we can't use something like this for compatibility purpose
 * since this will fail:
 *
 *    #define GET_SIZE(x) x->size;
 *
 * This is mostly use for the compatibility layer of lttng-tools. See
 * poll/epoll for a good example. Since x can be on the stack or allocated
 * memory using malloc(), we must use generic accessors for compat in order to
 * *not* use a function to access members and not the variable name.
 */
#define LTTNG_REF(x) ((typeof(*x) *)(x))

/*
 * Memory allocation zeroed
 */
static inline
void *zmalloc(size_t len)
{
	return calloc(1, len);
}

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(array)   (sizeof(array) / (sizeof((array)[0])))
#endif

#ifndef container_of
#define container_of(ptr, type, member)					\
	({								\
		const typeof(((type *)NULL)->member) * __ptr = (ptr);	\
		(type *)((char *)__ptr - offsetof(type, member));	\
	})
#endif

#ifndef max
#define max(a, b) ((a) > (b) ? (a) : (b))
#endif

#ifndef max_t
#define max_t(type, a, b)	((type) max(a, b))
#endif

#ifndef min
#define min(a, b) ((a) < (b) ? (a) : (b))
#endif

#ifndef LTTNG_PACKED
#define LTTNG_PACKED __attribute__((__packed__))
#endif

/*
 * LTTNG_HIDDEN: set the hidden attribute for internal functions
 * On Windows, symbols are local unless explicitly exported,
 * see https://gcc.gnu.org/wiki/Visibility
 */
#if defined(_WIN32) || defined(__CYGWIN__)
#define LTTNG_HIDDEN
#else
#define LTTNG_HIDDEN __attribute__((visibility("hidden")))
#endif

#define member_sizeof(type, field)	sizeof(((type *) 0)->field)

/*
 * lttng_strncpy returns 0 on success, or nonzero on failure.
 * It checks that the @src string fits into @dst_len before performing
 * the copy. On failure, no copy has been performed.
 *
 * dst_len includes the string's trailing NULL.
 */
static inline
int lttng_strncpy(char *dst, const char *src, size_t dst_len)
{
	if (lttng_strnlen(src, dst_len) == dst_len) {
		/* Fail since copying would result in truncation. */
		return -1;
	}
	strncpy(dst, src, dst_len);
	/*
	 * Be extra careful and put final \0 at the end after strncpy(),
	 * even though we checked the length before. This makes Coverity
	 * happy.
	 */
	dst[dst_len - 1] = '\0';
	return 0;
}

#endif /* _MACROS_H */
