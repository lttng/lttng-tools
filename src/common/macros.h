/*
 * Copyright (C) 2011 David Goulet <david.goulet@polymtl.ca>
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
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

#ifndef LTTNG_PACKED
#define LTTNG_PACKED __attribute__((__packed__))
#endif

#ifndef LTTNG_NO_SANITIZE_ADDRESS
#if defined(__clang__) || defined (__GNUC__)
#define LTTNG_NO_SANITIZE_ADDRESS __attribute__((no_sanitize_address))
#else
#define LTTNG_NO_SANITIZE_ADDRESS
#endif
#endif

#define is_signed(type) (((type) -1) < (type) 1)

#define member_sizeof(type, field)	sizeof(((type *) 0)->field)

#define ASSERT_LOCKED(lock) LTTNG_ASSERT(pthread_mutex_trylock(&lock))

/* Attribute suitable to tag functions as having printf()-like arguments. */
#define ATTR_FORMAT_PRINTF(_string_index, _first_to_check) \
	__attribute__((format(printf, _string_index, _first_to_check)))

/* Macros used to ignore specific compiler diagnostics. */

#define DIAGNOSTIC_PUSH _Pragma("GCC diagnostic push")
#define DIAGNOSTIC_POP _Pragma("GCC diagnostic pop")

#if defined(__clang__)
  /* Clang */
# define DIAGNOSTIC_IGNORE_SUGGEST_ATTRIBUTE_FORMAT
#else
  /* GCC */
# define DIAGNOSTIC_IGNORE_SUGGEST_ATTRIBUTE_FORMAT \
	_Pragma("GCC diagnostic ignored \"-Wsuggest-attribute=format\"")
#endif

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
	if (lttng_strnlen(src, dst_len) >= dst_len) {
		/* Fail since copying would result in truncation. */
		return -1;
	}
	strcpy(dst, src);
	return 0;
}

#ifdef NDEBUG
/*
* Force usage of the assertion condition to prevent unused variable warnings
* when `assert()` are disabled by the `NDEBUG` definition.
*/
# define LTTNG_ASSERT(_cond) ((void) sizeof((void) (_cond), 0))
#else
# include <assert.h>
# define LTTNG_ASSERT(_cond) assert(_cond)
#endif

#endif /* _MACROS_H */
