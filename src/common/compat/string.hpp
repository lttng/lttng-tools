/*
 * Copyright (C) 2015 Michael Jeanson <mjeanson@efficios.com>
 * Copyright (C) 2015 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 *
 */

#ifndef _COMPAT_STRING_H
#define _COMPAT_STRING_H

#include <stdlib.h>
#include <string.h>

#ifdef HAVE_STRNLEN
static inline size_t lttng_strnlen(const char *str, size_t max)
{
	return strnlen(str, max);
}
#else
static inline size_t lttng_strnlen(const char *str, size_t max)
{
	size_t ret;
	const char *end;

	end = (const char *) memchr(str, 0, max);

	if (end) {
		ret = (size_t) (end - str);
	} else {
		ret = max;
	}

	return ret;
}
#endif /* HAVE_STRNLEN */

#ifdef HAVE_STRNDUP
static inline char *lttng_strndup(const char *s, size_t n)
{
	return strndup(s, n);
}
#else
static inline char *lttng_strndup(const char *s, size_t n)
{
	char *ret;
	size_t navail;

	if (!s) {
		ret = NULL;
		goto end;
	}

	/* min() */
	navail = strlen(s) + 1;
	if ((n + 1) < navail) {
		navail = n + 1;
	}

	ret = malloc<char>(navail);
	if (!ret) {
		goto end;
	}

	memcpy(ret, s, navail);
	ret[navail - 1] = '\0';
end:
	return ret;
}
#endif /* HAVE_STRNDUP */

#ifdef HAVE_FLS
static inline int lttng_fls(int val)
{
	return fls(val);
}
#else
static inline int lttng_fls(int val)
{
	int r = 32;
	unsigned int x = (unsigned int) val;

	if (!x)
		return 0;
	if (!(x & 0xFFFF0000U)) {
		x <<= 16;
		r -= 16;
	}
	if (!(x & 0xFF000000U)) {
		x <<= 8;
		r -= 8;
	}
	if (!(x & 0xF0000000U)) {
		x <<= 4;
		r -= 4;
	}
	if (!(x & 0xC0000000U)) {
		x <<= 2;
		r -= 2;
	}
	if (!(x & 0x80000000U)) {
		r -= 1;
	}
	return r;
}
#endif /* HAVE_FLS */

#ifdef HAVE_MEMRCHR
static inline void *lttng_memrchr(const void *s, int c, size_t n)
{
	return (void *) memrchr(s, c, n);
}
#else
static inline void *lttng_memrchr(const void *s, int c, size_t n)
{
	int i;
	const char *str = (const char *) s;
	for (i = n - 1; i >= 0; i--) {
		if (str[i] == (char) c) {
			return (void *) (str + i);
		}
	}
	return NULL;
}
#endif /* HAVE_MEMRCHR */

#endif /* _COMPAT_STRING_H */
