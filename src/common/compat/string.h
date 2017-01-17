/*
 * Copyright (C) 2015 Michael Jeanson <mjeanson@efficios.com>
 *               2015 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef _COMPAT_STRING_H
#define _COMPAT_STRING_H

#include <string.h>

#ifdef HAVE_STRNLEN
static inline
size_t lttng_strnlen(const char *str, size_t max)
{
	return strnlen(str, max);
}
#else
static inline
size_t lttng_strnlen(const char *str, size_t max)
{
	size_t ret;
	const char *end;

	end = memchr(str, 0, max);

	if (end) {
		ret = (size_t) (end - str);
	} else {
		ret = max;
	}

	return ret;
}
#endif /* HAVE_STRNLEN */

#ifdef HAVE_STRNDUP
static inline
char *lttng_strndup(const char *s, size_t n)
{
	return strndup(s, n);
}
#else
static inline
char *lttng_strndup(const char *s, size_t n)
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

	ret = malloc(navail);
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

#endif /* _COMPAT_STRING_H */
