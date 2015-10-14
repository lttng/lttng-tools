#ifndef _COMPAT_STRING_H
#define _COMPAT_STRING_H

/*
 * Copyright (C) 2015 Michael Jeanson <mjeanson@efficios.com>
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

#endif /* _COMPAT_STRING_H */
