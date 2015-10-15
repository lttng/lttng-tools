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

#ifndef _COMPAT_NETDB_H
#define _COMPAT_NETDB_H

#include <netdb.h>

#ifdef HAVE_GETHOSTBYNAME2
static inline
struct hostent *lttng_gethostbyname2(const char *name, int af) {
	return gethostbyname2(name, af);
}
#elif HAVE_GETIPNODEBYNAME
static inline
struct hostent *lttng_gethostbyname2(const char *name, int af) {
	int unused;

	return getipnodebyname(name, af, AI_DEFAULT, &unused);
}
#else
# error "Missing compat for gethostbyname2()"
#endif

#endif /* _COMPAT_NETDB_H */
