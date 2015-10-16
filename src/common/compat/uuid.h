/*
 * Copyright (C) 2011  Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#ifndef LTTNG_UUID_H
#define LTTNG_UUID_H

/*
 * Includes final \0.
 */
#define UUID_STR_LEN		37
#define UUID_LEN		16

#ifdef LTTNG_HAVE_LIBUUID
#include <uuid/uuid.h>

/*
 * uuid_out is of len UUID_LEN.
 */
static inline
int lttng_uuid_generate(unsigned char *uuid_out)
{
	uuid_generate(uuid_out);
	return 0;
}

#elif defined(LTTNG_HAVE_LIBC_UUID)
#include <uuid.h>
#include <stdint.h>

/*
 * uuid_out is of len UUID_LEN.
 */
static inline
int lttng_uuid_generate(unsigned char *uuid_out)
{
	uint32_t status;

	uuid_create((uuid_t *) uuid_out, &status);
	if (status == uuid_s_ok)
		return 0;
	else
		return -1;
}

#else
#error "LTTng-Tools needs to have a UUID generator configured."
#endif

#endif /* LTTNG_UUID_H */
