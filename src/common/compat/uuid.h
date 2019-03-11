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

#include <common/macros.h>
#include <stdbool.h>

/*
 * Includes final \0.
 */
#define UUID_STR_LEN		37
#define UUID_LEN		16

typedef unsigned char lttng_uuid[UUID_LEN];

#ifdef LTTNG_HAVE_LIBUUID
#include <uuid/uuid.h>

/*
 * uuid_out is of len UUID_LEN.
 */
static inline
int lttng_uuid_generate(lttng_uuid uuid_out)
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
int lttng_uuid_generate(lttng_uuid uuid_out)
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

/*
 * Convert a UUID to a human-readable, NULL-terminated, string of the form
 * xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx.
 *
 * Assumes uuid_str is at least UUID_STR_LEN byte long.
 */
LTTNG_HIDDEN
void lttng_uuid_to_str(const lttng_uuid uuid, char *uuid_str);

LTTNG_HIDDEN
bool lttng_uuid_is_equal(const lttng_uuid a, const lttng_uuid b);

#endif /* LTTNG_UUID_H */
