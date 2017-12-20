#ifndef LTTNG_REF_INTERNAL_H
#define LTTNG_REF_INTERNAL_H

/*
 * LTTng - Non thread-safe reference counting
 *
 * Copyright 2013, 2014 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * Author: Jérémie Galarneau <jeremie.galarneau@efficios.com>
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

#include <assert.h>

typedef void (*lttng_release_func)(void *);

struct lttng_ref {
	unsigned long count;
	lttng_release_func release;
};

static inline
void lttng_ref_init(struct lttng_ref *ref, lttng_release_func release)
{
	assert(ref);
	ref->count = 1;
	ref->release = release;
}

static inline
void lttng_ref_get(struct lttng_ref *ref)
{
	assert(ref);
	ref->count++;
	/* Overflow check. */
	assert(ref->count);
}

static inline
void lttng_ref_put(struct lttng_ref *ref)
{
	assert(ref);
	/* Underflow check. */
	assert(ref->count);
	if (caa_unlikely((--ref->count) == 0)) {
		ref->release(ref);
	}
}

#endif /* LTTNG_REF_INTERNAL_H */
