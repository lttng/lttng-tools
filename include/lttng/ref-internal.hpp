#ifndef LTTNG_REF_INTERNAL_H
#define LTTNG_REF_INTERNAL_H

/*
 * LTTng - Non thread-safe reference counting
 *
 * Copyright 2013, 2014 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

using lttng_release_func = void (*)(void *);

struct lttng_ref {
	unsigned long count;
	lttng_release_func release;
};

static inline void lttng_ref_init(struct lttng_ref *ref, lttng_release_func release)
{
	LTTNG_ASSERT(ref);
	ref->count = 1;
	ref->release = release;
}

static inline void lttng_ref_get(struct lttng_ref *ref)
{
	LTTNG_ASSERT(ref);
	ref->count++;
	/* Overflow check. */
	LTTNG_ASSERT(ref->count);
}

static inline void lttng_ref_put(struct lttng_ref *ref)
{
	LTTNG_ASSERT(ref);
	/* Underflow check. */
	LTTNG_ASSERT(ref->count);
	if (caa_unlikely((--ref->count) == 0)) {
		ref->release(ref);
	}
}

#endif /* LTTNG_REF_INTERNAL_H */
