/*
 * Copyright (C) 2010-2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 *
 */

#ifndef _LTTNG_ALIGN_H
#define _LTTNG_ALIGN_H

#include "bug.h"
#include <unistd.h>
#include <limits.h>

#ifndef PAGE_SIZE	/* Cygwin limits.h defines its own PAGE_SIZE. */
#define PAGE_SIZE		sysconf(_SC_PAGE_SIZE)
#endif

#ifndef PAGE_MASK	/* macOS defines its own PAGE_MASK. */
#define PAGE_MASK		(~(PAGE_SIZE - 1))
#endif

#define __ALIGN_MASK(v, mask)	(((v) + (mask)) & ~(mask))

#ifndef ALIGN		/* macOS defines its own ALIGN. */
#define ALIGN(v, align)		__ALIGN_MASK(v, (__typeof__(v)) (align) - 1)
#endif

#define __ALIGN_FLOOR_MASK(v, mask)	((v) & ~(mask))

#ifndef ALIGN_FLOOR
#define ALIGN_FLOOR(v, align)	__ALIGN_FLOOR_MASK(v, (__typeof__(v)) (align) - 1)
#endif

#define PAGE_ALIGN(addr)	ALIGN(addr, PAGE_SIZE)

/**
 * offset_align - Calculate the offset needed to align an object on its natural
 *                alignment towards higher addresses.
 * @align_drift:  object offset from an "alignment"-aligned address.
 * @alignment:    natural object alignment. Must be non-zero, power of 2.
 *
 * Returns the offset that must be added to align towards higher
 * addresses.
 */
#define offset_align(align_drift, alignment)				       \
	({								       \
		LTTNG_BUILD_RUNTIME_BUG_ON((alignment) == 0		       \
				   || ((alignment) & ((alignment) - 1)));      \
		(((alignment) - (align_drift)) & ((alignment) - 1));	       \
	})

/**
 * offset_align_floor - Calculate the offset needed to align an object
 *                      on its natural alignment towards lower addresses.
 * @align_drift:  object offset from an "alignment"-aligned address.
 * @alignment:    natural object alignment. Must be non-zero, power of 2.
 *
 * Returns the offset that must be substracted to align towards lower addresses.
 */
#define offset_align_floor(align_drift, alignment)			       \
	({								       \
		LTTNG_BUILD_RUNTIME_BUG_ON((alignment) == 0		       \
				   || ((alignment) & ((alignment) - 1)));      \
		(((align_drift) - (alignment)) & ((alignment) - 1));	       \
	})

#endif /* _LTTNG_ALIGN_H */
