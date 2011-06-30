/*
 * Copyright (C) - 2011 - David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef _LTTNG_SHARE_H
#define _LTTNG_SHARE_H

#include <asm/types.h>
#include <stdint.h>

typedef uint32_t u32;
typedef uint64_t u64;

typedef __s64 s64;

#define LTTNG_RUNDIR        "/var/run/lttng"

/* Default channel attributes */
#define DEFAULT_CHANNEL_NAME			"channel0"
#define DEFAULT_CHANNEL_OVERWRITE		0
/* DEFAULT_CHANNEL_SUBBUF_SIZE must always be a power of 2 */
#define DEFAULT_CHANNEL_SUBBUF_SIZE		4096	/* bytes */
/* DEFAULT_CHANNEL_SUBBUF_NUM must always be a power of 2 */
#define DEFAULT_CHANNEL_SUBBUF_NUM		8
#define DEFAULT_CHANNEL_SWITCH_TIMER		0	/* usec */
#define DEFAULT_CHANNEL_READ_TIMER		200	/* usec */
/* See lttng.h enum lttng_kernel_output for channel output */
#define DEFAULT_KERNEL_CHANNEL_OUTPUT		LTTNG_KERNEL_SPLICE
#define DEFAULT_UST_CHANNEL_OUTPUT		LTTNG_UST_MMAP

/*
 * lttng user-space instrumentation type
 */
enum lttng_ust_instrumentation {
	LTTNG_UST_TRACEPOINT,
	LTTNG_UST_MARKER,
};

#endif /* _LTTNG_SHARE_H */
