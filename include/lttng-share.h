/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *                      Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; only version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef _LTTNG_SHARE_H
#define _LTTNG_SHARE_H

#include <stdlib.h>

/* Default channel attributes */
#define DEFAULT_CHANNEL_NAME            "channel0"
#define DEFAULT_CHANNEL_OVERWRITE       0       /* usec */
/* DEFAULT_CHANNEL_SUBBUF_SIZE must always be a power of 2 */
#define DEFAULT_CHANNEL_SUBBUF_SIZE     4096    /* bytes */
/* DEFAULT_CHANNEL_SUBBUF_NUM must always be a power of 2 */
#define DEFAULT_CHANNEL_SUBBUF_NUM      8
#define DEFAULT_CHANNEL_SWITCH_TIMER    0       /* usec */
#define DEFAULT_CHANNEL_READ_TIMER		200     /* usec */
#define DEFAULT_CHANNEL_OUTPUT          LTTNG_EVENT_MMAP

#define DEFAULT_METADATA_SUBBUF_SIZE    4096
#define DEFAULT_METADATA_SUBBUF_NUM     2

/* Kernel has different defaults */

/* DEFAULT_KERNEL_CHANNEL_SUBBUF_SIZE must always be a power of 2 */
#define DEFAULT_KERNEL_CHANNEL_SUBBUF_SIZE  262144    /* bytes */
/* DEFAULT_KERNEL_CHANNEL_SUBBUF_NUM must always be a power of 2 */
#define DEFAULT_KERNEL_CHANNEL_SUBBUF_NUM   4
/* See lttng-kernel.h enum lttng_kernel_output for channel output */
#define DEFAULT_KERNEL_CHANNEL_OUTPUT       LTTNG_EVENT_SPLICE

/* User space defaults */

/* Must be a power of 2 */
#define DEFAULT_UST_CHANNEL_SUBBUF_SIZE     4096    /* bytes */
/* Must be a power of 2 */
#define DEFAULT_UST_CHANNEL_SUBBUF_NUM      4

/*
 * Takes a pointer x and transform it so we can use it to access members
 * without a function call. Here an example:
 *
 *    #define GET_SIZE(x) LTTNG_REF(x)->size
 *
 *    struct { int size; } s;
 *
 *    printf("size : %d\n", GET_SIZE(&s));
 *
 * For this example we can't use something like this for compatibility purpose
 * since this will fail:
 *
 *    #define GET_SIZE(x) x->size;
 *
 * This is mostly use for the compatibility layer of lttng-tools. See
 * poll/epoll for a good example. Since x can be on the stack or allocated
 * memory using malloc(), we must use generic accessors for compat in order to
 * *not* use a function to access members and not the variable name.
 */
#define LTTNG_REF(x) ((typeof(*x) *)(x))

/*
 * Memory allocation zeroed
 */
#define zmalloc(x) calloc(1, x)

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(array)   (sizeof(array) / (sizeof((array)[0])))
#endif


#endif /* _LTTNG_SHARE_H */
