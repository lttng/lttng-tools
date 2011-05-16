/*
 * Copyright (C) 2011 - Julien Desfossez <julien.desfossez@polymtl.ca>
 *                      Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *                      David Goulet <david.goulet@polymtl.ca>
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

#ifndef _LTTNG_KERNEL_H
#define _LTTNG_KERNEL_H

#include <stdint.h>

typedef uint64_t u64;

/*
 * LTTng DebugFS ABI structures.
 */
enum lttng_instrum_type {
	INSTRUM_TRACEPOINTS,
};

struct lttng_channel {
	int overwrite;         /* 1: overwrite, 0: discard */
	u64 subbuf_size;
	u64 num_subbuf;
	unsigned int switch_timer_interval;
	unsigned int read_timer_interval;
};

struct lttng_event {
	enum lttng_instrum_type itype;
	char name[];
};

#endif /* _LTTNG_KERNEL_H */
