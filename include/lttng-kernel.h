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

#include "lttng-share.h"

#define LTTNG_SYM_NAME_LEN  128

enum lttng_kernel_instrumentation {
	LTTNG_KERNEL_TRACEPOINT    = 0,
	LTTNG_KERNEL_KPROBE        = 1,
	LTTNG_KERNEL_FUNCTION      = 2,
};

/*
 * LTTng consumer mode
 */
enum lttng_kernel_output {
	LTTNG_KERNEL_SPLICE       = 0,
	LTTNG_KERNEL_MMAP         = 1,
};

/*
 * LTTng DebugFS ABI structures.
 *
 * This is the kernel ABI copied from lttng-modules tree.
 */

/* Function tracer */
struct lttng_kernel_function_attr {
	char symbol_name[LTTNG_SYM_NAME_LEN];
};

struct lttng_kernel_event {
	char name[LTTNG_SYM_NAME_LEN];
	enum lttng_kernel_instrumentation instrumentation;
	/* Per instrumentation type configuration */
	union {
		struct lttng_kernel_kprobe_attr kprobe;
		struct lttng_kernel_function_attr ftrace;
	} u;
};

struct lttng_kernel_tracer_version {
	uint32_t version;
	uint32_t patchlevel;
	uint32_t sublevel;
};

#endif /* _LTTNG_KERNEL_H */
