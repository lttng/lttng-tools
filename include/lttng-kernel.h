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
	LTTNG_KERNEL_TRACEPOINTS,
	LTTNG_KERNEL_KPROBES,
	LTTNG_KERNEL_FUNCTION,
};

/*
 * LTTng DebugFS ABI structures.
 *
 * This is the kernel ABI copied from lttng-modules tree.
 */

/* Either addr is used or symbol_name and offset. */
struct lttng_kernel_kprobe {
	uint64_t addr;

	uint64_t offset;
	char symbol_name[LTTNG_SYM_NAME_LEN];
};

struct lttng_kernel_function_tracer {
	char symbol_name[LTTNG_SYM_NAME_LEN];
};

struct lttng_kernel_event {
	char name[LTTNG_SYM_NAME_LEN];
	enum lttng_kernel_instrumentation instrumentation;
	/* Per instrumentation type configuration */
	union {
		struct lttng_kernel_kprobe kprobe;
		struct lttng_kernel_function_tracer ftrace;
	} u;
};

struct lttng_kernel_tracer_version {
	uint32_t version;
	uint32_t patchlevel;
	uint32_t sublevel;
};

#endif /* _LTTNG_KERNEL_H */
