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

/*
 * LTTng DebugFS ABI structures.
 *
 * This is the kernel ABI copied from lttng-modules tree.
 */

enum lttng_kernel_instrumentation {
	LTTNG_KERNEL_TRACEPOINT    = 0,
	LTTNG_KERNEL_KPROBE        = 1,
	LTTNG_KERNEL_FUNCTION      = 2,
};

enum lttng_kernel_context_type {
	LTTNG_KERNEL_CONTEXT_PID            = 0,
	LTTNG_KERNEL_CONTEXT_PERF_COUNTER   = 1,
	LTTNG_KERNEL_CONTEXT_COMM           = 2,
	LTTNG_KERNEL_CONTEXT_PRIO           = 3,
	LTTNG_KERNEL_CONTEXT_NICE           = 4,
	LTTNG_KERNEL_CONTEXT_VPID           = 5,
	LTTNG_KERNEL_CONTEXT_TID            = 6,
	LTTNG_KERNEL_CONTEXT_VTID           = 7,
	LTTNG_KERNEL_CONTEXT_PPID           = 8,
	LTTNG_KERNEL_CONTEXT_VPPID          = 9,
};

/* Perf counter attributes */
struct lttng_kernel_perf_counter_ctx {
	uint32_t type;
	uint64_t config;
	char name[LTTNG_SYMBOL_NAME_LEN];
};

/* Event/Channel context */
struct lttng_kernel_context {
	enum lttng_kernel_context_type ctx;
	union {
		struct lttng_kernel_perf_counter_ctx perf_counter;
	} u;
};

/*
 * Either addr is used, or symbol_name and offset.
 */
struct lttng_kernel_kprobe {
	uint64_t addr;

	uint64_t offset;
	char symbol_name[LTTNG_SYM_NAME_LEN];
};

/* Function tracer */
struct lttng_kernel_function {
	char symbol_name[LTTNG_SYM_NAME_LEN];
};

struct lttng_kernel_event {
	char name[LTTNG_SYM_NAME_LEN];
	enum lttng_kernel_instrumentation instrumentation;
	/* Per instrumentation type configuration */
	union {
		struct lttng_kernel_kprobe kprobe;
		struct lttng_kernel_function ftrace;
	} u;
};

struct lttng_kernel_tracer_version {
	uint32_t version;
	uint32_t patchlevel;
	uint32_t sublevel;
};

#endif /* _LTTNG_KERNEL_H */
