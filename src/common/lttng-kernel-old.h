/*
 * Copyright (C) 2011 - Julien Desfossez <julien.desfossez@polymtl.ca>
 *                      Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *                      David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _LTTNG_KERNEL_OLD_H
#define _LTTNG_KERNEL_OLD_H

#include <stdint.h>
#include <common/lttng-kernel.h>

/*
 * LTTng DebugFS ABI structures.
 *
 * This is the kernel ABI copied from lttng-modules tree.
 */

/* Perf counter attributes */
struct lttng_kernel_old_perf_counter_ctx {
	uint32_t type;
	uint64_t config;
	char name[LTTNG_KERNEL_SYM_NAME_LEN];
};

/* Event/Channel context */
#define LTTNG_KERNEL_OLD_CONTEXT_PADDING1  16
#define LTTNG_KERNEL_OLD_CONTEXT_PADDING2  LTTNG_KERNEL_SYM_NAME_LEN + 32
struct lttng_kernel_old_context {
	enum lttng_kernel_context_type ctx;
	char padding[LTTNG_KERNEL_OLD_CONTEXT_PADDING1];

	union {
		struct lttng_kernel_old_perf_counter_ctx perf_counter;
		char padding[LTTNG_KERNEL_OLD_CONTEXT_PADDING2];
	} u;
};

struct lttng_kernel_old_kretprobe {
	uint64_t addr;

	uint64_t offset;
	char symbol_name[LTTNG_KERNEL_SYM_NAME_LEN];
};

/*
 * Either addr is used, or symbol_name and offset.
 */
struct lttng_kernel_old_kprobe {
	uint64_t addr;

	uint64_t offset;
	char symbol_name[LTTNG_KERNEL_SYM_NAME_LEN];
};

/* Function tracer */
struct lttng_kernel_old_function {
	char symbol_name[LTTNG_KERNEL_SYM_NAME_LEN];
};

#define LTTNG_KERNEL_OLD_EVENT_PADDING1    16
#define LTTNG_KERNEL_OLD_EVENT_PADDING2    LTTNG_KERNEL_SYM_NAME_LEN + 32
struct lttng_kernel_old_event {
	char name[LTTNG_KERNEL_SYM_NAME_LEN];
	enum lttng_kernel_instrumentation instrumentation;
	char padding[LTTNG_KERNEL_OLD_EVENT_PADDING1];

	/* Per instrumentation type configuration */
	union {
		struct lttng_kernel_old_kretprobe kretprobe;
		struct lttng_kernel_old_kprobe kprobe;
		struct lttng_kernel_old_function ftrace;
		char padding[LTTNG_KERNEL_OLD_EVENT_PADDING2];
	} u;
};

struct lttng_kernel_old_tracer_version {
	uint32_t major;
	uint32_t minor;
	uint32_t patchlevel;
};

/*
 * kernel channel
 */
#define LTTNG_KERNEL_OLD_CHANNEL_PADDING1 LTTNG_SYMBOL_NAME_LEN + 32
struct lttng_kernel_old_channel {
	int overwrite;                      /* 1: overwrite, 0: discard */
	uint64_t subbuf_size;               /* bytes */
	uint64_t num_subbuf;                /* power of 2 */
	unsigned int switch_timer_interval; /* usec */
	unsigned int read_timer_interval;   /* usec */
	enum lttng_event_output output;     /* splice, mmap */

	char padding[LTTNG_KERNEL_OLD_CHANNEL_PADDING1];
};

#endif /* _LTTNG_KERNEL_OLD_H */
