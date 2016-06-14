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

#ifndef _LTTNG_KERNEL_H
#define _LTTNG_KERNEL_H

#include <stdint.h>
#include <common/macros.h>

#define LTTNG_KERNEL_SYM_NAME_LEN  256

/*
 * LTTng DebugFS ABI structures.
 *
 * This is the kernel ABI copied from lttng-modules tree.
 */

enum lttng_kernel_instrumentation {
	LTTNG_KERNEL_ALL           = -1,   /* Used within lttng-tools */
	LTTNG_KERNEL_TRACEPOINT    = 0,
	LTTNG_KERNEL_KPROBE        = 1,
	LTTNG_KERNEL_FUNCTION      = 2,
	LTTNG_KERNEL_KRETPROBE     = 3,
	LTTNG_KERNEL_NOOP          = 4,    /* not hooked */
	LTTNG_KERNEL_SYSCALL       = 5,
};

enum lttng_kernel_context_type {
	LTTNG_KERNEL_CONTEXT_PID            = 0,
	LTTNG_KERNEL_CONTEXT_PERF_CPU_COUNTER = 1,
	LTTNG_KERNEL_CONTEXT_PROCNAME       = 2,
	LTTNG_KERNEL_CONTEXT_PRIO           = 3,
	LTTNG_KERNEL_CONTEXT_NICE           = 4,
	LTTNG_KERNEL_CONTEXT_VPID           = 5,
	LTTNG_KERNEL_CONTEXT_TID            = 6,
	LTTNG_KERNEL_CONTEXT_VTID           = 7,
	LTTNG_KERNEL_CONTEXT_PPID           = 8,
	LTTNG_KERNEL_CONTEXT_VPPID          = 9,
	LTTNG_KERNEL_CONTEXT_HOSTNAME       = 10,
	LTTNG_KERNEL_CONTEXT_CPU_ID         = 11,
	LTTNG_KERNEL_CONTEXT_INTERRUPTIBLE  = 12,
	LTTNG_KERNEL_CONTEXT_PREEMPTIBLE    = 13,
	LTTNG_KERNEL_CONTEXT_NEED_RESCHEDULE = 14,
	LTTNG_KERNEL_CONTEXT_MIGRATABLE     = 15,
};

/* Perf counter attributes */
struct lttng_kernel_perf_counter_ctx {
	uint32_t type;
	uint64_t config;
	char name[LTTNG_KERNEL_SYM_NAME_LEN];
} LTTNG_PACKED;

/* Event/Channel context */
#define LTTNG_KERNEL_CONTEXT_PADDING1  16
#define LTTNG_KERNEL_CONTEXT_PADDING2  LTTNG_KERNEL_SYM_NAME_LEN + 32
struct lttng_kernel_context {
	enum lttng_kernel_context_type ctx;
	char padding[LTTNG_KERNEL_CONTEXT_PADDING1];

	union {
		struct lttng_kernel_perf_counter_ctx perf_counter;
		char padding[LTTNG_KERNEL_CONTEXT_PADDING2];
	} u;
} LTTNG_PACKED;

struct lttng_kernel_kretprobe {
	uint64_t addr;

	uint64_t offset;
	char symbol_name[LTTNG_KERNEL_SYM_NAME_LEN];
} LTTNG_PACKED;

/*
 * Either addr is used, or symbol_name and offset.
 */
struct lttng_kernel_kprobe {
	uint64_t addr;

	uint64_t offset;
	char symbol_name[LTTNG_KERNEL_SYM_NAME_LEN];
} LTTNG_PACKED;

/* Function tracer */
struct lttng_kernel_function {
	char symbol_name[LTTNG_KERNEL_SYM_NAME_LEN];
} LTTNG_PACKED;

#define LTTNG_KERNEL_EVENT_PADDING1    16
#define LTTNG_KERNEL_EVENT_PADDING2    LTTNG_KERNEL_SYM_NAME_LEN + 32
struct lttng_kernel_event {
	char name[LTTNG_KERNEL_SYM_NAME_LEN];
	enum lttng_kernel_instrumentation instrumentation;
	char padding[LTTNG_KERNEL_EVENT_PADDING1];

	/* Per instrumentation type configuration */
	union {
		struct lttng_kernel_kretprobe kretprobe;
		struct lttng_kernel_kprobe kprobe;
		struct lttng_kernel_function ftrace;
		char padding[LTTNG_KERNEL_EVENT_PADDING2];
	} u;
} LTTNG_PACKED;

struct lttng_kernel_tracer_version {
	uint32_t major;
	uint32_t minor;
	uint32_t patchlevel;
} LTTNG_PACKED;

struct lttng_kernel_tracer_abi_version {
	uint32_t major;
	uint32_t minor;
} LTTNG_PACKED;

struct lttng_kernel_syscall_mask {
	uint32_t len;	/* in bits */
	char mask[];
} LTTNG_PACKED;

/*
 * kernel channel
 */
#define LTTNG_KERNEL_CHANNEL_PADDING1 LTTNG_SYMBOL_NAME_LEN + 32
struct lttng_kernel_channel {
	uint64_t subbuf_size;               /* bytes */
	uint64_t num_subbuf;                /* power of 2 */
	unsigned int switch_timer_interval; /* usec */
	unsigned int read_timer_interval;   /* usec */
	enum lttng_event_output output;     /* splice, mmap */

	int overwrite;                      /* 1: overwrite, 0: discard */
	char padding[LTTNG_KERNEL_CHANNEL_PADDING1];
} LTTNG_PACKED;

#define KERNEL_FILTER_BYTECODE_MAX_LEN		65536
struct lttng_kernel_filter_bytecode {
	uint32_t len;
	uint32_t reloc_offset;
	uint64_t seqnum;
	char data[0];
} LTTNG_PACKED;

#endif /* _LTTNG_KERNEL_H */
