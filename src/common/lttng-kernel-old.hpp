/*
 * SPDX-FileCopyrightText: 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef _LTTNG_KERNEL_OLD_H
#define _LTTNG_KERNEL_OLD_H

#include <common/lttng-kernel.hpp>

#include <stdint.h>

/*
 * LTTng DebugFS ABI structures.
 *
 * This is the kernel ABI copied from lttng-modules tree.
 */

/* Perf counter attributes */
struct lttng_kernel_abi_old_perf_counter_ctx {
	uint32_t type;
	uint64_t config;
	char name[LTTNG_KERNEL_ABI_SYM_NAME_LEN];
};

/* Event/Channel context */
#define LTTNG_KERNEL_ABI_OLD_CONTEXT_PADDING1 16
#define LTTNG_KERNEL_ABI_OLD_CONTEXT_PADDING2 ((LTTNG_KERNEL_ABI_SYM_NAME_LEN + 32))
struct lttng_kernel_abi_old_context {
	enum lttng_kernel_abi_context_type ctx;
	char padding[LTTNG_KERNEL_ABI_OLD_CONTEXT_PADDING1];

	union {
		struct lttng_kernel_abi_old_perf_counter_ctx perf_counter;
		char padding[LTTNG_KERNEL_ABI_OLD_CONTEXT_PADDING2];
	} u;
};

struct lttng_kernel_abi_old_kretprobe {
	uint64_t addr;

	uint64_t offset;
	char symbol_name[LTTNG_KERNEL_ABI_SYM_NAME_LEN];
};

/*
 * Either addr is used, or symbol_name and offset.
 */
struct lttng_kernel_abi_old_kprobe {
	uint64_t addr;

	uint64_t offset;
	char symbol_name[LTTNG_KERNEL_ABI_SYM_NAME_LEN];
};

/* Function tracer */
struct lttng_kernel_abi_old_function {
	char symbol_name[LTTNG_KERNEL_ABI_SYM_NAME_LEN];
};

#define LTTNG_KERNEL_ABI_OLD_EVENT_PADDING1 16
#define LTTNG_KERNEL_ABI_OLD_EVENT_PADDING2 ((LTTNG_KERNEL_ABI_SYM_NAME_LEN + 32))
struct lttng_kernel_abi_old_event {
	char name[LTTNG_KERNEL_ABI_SYM_NAME_LEN];
	enum lttng_kernel_abi_instrumentation instrumentation;
	char padding[LTTNG_KERNEL_ABI_OLD_EVENT_PADDING1];

	/* Per instrumentation type configuration */
	union {
		struct lttng_kernel_abi_old_kretprobe kretprobe;
		struct lttng_kernel_abi_old_kprobe kprobe;
		struct lttng_kernel_abi_old_function ftrace;
		char padding[LTTNG_KERNEL_ABI_OLD_EVENT_PADDING2];
	} u;
};

struct lttng_kernel_abi_old_tracer_version {
	uint32_t major;
	uint32_t minor;
	uint32_t patchlevel;
};

/*
 * kernel channel
 */
#define LTTNG_KERNEL_ABI_OLD_CHANNEL_PADDING1 ((LTTNG_SYMBOL_NAME_LEN + 32))
struct lttng_kernel_abi_old_channel {
	int overwrite; /* 1: overwrite, 0: discard */
	uint64_t subbuf_size; /* bytes */
	uint64_t num_subbuf; /* power of 2 */
	unsigned int switch_timer_interval; /* usec */
	unsigned int read_timer_interval; /* usec */
	enum lttng_event_output output; /* splice, mmap */

	char padding[LTTNG_KERNEL_ABI_OLD_CHANNEL_PADDING1];
};

/* Old (pre-2.14 lttng-modules) counter ABI. */
#define LTTNG_KERNEL_ABI_OLD_COUNTER_DIMENSION_MAX 4

struct lttng_kernel_abi_old_counter_dimension {
	uint64_t size;
	uint64_t underflow_index;
	uint64_t overflow_index;
	uint8_t has_underflow;
	uint8_t has_overflow;
} LTTNG_PACKED;

#define LTTNG_KERNEL_ABI_OLD_COUNTER_CONF_PADDING1 67
struct lttng_kernel_abi_old_counter_conf {
	uint32_t arithmetic; /* enum lttng_kernel_abi_counter_arithmetic */
	uint32_t bitness; /* enum lttng_kernel_abi_counter_bitness */
	uint32_t number_dimensions;
	int64_t global_sum_step;
	struct lttng_kernel_abi_old_counter_dimension
		dimensions[LTTNG_KERNEL_ABI_OLD_COUNTER_DIMENSION_MAX];
	uint8_t coalesce_hits;
	char padding[LTTNG_KERNEL_ABI_OLD_COUNTER_CONF_PADDING1];
} LTTNG_PACKED;

struct lttng_kernel_abi_old_counter_index {
	uint32_t number_dimensions;
	uint64_t dimension_indexes[LTTNG_KERNEL_ABI_OLD_COUNTER_DIMENSION_MAX];
} LTTNG_PACKED;

struct lttng_kernel_abi_old_counter_value {
	int64_t value;
	uint8_t underflow;
	uint8_t overflow;
} LTTNG_PACKED;

#define LTTNG_KERNEL_ABI_OLD_COUNTER_READ_PADDING 32
struct lttng_kernel_abi_old_counter_read {
	struct lttng_kernel_abi_old_counter_index index;
	int32_t cpu; /* -1 for global counter, >= 0 for specific cpu. */
	struct lttng_kernel_abi_old_counter_value value; /* output */
	char padding[LTTNG_KERNEL_ABI_OLD_COUNTER_READ_PADDING];
} LTTNG_PACKED;

#define LTTNG_KERNEL_ABI_OLD_COUNTER_AGGREGATE_PADDING 32
struct lttng_kernel_abi_old_counter_aggregate {
	struct lttng_kernel_abi_old_counter_index index;
	struct lttng_kernel_abi_old_counter_value value; /* output */
	char padding[LTTNG_KERNEL_ABI_OLD_COUNTER_AGGREGATE_PADDING];
} LTTNG_PACKED;

#define LTTNG_KERNEL_ABI_OLD_COUNTER_CLEAR_PADDING 32
struct lttng_kernel_abi_old_counter_clear {
	struct lttng_kernel_abi_old_counter_index index;
	char padding[LTTNG_KERNEL_ABI_OLD_COUNTER_CLEAR_PADDING];
} LTTNG_PACKED;

#endif /* _LTTNG_KERNEL_OLD_H */
