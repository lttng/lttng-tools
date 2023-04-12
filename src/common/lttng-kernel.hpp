/*
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright (C) 2011 EfficiOS Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef _LTTNG_KERNEL_H
#define _LTTNG_KERNEL_H

#include <common/compiler.hpp>
#include <common/macros.hpp>

#include <lttng/constant.h>
#include <lttng/event.h>

#include <stdint.h>

#define LTTNG_KERNEL_ABI_SYM_NAME_LEN			   256
#define LTTNG_KERNEL_ABI_MAX_UPROBE_NUM			   32
#define LTTNG_KERNEL_ABI_SESSION_NAME_LEN		   256
#define LTTNG_KERNEL_ABI_SESSION_CREATION_TIME_ISO8601_LEN 26

/*
 * LTTng DebugFS ABI structures.
 *
 * This is the kernel ABI copied from lttng-modules tree.
 */

enum lttng_kernel_abi_instrumentation {
	LTTNG_KERNEL_ABI_ALL = -1, /* Used within lttng-tools */
	LTTNG_KERNEL_ABI_TRACEPOINT = 0,
	LTTNG_KERNEL_ABI_KPROBE = 1,
	LTTNG_KERNEL_ABI_FUNCTION = 2,
	LTTNG_KERNEL_ABI_KRETPROBE = 3,
	LTTNG_KERNEL_ABI_NOOP = 4, /* not hooked */
	LTTNG_KERNEL_ABI_SYSCALL = 5,
	LTTNG_KERNEL_ABI_UPROBE = 6,
};

enum lttng_kernel_abi_context_type {
	LTTNG_KERNEL_ABI_CONTEXT_PID = 0,
	LTTNG_KERNEL_ABI_CONTEXT_PERF_CPU_COUNTER = 1,
	LTTNG_KERNEL_ABI_CONTEXT_PROCNAME = 2,
	LTTNG_KERNEL_ABI_CONTEXT_PRIO = 3,
	LTTNG_KERNEL_ABI_CONTEXT_NICE = 4,
	LTTNG_KERNEL_ABI_CONTEXT_VPID = 5,
	LTTNG_KERNEL_ABI_CONTEXT_TID = 6,
	LTTNG_KERNEL_ABI_CONTEXT_VTID = 7,
	LTTNG_KERNEL_ABI_CONTEXT_PPID = 8,
	LTTNG_KERNEL_ABI_CONTEXT_VPPID = 9,
	LTTNG_KERNEL_ABI_CONTEXT_HOSTNAME = 10,
	LTTNG_KERNEL_ABI_CONTEXT_CPU_ID = 11,
	LTTNG_KERNEL_ABI_CONTEXT_INTERRUPTIBLE = 12,
	LTTNG_KERNEL_ABI_CONTEXT_PREEMPTIBLE = 13,
	LTTNG_KERNEL_ABI_CONTEXT_NEED_RESCHEDULE = 14,
	LTTNG_KERNEL_ABI_CONTEXT_MIGRATABLE = 15,
	LTTNG_KERNEL_ABI_CONTEXT_CALLSTACK_KERNEL = 16,
	LTTNG_KERNEL_ABI_CONTEXT_CALLSTACK_USER = 17,
	LTTNG_KERNEL_ABI_CONTEXT_CGROUP_NS = 18,
	LTTNG_KERNEL_ABI_CONTEXT_IPC_NS = 19,
	LTTNG_KERNEL_ABI_CONTEXT_MNT_NS = 20,
	LTTNG_KERNEL_ABI_CONTEXT_NET_NS = 21,
	LTTNG_KERNEL_ABI_CONTEXT_PID_NS = 22,
	LTTNG_KERNEL_ABI_CONTEXT_USER_NS = 23,
	LTTNG_KERNEL_ABI_CONTEXT_UTS_NS = 24,
	LTTNG_KERNEL_ABI_CONTEXT_UID = 25,
	LTTNG_KERNEL_ABI_CONTEXT_EUID = 26,
	LTTNG_KERNEL_ABI_CONTEXT_SUID = 27,
	LTTNG_KERNEL_ABI_CONTEXT_GID = 28,
	LTTNG_KERNEL_ABI_CONTEXT_EGID = 29,
	LTTNG_KERNEL_ABI_CONTEXT_SGID = 30,
	LTTNG_KERNEL_ABI_CONTEXT_VUID = 31,
	LTTNG_KERNEL_ABI_CONTEXT_VEUID = 32,
	LTTNG_KERNEL_ABI_CONTEXT_VSUID = 33,
	LTTNG_KERNEL_ABI_CONTEXT_VGID = 34,
	LTTNG_KERNEL_ABI_CONTEXT_VEGID = 35,
	LTTNG_KERNEL_ABI_CONTEXT_VSGID = 36,
	LTTNG_KERNEL_ABI_CONTEXT_TIME_NS = 37,
};

/* Perf counter attributes */
struct lttng_kernel_abi_perf_counter_ctx {
	uint32_t type;
	uint64_t config;
	char name[LTTNG_KERNEL_ABI_SYM_NAME_LEN];
} LTTNG_PACKED;

/* Event/Channel context */
#define LTTNG_KERNEL_ABI_CONTEXT_PADDING1 16
#define LTTNG_KERNEL_ABI_CONTEXT_PADDING2 ((LTTNG_KERNEL_ABI_SYM_NAME_LEN + 32))
struct lttng_kernel_abi_context {
	enum lttng_kernel_abi_context_type ctx;
	char padding[LTTNG_KERNEL_ABI_CONTEXT_PADDING1];

	union {
		struct lttng_kernel_abi_perf_counter_ctx perf_counter;
		char padding[LTTNG_KERNEL_ABI_CONTEXT_PADDING2];
	} u;
} LTTNG_PACKED;

struct lttng_kernel_abi_kretprobe {
	uint64_t addr;

	uint64_t offset;
	char symbol_name[LTTNG_KERNEL_ABI_SYM_NAME_LEN];
} LTTNG_PACKED;

/*
 * Either addr is used, or symbol_name and offset.
 */
struct lttng_kernel_abi_kprobe {
	uint64_t addr;

	uint64_t offset;
	char symbol_name[LTTNG_KERNEL_ABI_SYM_NAME_LEN];
} LTTNG_PACKED;

struct lttng_kernel_abi_uprobe {
	int fd;
} LTTNG_PACKED;

struct lttng_kernel_abi_event_callsite_uprobe {
	uint64_t offset;
} LTTNG_PACKED;

struct lttng_kernel_abi_event_callsite {
	union {
		struct lttng_kernel_abi_event_callsite_uprobe uprobe;
	} u;
} LTTNG_PACKED;

enum lttng_kernel_abi_syscall_entryexit {
	LTTNG_KERNEL_ABI_SYSCALL_ENTRYEXIT = 0,
	LTTNG_KERNEL_ABI_SYSCALL_ENTRY = 1,
	LTTNG_KERNEL_ABI_SYSCALL_EXIT = 2,
};

enum lttng_kernel_abi_syscall_abi {
	LTTNG_KERNEL_ABI_SYSCALL_ABI_ALL = 0,
	LTTNG_KERNEL_ABI_SYSCALL_ABI_NATIVE = 1,
	LTTNG_KERNEL_ABI_SYSCALL_ABI_COMPAT = 2,
};

enum lttng_kernel_abi_syscall_match {
	LTTNG_KERNEL_ABI_SYSCALL_MATCH_NAME = 0,
	LTTNG_KERNEL_ABI_SYSCALL_MATCH_NR = 1,
};

struct lttng_kernel_abi_syscall {
	uint8_t entryexit; /* enum lttng_kernel_abi_syscall_entryexit */
	uint8_t abi; /* enum lttng_kernel_abi_syscall_abi */
	uint8_t match; /* enum lttng_kernel_abi_syscall_match */
	uint8_t padding;
	uint32_t nr; /* For LTTNG_SYSCALL_MATCH_NR */
} LTTNG_PACKED;

/* Function tracer */
struct lttng_kernel_abi_function {
	char symbol_name[LTTNG_KERNEL_ABI_SYM_NAME_LEN];
} LTTNG_PACKED;

#define LTTNG_KERNEL_ABI_EVENT_PADDING1 8
#define LTTNG_KERNEL_ABI_EVENT_PADDING2 ((LTTNG_KERNEL_ABI_SYM_NAME_LEN + 32))
struct lttng_kernel_abi_event {
	char name[LTTNG_KERNEL_ABI_SYM_NAME_LEN];
	enum lttng_kernel_abi_instrumentation instrumentation;
	uint64_t token;
	char padding[LTTNG_KERNEL_ABI_EVENT_PADDING1];

	/* Per instrumentation type configuration */
	union {
		struct lttng_kernel_abi_kretprobe kretprobe;
		struct lttng_kernel_abi_kprobe kprobe;
		struct lttng_kernel_abi_function ftrace;
		struct lttng_kernel_abi_uprobe uprobe;
		struct lttng_kernel_abi_syscall syscall;
		char padding[LTTNG_KERNEL_ABI_EVENT_PADDING2];
	} u;
} LTTNG_PACKED;

#define LTTNG_KERNEL_ABI_EVENT_NOTIFIER_PADDING 32
struct lttng_kernel_abi_event_notifier {
	struct lttng_kernel_abi_event event;
	uint64_t error_counter_idx;

	char padding[LTTNG_KERNEL_ABI_EVENT_NOTIFIER_PADDING];
} LTTNG_PACKED;

#define LTTNG_KERNEL_ABI_COUNTER_DIMENSION_MAX 4

enum lttng_kernel_abi_counter_arithmetic {
	LTTNG_KERNEL_ABI_COUNTER_ARITHMETIC_MODULAR = 0,
};

enum lttng_kernel_abi_counter_bitness {
	LTTNG_KERNEL_ABI_COUNTER_BITNESS_32 = 0,
	LTTNG_KERNEL_ABI_COUNTER_BITNESS_64 = 1,
};

struct lttng_kernel_abi_counter_dimension {
	uint64_t size;
	uint64_t underflow_index;
	uint64_t overflow_index;
	uint8_t has_underflow;
	uint8_t has_overflow;
} LTTNG_PACKED;

#define LTTNG_KERNEL_ABI_COUNTER_CONF_PADDING1 67
struct lttng_kernel_abi_counter_conf {
	uint32_t arithmetic; /* enum lttng_kernel_abi_counter_arithmetic */
	uint32_t bitness; /* enum lttng_kernel_abi_counter_bitness */
	uint32_t number_dimensions;
	int64_t global_sum_step;
	struct lttng_kernel_abi_counter_dimension dimensions[LTTNG_KERNEL_ABI_COUNTER_DIMENSION_MAX];
	uint8_t coalesce_hits;
	char padding[LTTNG_KERNEL_ABI_COUNTER_CONF_PADDING1];
} LTTNG_PACKED;

struct lttng_kernel_abi_counter_index {
	uint32_t number_dimensions;
	uint64_t dimension_indexes[LTTNG_KERNEL_ABI_COUNTER_DIMENSION_MAX];
} LTTNG_PACKED;

struct lttng_kernel_abi_counter_value {
	int64_t value;
	uint8_t underflow;
	uint8_t overflow;
} LTTNG_PACKED;

#define LTTNG_KERNEL_ABI_COUNTER_READ_PADDING 32
struct lttng_kernel_abi_counter_read {
	struct lttng_kernel_abi_counter_index index;
	int32_t cpu; /* -1 for global counter, >= 0 for specific cpu. */
	struct lttng_kernel_abi_counter_value value; /* output */
	char padding[LTTNG_KERNEL_ABI_COUNTER_READ_PADDING];
} LTTNG_PACKED;

#define LTTNG_KERNEL_ABI_COUNTER_AGGREGATE_PADDING 32
struct lttng_kernel_abi_counter_aggregate {
	struct lttng_kernel_abi_counter_index index;
	struct lttng_kernel_abi_counter_value value; /* output */
	char padding[LTTNG_KERNEL_ABI_COUNTER_AGGREGATE_PADDING];
} LTTNG_PACKED;

#define LTTNG_KERNEL_ABI_COUNTER_CLEAR_PADDING 32
struct lttng_kernel_abi_counter_clear {
	struct lttng_kernel_abi_counter_index index;
	char padding[LTTNG_KERNEL_ABI_COUNTER_CLEAR_PADDING];
} LTTNG_PACKED;

#define LTTNG_KERNEL_ABI_EVENT_NOTIFIER_NOTIFICATION_PADDING 32
struct lttng_kernel_abi_event_notifier_notification {
	uint64_t token;
	uint16_t capture_buf_size;
	char padding[LTTNG_KERNEL_ABI_EVENT_NOTIFIER_NOTIFICATION_PADDING];
} LTTNG_PACKED;

#define LTTNG_KERNEL_ABI_CAPTURE_BYTECODE_MAX_LEN 65536
struct lttng_kernel_abi_capture_bytecode {
	uint32_t len;
	uint32_t reloc_offset;
	uint64_t seqnum;
	char data[0];
} LTTNG_PACKED;

struct lttng_kernel_abi_tracer_version {
	uint32_t major;
	uint32_t minor;
	uint32_t patchlevel;
} LTTNG_PACKED;

struct lttng_kernel_abi_tracer_abi_version {
	uint32_t major;
	uint32_t minor;
} LTTNG_PACKED;

struct lttng_kernel_abi_syscall_mask {
	uint32_t len; /* in bits */
	char mask[LTTNG_FLEXIBLE_ARRAY_MEMBER_LENGTH];
} LTTNG_PACKED;

/*
 * kernel channel
 */
#define LTTNG_KERNEL_ABI_CHANNEL_PADDING1 ((LTTNG_SYMBOL_NAME_LEN + 32))
struct lttng_kernel_abi_channel {
	uint64_t subbuf_size; /* bytes */
	uint64_t num_subbuf; /* power of 2 */
	unsigned int switch_timer_interval; /* usec */
	unsigned int read_timer_interval; /* usec */
	enum lttng_event_output output; /* splice, mmap */

	int overwrite; /* 1: overwrite, 0: discard */
	char padding[LTTNG_KERNEL_ABI_CHANNEL_PADDING1];
} LTTNG_PACKED;

#define KERNEL_FILTER_BYTECODE_MAX_LEN 65536
struct lttng_kernel_abi_filter_bytecode {
	uint32_t len;
	uint32_t reloc_offset;
	uint64_t seqnum;
	char data[0];
} LTTNG_PACKED;

/*
 * kernel session name
 */
struct lttng_kernel_abi_session_name {
	char name[LTTNG_KERNEL_ABI_SESSION_NAME_LEN];
} LTTNG_PACKED;

/*
 * kernel session creation datetime
 */
struct lttng_kernel_abi_session_creation_time {
	char iso8601[LTTNG_KERNEL_ABI_SESSION_CREATION_TIME_ISO8601_LEN];
} LTTNG_PACKED;

enum lttng_kernel_abi_tracker_type {
	LTTNG_KERNEL_ABI_TRACKER_UNKNOWN = -1,

	LTTNG_KERNEL_ABI_TRACKER_PID = 0,
	LTTNG_KERNEL_ABI_TRACKER_VPID = 1,
	LTTNG_KERNEL_ABI_TRACKER_UID = 2,
	LTTNG_KERNEL_ABI_TRACKER_VUID = 3,
	LTTNG_KERNEL_ABI_TRACKER_GID = 4,
	LTTNG_KERNEL_ABI_TRACKER_VGID = 5,
};

struct lttng_kernel_abi_tracker_args {
	enum lttng_kernel_abi_tracker_type type;
	int32_t id;
};

#endif /* _LTTNG_KERNEL_H */
