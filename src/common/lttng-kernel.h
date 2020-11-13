/*
 * Copyright (C) 2011 Julien Desfossez <julien.desfossez@polymtl.ca>
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright (C) 2011 David Goulet <david.goulet@polymtl.ca>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef _LTTNG_KERNEL_H
#define _LTTNG_KERNEL_H

#include <stdint.h>
#include <common/macros.h>
#include <lttng/constant.h>
#include <lttng/event.h>

#define LTTNG_KERNEL_SYM_NAME_LEN  256
#define LTTNG_KERNEL_MAX_UPROBE_NUM  32
#define LTTNG_KERNEL_SESSION_NAME_LEN	256
#define LTTNG_KERNEL_SESSION_CREATION_TIME_ISO8601_LEN	26

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
	LTTNG_KERNEL_UPROBE        = 6,
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
	LTTNG_KERNEL_CONTEXT_CALLSTACK_KERNEL = 16,
	LTTNG_KERNEL_CONTEXT_CALLSTACK_USER   = 17,
	LTTNG_KERNEL_CONTEXT_CGROUP_NS      = 18,
	LTTNG_KERNEL_CONTEXT_IPC_NS         = 19,
	LTTNG_KERNEL_CONTEXT_MNT_NS         = 20,
	LTTNG_KERNEL_CONTEXT_NET_NS         = 21,
	LTTNG_KERNEL_CONTEXT_PID_NS         = 22,
	LTTNG_KERNEL_CONTEXT_USER_NS        = 23,
	LTTNG_KERNEL_CONTEXT_UTS_NS         = 24,
	LTTNG_KERNEL_CONTEXT_UID            = 25,
	LTTNG_KERNEL_CONTEXT_EUID           = 26,
	LTTNG_KERNEL_CONTEXT_SUID           = 27,
	LTTNG_KERNEL_CONTEXT_GID            = 28,
	LTTNG_KERNEL_CONTEXT_EGID           = 29,
	LTTNG_KERNEL_CONTEXT_SGID           = 30,
	LTTNG_KERNEL_CONTEXT_VUID           = 31,
	LTTNG_KERNEL_CONTEXT_VEUID          = 32,
	LTTNG_KERNEL_CONTEXT_VSUID          = 33,
	LTTNG_KERNEL_CONTEXT_VGID           = 34,
	LTTNG_KERNEL_CONTEXT_VEGID          = 35,
	LTTNG_KERNEL_CONTEXT_VSGID          = 36,
	LTTNG_KERNEL_CONTEXT_TIME_NS        = 37,
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

struct lttng_kernel_uprobe {
	int fd;
} LTTNG_PACKED;

struct lttng_kernel_event_callsite_uprobe {
	uint64_t offset;
} LTTNG_PACKED;

struct lttng_kernel_event_callsite {
	union {
		struct lttng_kernel_event_callsite_uprobe uprobe;
	} u;
} LTTNG_PACKED;

enum lttng_kernel_syscall_entryexit {
	LTTNG_KERNEL_SYSCALL_ENTRYEXIT	= 0,
	LTTNG_KERNEL_SYSCALL_ENTRY	= 1,
	LTTNG_KERNEL_SYSCALL_EXIT	= 2,
};

enum lttng_kernel_syscall_abi {
	LTTNG_KERNEL_SYSCALL_ABI_ALL	= 0,
	LTTNG_KERNEL_SYSCALL_ABI_NATIVE = 1,
	LTTNG_KERNEL_SYSCALL_ABI_COMPAT = 2,
};

enum lttng_kernel_syscall_match {
	LTTNG_KERNEL_SYSCALL_MATCH_NAME = 0,
	LTTNG_KERNEL_SYSCALL_MATCH_NR	= 1,
};

struct lttng_kernel_syscall {
	uint8_t entryexit;	/* enum lttng_kernel_syscall_entryexit */
	uint8_t abi;		/* enum lttng_kernel_syscall_abi */
	uint8_t match;		/* enum lttng_kernel_syscall_match */
	uint8_t padding;
	uint32_t nr;		/* For LTTNG_SYSCALL_MATCH_NR */
} LTTNG_PACKED;

/* Function tracer */
struct lttng_kernel_function {
	char symbol_name[LTTNG_KERNEL_SYM_NAME_LEN];
} LTTNG_PACKED;

#define LTTNG_KERNEL_EVENT_PADDING1    8
#define LTTNG_KERNEL_EVENT_PADDING2    LTTNG_KERNEL_SYM_NAME_LEN + 32
struct lttng_kernel_event {
	char name[LTTNG_KERNEL_SYM_NAME_LEN];
	enum lttng_kernel_instrumentation instrumentation;
	uint64_t token;
	char padding[LTTNG_KERNEL_EVENT_PADDING1];

	/* Per instrumentation type configuration */
	union {
		struct lttng_kernel_kretprobe kretprobe;
		struct lttng_kernel_kprobe kprobe;
		struct lttng_kernel_function ftrace;
		struct lttng_kernel_uprobe uprobe;
		struct lttng_kernel_syscall syscall;
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

/*
 * kernel session name
 */
struct lttng_kernel_session_name {
	char name[LTTNG_KERNEL_SESSION_NAME_LEN];
} LTTNG_PACKED;

/*
 * kernel session creation datetime
 */
struct lttng_kernel_session_creation_time {
	char iso8601[LTTNG_KERNEL_SESSION_CREATION_TIME_ISO8601_LEN];
} LTTNG_PACKED;

enum lttng_kernel_tracker_type {
	LTTNG_KERNEL_TRACKER_UNKNOWN		= -1,

	LTTNG_KERNEL_TRACKER_PID		= 0,
	LTTNG_KERNEL_TRACKER_VPID		= 1,
	LTTNG_KERNEL_TRACKER_UID		= 2,
	LTTNG_KERNEL_TRACKER_VUID		= 3,
	LTTNG_KERNEL_TRACKER_GID		= 4,
	LTTNG_KERNEL_TRACKER_VGID		= 5,
};

struct lttng_kernel_tracker_args {
	enum lttng_kernel_tracker_type type;
	int32_t id;
};

#endif /* _LTTNG_KERNEL_H */
