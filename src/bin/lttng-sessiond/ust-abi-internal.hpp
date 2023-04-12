/*
 * Copyright 2010-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 *
 * Copied from LTTng-UST lttng/ust-abi.h
 *
 * LTTng-UST ABI header
 *
 */

#ifndef LTTNG_UST_ABI_INTERNAL_H
#define LTTNG_UST_ABI_INTERNAL_H

#include <common/macros.hpp>

#include <stdint.h>

#ifndef LTTNG_PACKED
#error "LTTNG_PACKED should be defined"
#endif

#ifndef __ust_stringify
#define __ust_stringify1(x) #x
#define __ust_stringify(x)  __ust_stringify1(x)
#endif /* __ust_stringify */

#define LTTNG_UST_ABI_SYM_NAME_LEN 256
#define LTTNG_UST_ABI_PROCNAME_LEN 16

/* UST comm magic number, used to validate protocol and endianness. */
#define LTTNG_UST_ABI_COMM_MAGIC 0xC57C57C5

/* Version for ABI between liblttng-ust, sessiond, consumerd */
#define LTTNG_UST_ABI_MAJOR_VERSION		      9
#define LTTNG_UST_ABI_MAJOR_VERSION_OLDEST_COMPATIBLE 8
#define LTTNG_UST_ABI_MINOR_VERSION		      0

enum lttng_ust_abi_instrumentation {
	LTTNG_UST_ABI_TRACEPOINT = 0,
	LTTNG_UST_ABI_PROBE = 1,
	LTTNG_UST_ABI_FUNCTION = 2,
};

enum lttng_ust_abi_loglevel_type {
	LTTNG_UST_ABI_LOGLEVEL_ALL = 0,
	LTTNG_UST_ABI_LOGLEVEL_RANGE = 1,
	LTTNG_UST_ABI_LOGLEVEL_SINGLE = 2,
};

enum lttng_ust_abi_output {
	LTTNG_UST_ABI_MMAP = 0,
};

enum lttng_ust_abi_chan_type {
	LTTNG_UST_ABI_CHAN_PER_CPU = 0,
	LTTNG_UST_ABI_CHAN_METADATA = 1,
};

struct lttng_ust_abi_tracer_version {
	uint32_t major;
	uint32_t minor;
	uint32_t patchlevel;
} LTTNG_PACKED;

#define LTTNG_UST_ABI_CHANNEL_PADDING (LTTNG_UST_ABI_SYM_NAME_LEN + 32)
/*
 * Given that the consumerd is limited to 64k file descriptors, we
 * cannot expect much more than 1MB channel structure size. This size is
 * depends on the number of streams within a channel, which depends on
 * the number of possible CPUs on the system.
 */
#define LTTNG_UST_ABI_CHANNEL_DATA_MAX_LEN 1048576U
struct lttng_ust_abi_channel {
	uint64_t len;
	int32_t type; /* enum lttng_ust_abi_chan_type */
	char padding[LTTNG_UST_ABI_CHANNEL_PADDING];
	char data[]; /* variable sized data */
} LTTNG_PACKED;

#define LTTNG_UST_ABI_STREAM_PADDING1 (LTTNG_UST_ABI_SYM_NAME_LEN + 32)
struct lttng_ust_abi_stream {
	uint64_t len; /* shm len */
	uint32_t stream_nr; /* stream number */
	char padding[LTTNG_UST_ABI_STREAM_PADDING1];
	/*
	 * shm_fd and wakeup_fd are send over unix socket as file
	 * descriptors after this structure.
	 */
} LTTNG_PACKED;

#define LTTNG_UST_ABI_COUNTER_DIMENSION_MAX 4

enum lttng_ust_abi_counter_arithmetic {
	LTTNG_UST_ABI_COUNTER_ARITHMETIC_MODULAR = 0,
	LTTNG_UST_ABI_COUNTER_ARITHMETIC_SATURATION = 1,
};

enum lttng_ust_abi_counter_bitness {
	LTTNG_UST_ABI_COUNTER_BITNESS_32 = 0,
	LTTNG_UST_ABI_COUNTER_BITNESS_64 = 1,
};

struct lttng_ust_abi_counter_dimension {
	uint64_t size;
	uint64_t underflow_index;
	uint64_t overflow_index;
	uint8_t has_underflow;
	uint8_t has_overflow;
} LTTNG_PACKED;

#define LTTNG_UST_ABI_COUNTER_CONF_PADDING1 67
struct lttng_ust_abi_counter_conf {
	uint32_t arithmetic; /* enum lttng_ust_abi_counter_arithmetic */
	uint32_t bitness; /* enum lttng_ust_abi_counter_bitness */
	uint32_t number_dimensions;
	int64_t global_sum_step;
	struct lttng_ust_abi_counter_dimension dimensions[LTTNG_UST_ABI_COUNTER_DIMENSION_MAX];
	uint8_t coalesce_hits;
	char padding[LTTNG_UST_ABI_COUNTER_CONF_PADDING1];
} LTTNG_PACKED;

struct lttng_ust_abi_counter_value {
	uint32_t number_dimensions;
	uint64_t dimension_indexes[LTTNG_UST_ABI_COUNTER_DIMENSION_MAX];
	int64_t value;
} LTTNG_PACKED;

#define LTTNG_UST_ABI_EVENT_PADDING1 8
#define LTTNG_UST_ABI_EVENT_PADDING2 (LTTNG_UST_ABI_SYM_NAME_LEN + 32)
struct lttng_ust_abi_event {
	int32_t instrumentation; /* enum lttng_ust_abi_instrumentation */
	char name[LTTNG_UST_ABI_SYM_NAME_LEN]; /* event name */

	int32_t loglevel_type; /* enum lttng_ust_abi_loglevel_type */
	int32_t loglevel; /* value, -1: all */
	uint64_t token; /* User-provided token */
	char padding[LTTNG_UST_ABI_EVENT_PADDING1];

	/* Per instrumentation type configuration */
	union {
		char padding[LTTNG_UST_ABI_EVENT_PADDING2];
	} u;
} LTTNG_PACKED;

#define LTTNG_UST_ABI_EVENT_NOTIFIER_PADDING 32
struct lttng_ust_abi_event_notifier {
	struct lttng_ust_abi_event event;
	uint64_t error_counter_index;
	char padding[LTTNG_UST_ABI_EVENT_NOTIFIER_PADDING];
} LTTNG_PACKED;

#define LTTNG_UST_ABI_EVENT_NOTIFIER_NOTIFICATION_PADDING 32
struct lttng_ust_abi_event_notifier_notification {
	uint64_t token;
	uint16_t capture_buf_size;
	char padding[LTTNG_UST_ABI_EVENT_NOTIFIER_NOTIFICATION_PADDING];
} LTTNG_PACKED;

#define LTTNG_UST_ABI_COUNTER_PADDING1	   (LTTNG_UST_ABI_SYM_NAME_LEN + 32)
#define LTTNG_UST_ABI_COUNTER_DATA_MAX_LEN 4096U
struct lttng_ust_abi_counter {
	uint64_t len;
	char padding[LTTNG_UST_ABI_COUNTER_PADDING1];
	char data[]; /* variable sized data */
} LTTNG_PACKED;

#define LTTNG_UST_ABI_COUNTER_GLOBAL_PADDING1 (LTTNG_UST_ABI_SYM_NAME_LEN + 32)
struct lttng_ust_abi_counter_global {
	uint64_t len; /* shm len */
	char padding[LTTNG_UST_ABI_COUNTER_GLOBAL_PADDING1];
} LTTNG_PACKED;

#define LTTNG_UST_ABI_COUNTER_CPU_PADDING1 (LTTNG_UST_ABI_SYM_NAME_LEN + 32)
struct lttng_ust_abi_counter_cpu {
	uint64_t len; /* shm len */
	uint32_t cpu_nr;
	char padding[LTTNG_UST_ABI_COUNTER_CPU_PADDING1];
} LTTNG_PACKED;

enum lttng_ust_abi_field_type {
	LTTNG_UST_ABI_FIELD_OTHER = 0,
	LTTNG_UST_ABI_FIELD_INTEGER = 1,
	LTTNG_UST_ABI_FIELD_ENUM = 2,
	LTTNG_UST_ABI_FIELD_FLOAT = 3,
	LTTNG_UST_ABI_FIELD_STRING = 4,
};

#define LTTNG_UST_ABI_FIELD_ITER_PADDING (LTTNG_UST_ABI_SYM_NAME_LEN + 28)
struct lttng_ust_abi_field_iter {
	char event_name[LTTNG_UST_ABI_SYM_NAME_LEN];
	char field_name[LTTNG_UST_ABI_SYM_NAME_LEN];
	int32_t type; /* enum lttng_ust_abi_field_type */
	int loglevel; /* event loglevel */
	int nowrite;
	char padding[LTTNG_UST_ABI_FIELD_ITER_PADDING];
} LTTNG_PACKED;

enum lttng_ust_abi_context_type {
	LTTNG_UST_ABI_CONTEXT_VTID = 0,
	LTTNG_UST_ABI_CONTEXT_VPID = 1,
	LTTNG_UST_ABI_CONTEXT_PTHREAD_ID = 2,
	LTTNG_UST_ABI_CONTEXT_PROCNAME = 3,
	LTTNG_UST_ABI_CONTEXT_IP = 4,
	LTTNG_UST_ABI_CONTEXT_PERF_THREAD_COUNTER = 5,
	LTTNG_UST_ABI_CONTEXT_CPU_ID = 6,
	LTTNG_UST_ABI_CONTEXT_APP_CONTEXT = 7,
	LTTNG_UST_ABI_CONTEXT_CGROUP_NS = 8,
	LTTNG_UST_ABI_CONTEXT_IPC_NS = 9,
	LTTNG_UST_ABI_CONTEXT_MNT_NS = 10,
	LTTNG_UST_ABI_CONTEXT_NET_NS = 11,
	LTTNG_UST_ABI_CONTEXT_PID_NS = 12,
	LTTNG_UST_ABI_CONTEXT_USER_NS = 13,
	LTTNG_UST_ABI_CONTEXT_UTS_NS = 14,
	LTTNG_UST_ABI_CONTEXT_VUID = 15,
	LTTNG_UST_ABI_CONTEXT_VEUID = 16,
	LTTNG_UST_ABI_CONTEXT_VSUID = 17,
	LTTNG_UST_ABI_CONTEXT_VGID = 18,
	LTTNG_UST_ABI_CONTEXT_VEGID = 19,
	LTTNG_UST_ABI_CONTEXT_VSGID = 20,
	LTTNG_UST_ABI_CONTEXT_TIME_NS = 21,
};

struct lttng_ust_abi_perf_counter_ctx {
	uint32_t type;
	uint64_t config;
	char name[LTTNG_UST_ABI_SYM_NAME_LEN];
} LTTNG_PACKED;

#define LTTNG_UST_ABI_CONTEXT_PADDING1 16
#define LTTNG_UST_ABI_CONTEXT_PADDING2 (LTTNG_UST_ABI_SYM_NAME_LEN + 32)
struct lttng_ust_abi_context {
	int32_t ctx; /* enum lttng_ust_abi_context_type */
	char padding[LTTNG_UST_ABI_CONTEXT_PADDING1];

	union {
		struct lttng_ust_abi_perf_counter_ctx perf_counter;
		struct {
			/* Includes trailing '\0'. */
			uint32_t provider_name_len;
			uint32_t ctx_name_len;
		} app_ctx;
		char padding[LTTNG_UST_ABI_CONTEXT_PADDING2];
	} u;
} LTTNG_PACKED;

/*
 * Tracer channel attributes.
 */
#define LTTNG_UST_ABI_CHANNEL_ATTR_PADDING (LTTNG_UST_ABI_SYM_NAME_LEN + 32)
struct lttng_ust_abi_channel_attr {
	uint64_t subbuf_size; /* bytes */
	uint64_t num_subbuf; /* power of 2 */
	int overwrite; /* 1: overwrite, 0: discard */
	unsigned int switch_timer_interval; /* usec */
	unsigned int read_timer_interval; /* usec */
	int32_t output; /* enum lttng_ust_abi_output */
	union {
		struct {
			int64_t blocking_timeout; /* Blocking timeout (usec) */
		} s;
		char padding[LTTNG_UST_ABI_CHANNEL_ATTR_PADDING];
	} u;
} LTTNG_PACKED;

#define LTTNG_UST_ABI_TRACEPOINT_ITER_PADDING 16
struct lttng_ust_abi_tracepoint_iter {
	char name[LTTNG_UST_ABI_SYM_NAME_LEN]; /* provider:name */
	int loglevel;
	char padding[LTTNG_UST_ABI_TRACEPOINT_ITER_PADDING];
} LTTNG_PACKED;

enum lttng_ust_abi_object_type {
	LTTNG_UST_ABI_OBJECT_TYPE_UNKNOWN = -1,
	LTTNG_UST_ABI_OBJECT_TYPE_CHANNEL = 0,
	LTTNG_UST_ABI_OBJECT_TYPE_STREAM = 1,
	LTTNG_UST_ABI_OBJECT_TYPE_EVENT = 2,
	LTTNG_UST_ABI_OBJECT_TYPE_CONTEXT = 3,
	LTTNG_UST_ABI_OBJECT_TYPE_EVENT_NOTIFIER_GROUP = 4,
	LTTNG_UST_ABI_OBJECT_TYPE_EVENT_NOTIFIER = 5,
	LTTNG_UST_ABI_OBJECT_TYPE_COUNTER = 6,
	LTTNG_UST_ABI_OBJECT_TYPE_COUNTER_GLOBAL = 7,
	LTTNG_UST_ABI_OBJECT_TYPE_COUNTER_CPU = 8,
};

#define LTTNG_UST_ABI_OBJECT_DATA_PADDING1 32
#define LTTNG_UST_ABI_OBJECT_DATA_PADDING2 (LTTNG_UST_ABI_SYM_NAME_LEN + 32)

struct lttng_ust_abi_object_data {
	int32_t type; /* enum lttng_ust_abi_object_type */
	int handle;
	uint64_t size;
	char padding1[LTTNG_UST_ABI_OBJECT_DATA_PADDING1];
	union {
		struct {
			void *data;
			int32_t type; /* enum lttng_ust_abi_chan_type */
			int wakeup_fd;
		} channel;
		struct {
			int shm_fd;
			int wakeup_fd;
			uint32_t stream_nr;
		} stream;
		struct {
			void *data;
		} counter;
		struct {
			int shm_fd;
		} counter_global;
		struct {
			int shm_fd;
			uint32_t cpu_nr;
		} counter_cpu;
		char padding2[LTTNG_UST_ABI_OBJECT_DATA_PADDING2];
	} u;
} LTTNG_PACKED;

enum lttng_ust_abi_calibrate_type {
	LTTNG_UST_ABI_CALIBRATE_TRACEPOINT,
};

#define LTTNG_UST_ABI_CALIBRATE_PADDING1 16
#define LTTNG_UST_ABI_CALIBRATE_PADDING2 (LTTNG_UST_ABI_SYM_NAME_LEN + 32)
struct lttng_ust_abi_calibrate {
	enum lttng_ust_abi_calibrate_type type; /* type (input) */
	char padding[LTTNG_UST_ABI_CALIBRATE_PADDING1];

	union {
		char padding[LTTNG_UST_ABI_CALIBRATE_PADDING2];
	} u;
} LTTNG_PACKED;

#define LTTNG_UST_ABI_FILTER_BYTECODE_MAX_LEN 65536
#define LTTNG_UST_ABI_FILTER_PADDING	      32
struct lttng_ust_abi_filter_bytecode {
	uint32_t len;
	uint32_t reloc_offset;
	uint64_t seqnum;
	char padding[LTTNG_UST_ABI_FILTER_PADDING];
	char data[0];
} LTTNG_PACKED;

#define LTTNG_UST_ABI_CAPTURE_BYTECODE_MAX_LEN 65536
#define LTTNG_UST_ABI_CAPTURE_PADDING	       32
struct lttng_ust_abi_capture_bytecode {
	uint32_t len;
	uint32_t reloc_offset;
	uint64_t seqnum;
	char padding[LTTNG_UST_ABI_CAPTURE_PADDING];
	char data[0];
} LTTNG_PACKED;

#define LTTNG_UST_ABI_EXCLUSION_PADDING 32
struct lttng_ust_abi_event_exclusion {
	uint32_t count;
	char padding[LTTNG_UST_ABI_EXCLUSION_PADDING];
	char names[LTTNG_UST_ABI_SYM_NAME_LEN][0];
} LTTNG_PACKED;

#define LTTNG_UST_ABI_CMD(minor)	(minor)
#define LTTNG_UST_ABI_CMDR(minor, type) (minor)
#define LTTNG_UST_ABI_CMDW(minor, type) (minor)

/* Handled by object descriptor */
#define LTTNG_UST_ABI_RELEASE LTTNG_UST_ABI_CMD(0x1)

/* Handled by object cmd */

/* LTTng-UST commands */
#define LTTNG_UST_ABI_SESSION			  LTTNG_UST_ABI_CMD(0x40)
#define LTTNG_UST_ABI_TRACER_VERSION		  LTTNG_UST_ABI_CMDR(0x41, struct lttng_ust_abi_tracer_version)
#define LTTNG_UST_ABI_TRACEPOINT_LIST		  LTTNG_UST_ABI_CMD(0x42)
#define LTTNG_UST_ABI_WAIT_QUIESCENT		  LTTNG_UST_ABI_CMD(0x43)
#define LTTNG_UST_ABI_REGISTER_DONE		  LTTNG_UST_ABI_CMD(0x44)
#define LTTNG_UST_ABI_TRACEPOINT_FIELD_LIST	  LTTNG_UST_ABI_CMD(0x45)
#define LTTNG_UST_ABI_EVENT_NOTIFIER_GROUP_CREATE LTTNG_UST_ABI_CMD(0x46)

/* Session commands */
#define LTTNG_UST_ABI_CHANNEL		LTTNG_UST_ABI_CMDW(0x51, struct lttng_ust_abi_channel)
#define LTTNG_UST_ABI_SESSION_START	LTTNG_UST_ABI_CMD(0x52)
#define LTTNG_UST_ABI_SESSION_STOP	LTTNG_UST_ABI_CMD(0x53)
#define LTTNG_UST_ABI_SESSION_STATEDUMP LTTNG_UST_ABI_CMD(0x54)

/* Channel commands */
#define LTTNG_UST_ABI_STREAM LTTNG_UST_ABI_CMD(0x60)
#define LTTNG_UST_ABI_EVENT  LTTNG_UST_ABI_CMDW(0x61, struct lttng_ust_abi_event)

/* Event and channel commands */
#define LTTNG_UST_ABI_CONTEXT	   LTTNG_UST_ABI_CMDW(0x70, struct lttng_ust_abi_context)
#define LTTNG_UST_ABI_FLUSH_BUFFER LTTNG_UST_ABI_CMD(0x71)

/* Event, event notifier, channel and session commands */
#define LTTNG_UST_ABI_ENABLE  LTTNG_UST_ABI_CMD(0x80)
#define LTTNG_UST_ABI_DISABLE LTTNG_UST_ABI_CMD(0x81)

/* Tracepoint list commands */
#define LTTNG_UST_ABI_TRACEPOINT_LIST_GET	LTTNG_UST_ABI_CMD(0x90)
#define LTTNG_UST_ABI_TRACEPOINT_FIELD_LIST_GET LTTNG_UST_ABI_CMD(0x91)

/* Event and event notifier commands */
#define LTTNG_UST_ABI_FILTER	LTTNG_UST_ABI_CMD(0xA0)
#define LTTNG_UST_ABI_EXCLUSION LTTNG_UST_ABI_CMD(0xA1)

/* Event notifier group commands */
#define LTTNG_UST_ABI_EVENT_NOTIFIER_CREATE \
	LTTNG_UST_ABI_CMDW(0xB0, struct lttng_ust_abi_event_notifier)

/* Event notifier commands */
#define LTTNG_UST_ABI_CAPTURE LTTNG_UST_ABI_CMD(0xB6)

/* Session and event notifier group commands */
#define LTTNG_UST_ABI_COUNTER LTTNG_UST_ABI_CMDW(0xC0, struct lttng_ust_abi_counter)

/* Counter commands */
#define LTTNG_UST_ABI_COUNTER_GLOBAL LTTNG_UST_ABI_CMDW(0xD0, struct lttng_ust_abi_counter_global)
#define LTTNG_UST_ABI_COUNTER_CPU    LTTNG_UST_ABI_CMDW(0xD1, struct lttng_ust_abi_counter_cpu)

#define LTTNG_UST_ABI_ROOT_HANDLE 0

#endif /* LTTNG_UST_ABI_INTERNAL_H */
