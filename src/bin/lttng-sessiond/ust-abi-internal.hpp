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

#ifndef lttng_ust_stringify
#define lttng_ust_stringify1(x) #x
#define lttng_ust_stringify(x)	lttng_ust_stringify1(x)
#endif /* lttng_ust_stringify */

#define LTTNG_UST_ABI_SYM_NAME_LEN 256
#define LTTNG_UST_ABI_PROCNAME_LEN 16

/* UST comm magic number, used to validate protocol and endianness. */
#define LTTNG_UST_ABI_COMM_MAGIC 0xC57C57C5

/* Version for ABI between liblttng-ust, sessiond, consumerd */
#define LTTNG_UST_ABI_MAJOR_VERSION		      11
#define LTTNG_UST_ABI_MAJOR_VERSION_OLDEST_COMPATIBLE 11
#define LTTNG_UST_ABI_MINOR_VERSION		      0

#define LTTNG_UST_ABI_CMD_MAX_LEN 4096U

#ifndef LTTNG_UST_ABI_UUID_LEN
#define LTTNG_UST_ABI_UUID_LEN 16
#endif

/*
 * Compile time assertion.
 * - predicate: boolean expression to evaluate,
 * - msg: string to print to the user on failure when `static_assert()` is
 *   supported,
 * - c_identifier_msg: message to be included in the typedef to emulate a
 *   static assertion. This parameter must be a valid C identifier as it will
 *   be used as a typedef name.
 */
#ifdef __cplusplus
#define lttng_ust_static_assert(predicate, msg, c_identifier_msg) static_assert(predicate, msg)
#elif defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L)
#define lttng_ust_static_assert(predicate, msg, c_identifier_msg) _Static_assert(predicate, msg)
#else
/*
 * Evaluates the predicate and emit a compilation error on failure.
 *
 * If the predicate evaluates to true, this macro emits a function
 * prototype with an argument type which is an array of size 0.
 *
 * If the predicate evaluates to false, this macro emits a function
 * prototype with an argument type which is an array of negative size
 * which is invalid in C and forces a compiler error. The
 * c_identifier_msg parameter is used as the argument identifier so it
 * is printed to the user when the error is reported.
 */
#define lttng_ust_static_assert(predicate, msg, c_identifier_msg) \
	void lttng_ust_static_assert_proto(char c_identifier_msg[2 * !!(predicate) -1])
#endif

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
	LTTNG_UST_ABI_CHAN_PER_CHANNEL = 2,
};

enum lttng_ust_abi_owner_id_type {
	LTTNG_UST_ABI_OWNER_ID_UNSET = 0,
	LTTNG_UST_ABI_OWNER_ID_CONSUMER = 1,
};

struct lttng_ust_abi_tracer_version {
	uint32_t major;
	uint32_t minor;
	uint32_t patchlevel;
} LTTNG_PACKED;

#define LTTNG_UST_ABI_CHANNEL_SIZE 64
/*
 * Given that the consumerd is limited to 64k file descriptors, we
 * cannot expect much more than 1MB channel structure size. This size is
 * depends on the number of streams within a channel, which depends on
 * the number of possible CPUs on the system.
 */
#define LTTNG_UST_ABI_CHANNEL_DATA_MAX_LEN 1048576U
struct lttng_ust_abi_channel {
	union {
		char padding[LTTNG_UST_ABI_CHANNEL_SIZE];
		struct {
			uint64_t len;
			int32_t type; /* enum lttng_ust_abi_chan_type */
			uint32_t owner_id;
		} LTTNG_PACKED;
	};
	char data[]; /* variable sized data */
} LTTNG_PACKED;

lttng_ust_static_assert(sizeof(struct lttng_ust_abi_channel) == LTTNG_UST_ABI_CHANNEL_SIZE,
			"Unexpected size for struct lttng_ust_abi_channel",
			Unexpected_size_for_struct_lttng_ust_abi_channel);

#define LTTNG_UST_ABI_CHANNEL_CONFIG_SIZE 64
struct lttng_ust_abi_channel_config {
	union {
		char padding[LTTNG_UST_ABI_CHANNEL_CONFIG_SIZE];
		struct {
			unsigned int id; /* Channel ID */
			unsigned char uuid[LTTNG_UST_ABI_UUID_LEN]; /* Trace session unique ID */
		} LTTNG_PACKED;
	};
} LTTNG_PACKED;

lttng_ust_static_assert(sizeof(struct lttng_ust_abi_channel_config) ==
				LTTNG_UST_ABI_CHANNEL_CONFIG_SIZE,
			"Incorrect size for struct lttng_ust_abi_channel_config",
			Incorrect_size_for_struct_lttng_ust_abi_channel_config);

#define LTTNG_UST_ABI_STREAM_SIZE 64
struct lttng_ust_abi_stream {
	union {
		char padding[LTTNG_UST_ABI_STREAM_SIZE];
		struct {
			uint64_t len; /* shm len */
			uint32_t stream_nr; /* stream number */
		} LTTNG_PACKED;
	};
	/*
	 * shm_fd and wakeup_fd are send over unix socket as file
	 * descriptors after this structure.
	 */
} LTTNG_PACKED;

lttng_ust_static_assert(sizeof(struct lttng_ust_abi_stream) == LTTNG_UST_ABI_STREAM_SIZE,
			"Unexpected size for struct lttng_ust_abi_stream",
			Unexpected_size_for_struct_lttng_ust_abi_stream);

#define LTTNG_UST_ABI_EVENT_SIZE 320
struct lttng_ust_abi_event {
	union {
		char padding[LTTNG_UST_ABI_EVENT_SIZE];
		struct {
			int32_t instrumentation; /* enum lttng_ust_abi_instrumentation */
			int32_t loglevel_type; /* enum lttng_ust_abi_loglevel_type */
			int32_t loglevel; /* value, -1: all */
			uint64_t token; /* User-provided token */
			char name[LTTNG_UST_ABI_SYM_NAME_LEN]; /* event name */
		} LTTNG_PACKED;
	};
} LTTNG_PACKED;

lttng_ust_static_assert(sizeof(struct lttng_ust_abi_event) == LTTNG_UST_ABI_EVENT_SIZE,
			"Unexpected size for struct lttng_ust_abi_event",
			Unexpected_size_for_struct_lttng_ust_abi_event);

#define LTTNG_UST_ABI_EVENT_NOTIFIER_SIZE 320
struct lttng_ust_abi_event_notifier {
	union {
		char padding[LTTNG_UST_ABI_EVENT_NOTIFIER_SIZE];
		struct {
			int32_t instrumentation; /* enum lttng_ust_abi_instrumentation */
			int32_t loglevel_type; /* enum lttng_ust_abi_loglevel_type */
			int32_t loglevel; /* value, -1: all */
			uint64_t token; /* User-provided token */
			uint64_t error_counter_index;
			char name[LTTNG_UST_ABI_SYM_NAME_LEN]; /* event name */
		} LTTNG_PACKED;
	};
} LTTNG_PACKED;

lttng_ust_static_assert(sizeof(struct lttng_ust_abi_event_notifier) ==
				LTTNG_UST_ABI_EVENT_NOTIFIER_SIZE,
			"Unexpected size for struct lttng_ust_abi_event_notifier",
			Unexpected_size_for_struct_lttng_ust_abi_event_notifier);

#define LTTNG_UST_ABI_EVENT_NOTIFIER_NOTIFICATION_SIZE 32
struct lttng_ust_abi_event_notifier_notification {
	union {
		char padding[LTTNG_UST_ABI_EVENT_NOTIFIER_NOTIFICATION_SIZE];
		struct {
			uint64_t token;
			uint16_t capture_buf_size;
		} LTTNG_PACKED;
	};
} LTTNG_PACKED;

lttng_ust_static_assert(sizeof(struct lttng_ust_abi_event_notifier_notification) ==
				LTTNG_UST_ABI_EVENT_NOTIFIER_NOTIFICATION_SIZE,
			"Unexpected size for struct lttng_ust_abi_event_notifier_notification",
			Unexpected_size_for_struct_lttng_ust_abi_event_notifier_notification);

enum lttng_ust_abi_key_token_type {
	LTTNG_UST_ABI_KEY_TOKEN_STRING = 0, /* arg: strtab_offset. */
	LTTNG_UST_ABI_KEY_TOKEN_EVENT_NAME = 1, /* no arg. */
	LTTNG_UST_ABI_KEY_TOKEN_PROVIDER_NAME = 2, /* no arg. */
};

enum lttng_ust_abi_counter_arithmetic {
	LTTNG_UST_ABI_COUNTER_ARITHMETIC_MODULAR = 0,
	LTTNG_UST_ABI_COUNTER_ARITHMETIC_SATURATION = 1,
};

enum lttng_ust_abi_counter_bitness {
	LTTNG_UST_ABI_COUNTER_BITNESS_32 = 0,
	LTTNG_UST_ABI_COUNTER_BITNESS_64 = 1,
};

#ifdef CONFIG_LTTNG_UST_EXPERIMENTAL_COUNTER
struct lttng_ust_abi_key_token {
	uint32_t len; /* length of child structure. */
	uint32_t type; /* enum lttng_ust_abi_key_token_type */
	/*
	 * The size of this structure is fixed because it is embedded into
	 * children structures.
	 */
} LTTNG_PACKED;

/* Length of this structure excludes the following string. */
struct lttng_ust_abi_key_token_string {
	struct lttng_ust_abi_key_token parent;
	uint32_t string_len; /* string length (includes \0) */

	char str[]; /* Null-terminated string following this structure. */
} LTTNG_PACKED;
#endif /* CONFIG_LTTNG_UST_EXPERIMENTAL_COUNTER */

/*
 * token types event_name and provider_name don't have specific fields,
 * so they do not need to derive their own specific child structure.
 */

/*
 * Dimension indexing: All events should use the same key type to index
 * a given map dimension.
 */
enum lttng_ust_abi_key_type {
	LTTNG_UST_ABI_KEY_TYPE_TOKENS = 0, /* Dimension key is a set of tokens. */
	LTTNG_UST_ABI_KEY_TYPE_INTEGER = 1, /* Dimension key is an integer value. */
};

#ifdef CONFIG_LTTNG_UST_EXPERIMENTAL_COUNTER
struct lttng_ust_abi_counter_key_dimension {
	uint32_t len; /* length of child structure */
	uint32_t key_type; /* enum lttng_ust_abi_key_type */
	/*
	 * The size of this structure is fixed because it is embedded into
	 * children structures.
	 */
} LTTNG_PACKED;

struct lttng_ust_abi_counter_key_dimension_tokens {
	struct lttng_ust_abi_counter_key_dimension parent;
	uint32_t nr_key_tokens;

	/* Followed by an array of nr_key_tokens struct lttng_ust_abi_key_token elements. */
} LTTNG_PACKED;

/*
 * The "integer" key type is not implemented yet, but when it will be
 * introduced in the future, its specific key dimension will allow
 * defining the function to apply over input argument, bytecode to run
 * and so on.
 */

enum lttng_ust_abi_counter_action {
	LTTNG_UST_ABI_COUNTER_ACTION_INCREMENT = 0,

	/*
	 * Can be extended with additional actions, such as decrement,
	 * set value, run bytecode, and so on.
	 */
};

struct lttng_ust_abi_counter_event {
	uint32_t len; /* length of this structure */
	uint32_t action; /* enum lttng_ust_abi_counter_action */

	struct lttng_ust_abi_event event;
	uint32_t number_key_dimensions; /* array of dimensions is an array of var. len. elements. */

	/*
	 * Followed by additional data specific to the action, and by a
	 * variable-length array of key dimensions.
	 */
} LTTNG_PACKED;
#endif /* CONFIG_LTTNG_UST_EXPERIMENTAL_COUNTER */

enum lttng_ust_abi_counter_dimension_flags {
	LTTNG_UST_ABI_COUNTER_DIMENSION_FLAG_UNDERFLOW = (1 << 0),
	LTTNG_UST_ABI_COUNTER_DIMENSION_FLAG_OVERFLOW = (1 << 1),
};

struct lttng_ust_abi_counter_dimension {
	uint32_t key_type; /* enum lttng_ust_abi_key_type */
	uint32_t flags; /* enum lttng_ust_abi_counter_dimension_flags */
	uint64_t size; /* dimension size (count of entries) */
	uint64_t underflow_index;
	uint64_t overflow_index;
} LTTNG_PACKED;

enum lttng_ust_abi_counter_conf_flags {
	LTTNG_UST_ABI_COUNTER_CONF_FLAG_COALESCE_HITS = (1 << 0),
};

struct lttng_ust_abi_counter_conf {
	uint32_t len; /* Length of fields before var. len. data. */
	uint32_t flags; /* enum lttng_ust_abi_counter_conf_flags */
	uint32_t arithmetic; /* enum lttng_ust_abi_counter_arithmetic */
	uint32_t bitness; /* enum lttng_ust_abi_counter_bitness */
	int64_t global_sum_step;
	uint32_t number_dimensions;
	uint32_t elem_len; /* array stride (size of lttng_ust_abi_counter_dimension) */
} LTTNG_PACKED;

struct lttng_ust_abi_counter_channel {
	uint32_t len; /* Length of this structure */
	uint64_t shm_len; /* shm len */
} LTTNG_PACKED;

struct lttng_ust_abi_counter_cpu {
	uint32_t len; /* Length of this structure */
	uint64_t shm_len; /* shm len */
	uint32_t cpu_nr;
} LTTNG_PACKED;

enum lttng_ust_abi_field_type {
	LTTNG_UST_ABI_FIELD_OTHER = 0,
	LTTNG_UST_ABI_FIELD_INTEGER = 1,
	LTTNG_UST_ABI_FIELD_ENUM = 2,
	LTTNG_UST_ABI_FIELD_FLOAT = 3,
	LTTNG_UST_ABI_FIELD_STRING = 4,
};

#define LTTNG_UST_ABI_FIELD_ITER_SIZE 640
struct lttng_ust_abi_field_iter {
	union {
		char padding[LTTNG_UST_ABI_FIELD_ITER_SIZE];
		struct {
			char event_name[LTTNG_UST_ABI_SYM_NAME_LEN];
			char field_name[LTTNG_UST_ABI_SYM_NAME_LEN];
			int32_t type; /* enum lttng_ust_abi_field_type */
			int loglevel; /* event loglevel */
			int nowrite;
		} LTTNG_PACKED;
	};
} LTTNG_PACKED;

lttng_ust_static_assert(sizeof(struct lttng_ust_abi_field_iter) == LTTNG_UST_ABI_FIELD_ITER_SIZE,
			"Unexpected size for struct lttng_ust_abi_field_iter",
			Unexpected_size_for_struct_lttng_ust_abi_field_iter);

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

#define LTTNG_UST_ABI_CONTEXT_HEADER_SIZE 16
#define LTTNG_UST_ABI_CONTEXT_TYPE_SIZE	  288
struct lttng_ust_abi_context {
	union {
		char padding[LTTNG_UST_ABI_CONTEXT_HEADER_SIZE];
		struct {
			int32_t ctx; /* enum lttng_ust_abi_context_type */
		} LTTNG_PACKED;
	} header;

	union {
		char padding[LTTNG_UST_ABI_CONTEXT_TYPE_SIZE];
		struct lttng_ust_abi_perf_counter_ctx perf_counter;
		struct {
			/* Includes trailing '\0'. */
			uint32_t provider_name_len;
			uint32_t ctx_name_len;
		} LTTNG_PACKED app_ctx;
	} type;
} LTTNG_PACKED;

lttng_ust_static_assert(sizeof(struct lttng_ust_abi_context) ==
				LTTNG_UST_ABI_CONTEXT_HEADER_SIZE + LTTNG_UST_ABI_CONTEXT_TYPE_SIZE,
			"Unexpected size for struct lttng_ust_abi_context",
			Unexpected_size_for_struct_lttng_ust_abi_context);

/*
 * Tracer channel attributes.
 */
#define LTTNG_UST_ABI_CHANNEL_ATTR_SIZE 320
struct lttng_ust_abi_channel_attr {
	union {
		char padding[LTTNG_UST_ABI_CHANNEL_ATTR_SIZE];
		struct {
			uint64_t subbuf_size; /* bytes */
			uint64_t num_subbuf; /* power of 2 */
			int overwrite; /* 1: overwrite, 0: discard */
			unsigned int switch_timer_interval; /* usec */
			unsigned int read_timer_interval; /* usec */
			int32_t output; /* enum lttng_ust_abi_output */
			int64_t blocking_timeout; /* Blocking timeout (usec) */
			int8_t type; /* enum lttng_ust_abi_chan_type */
		} LTTNG_PACKED;
	};
} LTTNG_PACKED;

lttng_ust_static_assert(sizeof(struct lttng_ust_abi_channel_attr) ==
				LTTNG_UST_ABI_CHANNEL_ATTR_SIZE,
			"Unexpected size for struct lttng_ust_abi_channel_attr",
			Unexpected_size_for_struct_lttng_ust_abi_channel_attr);

#define LTTNG_UST_ABI_TRACEPOINT_ITER_SIZE 320
struct lttng_ust_abi_tracepoint_iter {
	union {
		char padding[LTTNG_UST_ABI_TRACEPOINT_ITER_SIZE];
		struct {
			char name[LTTNG_UST_ABI_SYM_NAME_LEN]; /* provider:name */
			int loglevel;
		} LTTNG_PACKED;
	};
} LTTNG_PACKED;

lttng_ust_static_assert(sizeof(struct lttng_ust_abi_tracepoint_iter) ==
				LTTNG_UST_ABI_TRACEPOINT_ITER_SIZE,
			"Unexpected size for struct lttng_ust_abi_tracepoint_iter",
			Unexpected_size_for_struct_lttng_ust_abi_tracepoint_iter);

enum lttng_ust_abi_object_type {
	LTTNG_UST_ABI_OBJECT_TYPE_UNKNOWN = -1,
	LTTNG_UST_ABI_OBJECT_TYPE_CHANNEL = 0,
	LTTNG_UST_ABI_OBJECT_TYPE_STREAM = 1,
	LTTNG_UST_ABI_OBJECT_TYPE_EVENT = 2,
	LTTNG_UST_ABI_OBJECT_TYPE_CONTEXT = 3,
	LTTNG_UST_ABI_OBJECT_TYPE_EVENT_NOTIFIER_GROUP = 4,
	LTTNG_UST_ABI_OBJECT_TYPE_EVENT_NOTIFIER = 5,
	LTTNG_UST_ABI_OBJECT_TYPE_COUNTER = 6,
	LTTNG_UST_ABI_OBJECT_TYPE_COUNTER_CHANNEL = 7,
	LTTNG_UST_ABI_OBJECT_TYPE_COUNTER_CPU = 8,
	LTTNG_UST_ABI_OBJECT_TYPE_COUNTER_EVENT = 9,
};

#define LTTNG_UST_ABI_OBJECT_DATA_HEADER_SIZE 32
#define LTTNG_UST_ABI_OBJECT_DATA_TYPE_SIZE   288

struct lttng_ust_abi_object_data {
	union {
		char padding[LTTNG_UST_ABI_OBJECT_DATA_HEADER_SIZE];
		struct {
			int32_t type; /* enum lttng_ust_abi_object_type */
			int handle;
			uint64_t size;
		} LTTNG_PACKED;
	} header;

	union {
		char padding[LTTNG_UST_ABI_OBJECT_DATA_TYPE_SIZE];
		struct {
			void *data;
			int32_t type; /* enum lttng_ust_abi_chan_type */
			int wakeup_fd;
			uint32_t owner_id;
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
		} counter_channel;
		struct {
			int shm_fd;
			uint32_t cpu_nr;
		} counter_cpu;
	} type;
} LTTNG_PACKED;

lttng_ust_static_assert(sizeof(struct lttng_ust_abi_object_data) ==
				LTTNG_UST_ABI_OBJECT_DATA_HEADER_SIZE +
					LTTNG_UST_ABI_OBJECT_DATA_TYPE_SIZE,
			"Unexpected size for struct lttng_ust_abi_object_data",
			Unexpected_size_for_struct_lttng_ust_abi_object_data);

enum lttng_ust_abi_calibrate_type {
	LTTNG_UST_ABI_CALIBRATE_TRACEPOINT,
};

#define LTTNG_UST_ABI_CALIBRATE_SIZE 32
struct lttng_ust_abi_calibrate {
	union {
		char padding[LTTNG_UST_ABI_CALIBRATE_SIZE];
		struct {
			enum lttng_ust_abi_calibrate_type type; /* type (input) */
		} LTTNG_PACKED;
	};
} LTTNG_PACKED;

lttng_ust_static_assert(sizeof(struct lttng_ust_abi_calibrate) == LTTNG_UST_ABI_CALIBRATE_SIZE,
			"Unexpected size for struct lttng_ust_abi_calibrate",
			Unexpected_size_for_struct_lttng_ust_abi_calibrate);

#define LTTNG_UST_ABI_FILTER_BYTECODE_MAX_LEN 65536
#define LTTNG_UST_ABI_FILTER_SIZE	      64
struct lttng_ust_abi_filter_bytecode {
	union {
		char padding[LTTNG_UST_ABI_FILTER_SIZE];
		struct {
			uint32_t len;
			uint32_t reloc_offset;
			uint64_t seqnum;
		} LTTNG_PACKED;
	};
	char data[0];
} LTTNG_PACKED;

lttng_ust_static_assert(sizeof(struct lttng_ust_abi_filter_bytecode) == LTTNG_UST_ABI_FILTER_SIZE,
			"Unexpected size for struct lttng_ust_abi_filter_bytecode",
			Unexpected_size_for_struct_lttng_ust_abi_filter_bytecode);

#define LTTNG_UST_ABI_CAPTURE_BYTECODE_MAX_LEN 65536
#define LTTNG_UST_ABI_CAPTURE_SIZE	       64
struct lttng_ust_abi_capture_bytecode {
	union {
		char padding[LTTNG_UST_ABI_CAPTURE_SIZE];
		struct {
			uint32_t len;
			uint32_t reloc_offset;
			uint64_t seqnum;
		} LTTNG_PACKED;
	};
	char data[0];
} LTTNG_PACKED;

lttng_ust_static_assert(sizeof(struct lttng_ust_abi_capture_bytecode) == LTTNG_UST_ABI_CAPTURE_SIZE,
			"Unexpected size for struct lttng_ust_abi_capture_bytecode",
			Unexpected_size_for_struct_lttng_ust_abi_capture_bytecode);

#define LTTNG_UST_ABI_EXCLUSION_SIZE 32
struct lttng_ust_abi_event_exclusion {
	union {
		char padding[LTTNG_UST_ABI_EXCLUSION_SIZE];
		struct {
			uint32_t count;
		} LTTNG_PACKED;
	};
	char names[LTTNG_UST_ABI_SYM_NAME_LEN][0];
} LTTNG_PACKED;

lttng_ust_static_assert(sizeof(struct lttng_ust_abi_event_exclusion) ==
				LTTNG_UST_ABI_EXCLUSION_SIZE,
			"Unexpected size for struct lttng_ust_abi_event_exclusion",
			Unexpected_size_for_struct_lttng_ust_abi_event_exclusion);

#define LTTNG_UST_ABI_CMD(minor)		    (minor)
#define LTTNG_UST_ABI_CMDR(minor, type)		    (minor)
#define LTTNG_UST_ABI_CMDW(minor, type)		    (minor)
#define LTTNG_UST_ABI_CMDV(minor, var_len_cmd_type) (minor)

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
	LTTNG_UST_ABI_CMDV(0xB0, struct lttng_ust_abi_event_notifier)

/* Event notifier commands */
#define LTTNG_UST_ABI_CAPTURE LTTNG_UST_ABI_CMD(0xB6)

/*
 * Dummy command for testing unknown command.
 *
 * Not meant to be used by users.
 */
#define LTTNG_UST_ABI_UNKNOWN_COMMAND LTTNG_UST_ABI_CMD(UINT32_MAX)

/* Session and event notifier group commands */
/* (0xC0) reserved for old ABI. */
#define LTTNG_UST_ABI_COUNTER LTTNG_UST_ABI_CMDV(0xC1, struct lttng_ust_abi_counter_conf)

/* Counter commands */
/* (0xD0, 0xD1) reserved for old ABI. */
#define LTTNG_UST_ABI_COUNTER_CHANNEL LTTNG_UST_ABI_CMDV(0xD2, struct lttng_ust_abi_counter_channel)
#define LTTNG_UST_ABI_COUNTER_CPU     LTTNG_UST_ABI_CMDV(0xD3, struct lttng_ust_abi_counter_cpu)
#define LTTNG_UST_ABI_COUNTER_EVENT   LTTNG_UST_ABI_CMDV(0xD4, struct lttng_ust_abi_counter_event)

#define LTTNG_UST_ABI_ROOT_HANDLE 0

#endif /* LTTNG_UST_ABI_INTERNAL_H */
