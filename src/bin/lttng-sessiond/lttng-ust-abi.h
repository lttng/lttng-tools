#ifndef _LTTNG_UST_ABI_H
#define _LTTNG_UST_ABI_H

/*
 * lttng/ust-abi.h
 *
 * LTTng-UST ABI header
 *
 * Copyright 2010-2012 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdint.h>

#define lttng_ust_notrace __attribute__((no_instrument_function))
#define LTTNG_PACKED    __attribute__((__packed__))

#ifndef __ust_stringify
#define __ust_stringify1(x)	#x
#define __ust_stringify(x)	__ust_stringify1(x)
#endif /* __ust_stringify */

#define LTTNG_UST_SYM_NAME_LEN			256
#define LTTNG_UST_ABI_PROCNAME_LEN		16

/* UST comm magic number, used to validate protocol and endianness. */
#define LTTNG_UST_COMM_MAGIC			0xC57C57C5

/* Version for ABI between liblttng-ust, sessiond, consumerd */
#define LTTNG_UST_ABI_MAJOR_VERSION		7
#define LTTNG_UST_ABI_MINOR_VERSION		2

struct lttng_ust_calibrate;

enum lttng_ust_instrumentation {
	LTTNG_UST_TRACEPOINT		= 0,
	LTTNG_UST_PROBE			= 1,
	LTTNG_UST_FUNCTION		= 2,
};

enum lttng_ust_loglevel_type {
	LTTNG_UST_LOGLEVEL_ALL		= 0,
	LTTNG_UST_LOGLEVEL_RANGE	= 1,
	LTTNG_UST_LOGLEVEL_SINGLE	= 2,
};

enum lttng_ust_output {
	LTTNG_UST_MMAP		= 0,
};

enum lttng_ust_chan_type {
	LTTNG_UST_CHAN_PER_CPU = 0,
	LTTNG_UST_CHAN_METADATA = 1,
};

struct lttng_ust_tracer_version {
	uint32_t major;
	uint32_t minor;
	uint32_t patchlevel;
} LTTNG_PACKED;

#define LTTNG_UST_CHANNEL_PADDING	(LTTNG_UST_SYM_NAME_LEN + 32)
/*
 * Given that the consumerd is limited to 64k file descriptors, we
 * cannot expect much more than 1MB channel structure size. This size is
 * depends on the number of streams within a channel, which depends on
 * the number of possible CPUs on the system.
 */
#define LTTNG_UST_CHANNEL_DATA_MAX_LEN	1048576U
struct lttng_ust_channel {
	uint64_t len;
	enum lttng_ust_chan_type type;
	char padding[LTTNG_UST_CHANNEL_PADDING];
	char data[];	/* variable sized data */
} LTTNG_PACKED;

#define LTTNG_UST_STREAM_PADDING1	(LTTNG_UST_SYM_NAME_LEN + 32)
struct lttng_ust_stream {
	uint64_t len;		/* shm len */
	uint32_t stream_nr;	/* stream number */
	char padding[LTTNG_UST_STREAM_PADDING1];
	/*
	 * shm_fd and wakeup_fd are send over unix socket as file
	 * descriptors after this structure.
	 */
} LTTNG_PACKED;

#define LTTNG_UST_EVENT_PADDING1	16
#define LTTNG_UST_EVENT_PADDING2	(LTTNG_UST_SYM_NAME_LEN + 32)
struct lttng_ust_event {
	enum lttng_ust_instrumentation instrumentation;
	char name[LTTNG_UST_SYM_NAME_LEN];	/* event name */

	enum lttng_ust_loglevel_type loglevel_type;
	int loglevel;	/* value, -1: all */
	char padding[LTTNG_UST_EVENT_PADDING1];

	/* Per instrumentation type configuration */
	union {
		char padding[LTTNG_UST_EVENT_PADDING2];
	} u;
} LTTNG_PACKED;

enum lttng_ust_field_type {
	LTTNG_UST_FIELD_OTHER			= 0,
	LTTNG_UST_FIELD_INTEGER			= 1,
	LTTNG_UST_FIELD_ENUM			= 2,
	LTTNG_UST_FIELD_FLOAT			= 3,
	LTTNG_UST_FIELD_STRING			= 4,
};

#define LTTNG_UST_FIELD_ITER_PADDING	(LTTNG_UST_SYM_NAME_LEN + 28)
struct lttng_ust_field_iter {
	char event_name[LTTNG_UST_SYM_NAME_LEN];
	char field_name[LTTNG_UST_SYM_NAME_LEN];
	enum lttng_ust_field_type type;
	int loglevel;				/* event loglevel */
	int nowrite;
	char padding[LTTNG_UST_FIELD_ITER_PADDING];
} LTTNG_PACKED;

enum lttng_ust_context_type {
	LTTNG_UST_CONTEXT_VTID			= 0,
	LTTNG_UST_CONTEXT_VPID			= 1,
	LTTNG_UST_CONTEXT_PTHREAD_ID		= 2,
	LTTNG_UST_CONTEXT_PROCNAME		= 3,
	LTTNG_UST_CONTEXT_IP			= 4,
	LTTNG_UST_CONTEXT_PERF_THREAD_COUNTER	= 5,
	LTTNG_UST_CONTEXT_CPU_ID		= 6,
	LTTNG_UST_CONTEXT_APP_CONTEXT		= 7,
};

struct lttng_ust_perf_counter_ctx {
	uint32_t type;
	uint64_t config;
	char name[LTTNG_UST_SYM_NAME_LEN];
} LTTNG_PACKED;

#define LTTNG_UST_CONTEXT_PADDING1	16
#define LTTNG_UST_CONTEXT_PADDING2	(LTTNG_UST_SYM_NAME_LEN + 32)
struct lttng_ust_context {
	enum lttng_ust_context_type ctx;
	char padding[LTTNG_UST_CONTEXT_PADDING1];

	union {
		struct lttng_ust_perf_counter_ctx perf_counter;
		struct {
			/* Includes trailing '\0'. */
			uint32_t provider_name_len;
			uint32_t ctx_name_len;
		} app_ctx;
		char padding[LTTNG_UST_CONTEXT_PADDING2];
	} u;
} LTTNG_PACKED;

/*
 * Tracer channel attributes.
 */
#define LTTNG_UST_CHANNEL_ATTR_PADDING	(LTTNG_UST_SYM_NAME_LEN + 32)
struct lttng_ust_channel_attr {
	uint64_t subbuf_size;			/* bytes, power of 2 */
	uint64_t num_subbuf;			/* power of 2 */
	int overwrite;				/* 1: overwrite, 0: discard */
	unsigned int switch_timer_interval;	/* usec */
	unsigned int read_timer_interval;	/* usec */
	enum lttng_ust_output output;		/* splice, mmap */
	union {
		struct {
			int64_t blocking_timeout;	/* Retry timeout (usec) */
		} s;
		char padding[LTTNG_UST_CHANNEL_ATTR_PADDING];
	} u;
} LTTNG_PACKED;

#define LTTNG_UST_TRACEPOINT_ITER_PADDING	16
struct lttng_ust_tracepoint_iter {
	char name[LTTNG_UST_SYM_NAME_LEN];	/* provider:name */
	int loglevel;
	char padding[LTTNG_UST_TRACEPOINT_ITER_PADDING];
} LTTNG_PACKED;

enum lttng_ust_object_type {
	LTTNG_UST_OBJECT_TYPE_UNKNOWN = -1,
	LTTNG_UST_OBJECT_TYPE_CHANNEL = 0,
	LTTNG_UST_OBJECT_TYPE_STREAM = 1,
	LTTNG_UST_OBJECT_TYPE_EVENT = 2,
	LTTNG_UST_OBJECT_TYPE_CONTEXT = 3,
};

#define LTTNG_UST_OBJECT_DATA_PADDING1	32
#define LTTNG_UST_OBJECT_DATA_PADDING2	(LTTNG_UST_SYM_NAME_LEN + 32)

struct lttng_ust_object_data {
	enum lttng_ust_object_type type;
	int handle;
	uint64_t size;
	char padding1[LTTNG_UST_OBJECT_DATA_PADDING1];
	union {
		struct {
			void *data;
			enum lttng_ust_chan_type type;
			int wakeup_fd;
		} channel;
		struct {
			int shm_fd;
			int wakeup_fd;
			uint32_t stream_nr;
		} stream;
		char padding2[LTTNG_UST_OBJECT_DATA_PADDING2];
	} u;
} LTTNG_PACKED;

#define FILTER_BYTECODE_MAX_LEN		65536
#define LTTNG_UST_FILTER_PADDING	32
struct lttng_ust_filter_bytecode {
	uint32_t len;
	uint32_t reloc_offset;
	uint64_t seqnum;
	char padding[LTTNG_UST_FILTER_PADDING];
	char data[0];
} LTTNG_PACKED;

#define LTTNG_UST_EXCLUSION_PADDING	32
struct lttng_ust_event_exclusion {
	uint32_t count;
	char padding[LTTNG_UST_EXCLUSION_PADDING];
	char names[LTTNG_UST_SYM_NAME_LEN][0];
} LTTNG_PACKED;

#define _UST_CMD(minor)				(minor)
#define _UST_CMDR(minor, type)			(minor)
#define _UST_CMDW(minor, type)			(minor)

/* Handled by object descriptor */
#define LTTNG_UST_RELEASE			_UST_CMD(0x1)

/* Handled by object cmd */

/* LTTng-UST commands */
#define LTTNG_UST_SESSION			_UST_CMD(0x40)
#define LTTNG_UST_TRACER_VERSION		\
	_UST_CMDR(0x41, struct lttng_ust_tracer_version)
#define LTTNG_UST_TRACEPOINT_LIST		_UST_CMD(0x42)
#define LTTNG_UST_WAIT_QUIESCENT		_UST_CMD(0x43)
#define LTTNG_UST_REGISTER_DONE			_UST_CMD(0x44)
#define LTTNG_UST_TRACEPOINT_FIELD_LIST		_UST_CMD(0x45)

/* Session FD commands */
#define LTTNG_UST_CHANNEL			\
	_UST_CMDW(0x51, struct lttng_ust_channel)
#define LTTNG_UST_SESSION_START			_UST_CMD(0x52)
#define LTTNG_UST_SESSION_STOP			_UST_CMD(0x53)
#define LTTNG_UST_SESSION_STATEDUMP		_UST_CMD(0x54)

/* Channel FD commands */
#define LTTNG_UST_STREAM			_UST_CMD(0x60)
#define LTTNG_UST_EVENT			\
	_UST_CMDW(0x61, struct lttng_ust_event)

/* Event and Channel FD commands */
#define LTTNG_UST_CONTEXT			\
	_UST_CMDW(0x70, struct lttng_ust_context)
#define LTTNG_UST_FLUSH_BUFFER			\
	_UST_CMD(0x71)

/* Event, Channel and Session commands */
#define LTTNG_UST_ENABLE			_UST_CMD(0x80)
#define LTTNG_UST_DISABLE			_UST_CMD(0x81)

/* Tracepoint list commands */
#define LTTNG_UST_TRACEPOINT_LIST_GET		_UST_CMD(0x90)
#define LTTNG_UST_TRACEPOINT_FIELD_LIST_GET	_UST_CMD(0x91)

/* Event FD commands */
#define LTTNG_UST_FILTER			_UST_CMD(0xA0)

#define LTTNG_UST_ROOT_HANDLE	0

struct lttng_ust_obj;

union ust_args {
	struct {
		void *chan_data;
		int wakeup_fd;
	} channel;
	struct {
		int shm_fd;
		int wakeup_fd;
	} stream;
	struct {
		struct lttng_ust_field_iter entry;
	} field_list;
};

struct lttng_ust_objd_ops {
	long (*cmd)(int objd, unsigned int cmd, unsigned long arg,
		union ust_args *args, void *owner);
	int (*release)(int objd);
};

/* Create root handle. Always ID 0. */
int lttng_abi_create_root_handle(void);

const struct lttng_ust_objd_ops *objd_ops(int id);
int lttng_ust_objd_unref(int id, int is_owner);

void lttng_ust_abi_exit(void);
void lttng_ust_events_exit(void);
void lttng_ust_objd_table_owner_cleanup(void *owner);

#endif /* _LTTNG_UST_ABI_H */
