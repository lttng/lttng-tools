#ifndef _LTTNG_UST_ABI_H
#define _LTTNG_UST_ABI_H

/*
 * lttng/ust-abi.h
 *
 * Copyright 2010-2011 (c) - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * LTTng-UST ABI header
 *
 * THIS MATERIAL IS PROVIDED AS IS, WITH ABSOLUTELY NO WARRANTY EXPRESSED
 * OR IMPLIED.  ANY USE IS AT YOUR OWN RISK.
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
 */

#include <stdint.h>

#define LTTNG_UST_SYM_NAME_LEN	256

#define LTTNG_UST_COMM_VERSION_MAJOR		2
#define LTTNG_UST_COMM_VERSION_MINOR		0

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

struct lttng_ust_tracer_version {
	uint32_t major;
	uint32_t minor;
	uint32_t patchlevel;
};

#define LTTNG_UST_CHANNEL_PADDING	LTTNG_UST_SYM_NAME_LEN + 32
struct lttng_ust_channel {
	int overwrite;				/* 1: overwrite, 0: discard */
	uint64_t subbuf_size;			/* in bytes */
	uint64_t num_subbuf;
	unsigned int switch_timer_interval;	/* usecs */
	unsigned int read_timer_interval;	/* usecs */
	enum lttng_ust_output output;		/* output mode */
	char padding[LTTNG_UST_CHANNEL_PADDING];
};

#define LTTNG_UST_STREAM_PADDING1	16
#define LTTNG_UST_STREAM_PADDING2	LTTNG_UST_SYM_NAME_LEN + 32
struct lttng_ust_stream {
	char padding[LTTNG_UST_STREAM_PADDING1];

	union {
		char padding[LTTNG_UST_STREAM_PADDING2];
	} u;
};

#define LTTNG_UST_EVENT_PADDING1	16
#define LTTNG_UST_EVENT_PADDING2	LTTNG_UST_SYM_NAME_LEN + 32
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
};

enum lttng_ust_context_type {
	LTTNG_UST_CONTEXT_VTID			= 0,
	LTTNG_UST_CONTEXT_VPID			= 1,
	LTTNG_UST_CONTEXT_PTHREAD_ID		= 2,
	LTTNG_UST_CONTEXT_PROCNAME		= 3,
};

#define LTTNG_UST_CONTEXT_PADDING1	16
#define LTTNG_UST_CONTEXT_PADDING2	LTTNG_UST_SYM_NAME_LEN + 32
struct lttng_ust_context {
	enum lttng_ust_context_type ctx;
	char padding[LTTNG_UST_CONTEXT_PADDING1];

	union {
		char padding[LTTNG_UST_CONTEXT_PADDING2];
	} u;
};

/*
 * Tracer channel attributes.
 */
#define LTTNG_UST_CHANNEL_ATTR_PADDING	LTTNG_UST_SYM_NAME_LEN + 32
struct lttng_ust_channel_attr {
	int overwrite;				/* 1: overwrite, 0: discard */
	uint64_t subbuf_size;			/* bytes */
	uint64_t num_subbuf;			/* power of 2 */
	unsigned int switch_timer_interval;	/* usec */
	unsigned int read_timer_interval;	/* usec */
	enum lttng_ust_output output;		/* splice, mmap */
	char padding[LTTNG_UST_CHANNEL_ATTR_PADDING];
};

#define LTTNG_UST_TRACEPOINT_ITER_PADDING	16
struct lttng_ust_tracepoint_iter {
	char name[LTTNG_UST_SYM_NAME_LEN];	/* provider:name */
	int loglevel;
	char padding[LTTNG_UST_TRACEPOINT_ITER_PADDING];
};

#define LTTNG_UST_OBJECT_DATA_PADDING		LTTNG_UST_SYM_NAME_LEN + 32
struct lttng_ust_object_data {
	int handle;
	int shm_fd;
	char *shm_path;
	int wait_fd;
	char *wait_pipe_path;
	uint64_t memory_map_size;
	char padding[LTTNG_UST_OBJECT_DATA_PADDING];
};

enum lttng_ust_calibrate_type {
	LTTNG_UST_CALIBRATE_TRACEPOINT,
};

#define LTTNG_UST_CALIBRATE_PADDING1	16
#define LTTNG_UST_CALIBRATE_PADDING2	LTTNG_UST_SYM_NAME_LEN + 32
struct lttng_ust_calibrate {
	enum lttng_ust_calibrate_type type;	/* type (input) */
	char padding[LTTNG_UST_CALIBRATE_PADDING1];

	union {
		char padding[LTTNG_UST_CALIBRATE_PADDING2];
	} u;
};

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

/* Session FD commands */
#define LTTNG_UST_METADATA			\
	_UST_CMDW(0x50, struct lttng_ust_channel)
#define LTTNG_UST_CHANNEL			\
	_UST_CMDW(0x51, struct lttng_ust_channel)
#define LTTNG_UST_SESSION_START			_UST_CMD(0x52)
#define LTTNG_UST_SESSION_STOP			_UST_CMD(0x53)

/* Channel FD commands */
#define LTTNG_UST_STREAM			_UST_CMD(0x60)
#define LTTNG_UST_EVENT			\
	_UST_CMDW(0x61, struct lttng_ust_event)
#define LTTNG_UST_STREAM_PIPE			_UST_CMD(0x62)
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

#define LTTNG_UST_ROOT_HANDLE	0

struct lttng_ust_obj;

union ust_args {
	struct {
		int *shm_fd;
		char *shm_path;
		int *wait_fd;
		char *wait_pipe_path;
		uint64_t *memory_map_size;
	} channel;
	struct {
		int *shm_fd;
		char *shm_path;
		int *wait_fd;
		char *wait_pipe_path;
		uint64_t *memory_map_size;
	} stream;
};

struct lttng_ust_objd_ops {
	long (*cmd)(int objd, unsigned int cmd, unsigned long arg,
		union ust_args *args);
	int (*release)(int objd);
};

/* Create root handle. Always ID 0. */
int lttng_abi_create_root_handle(void);

const struct lttng_ust_objd_ops *objd_ops(int id);
int lttng_ust_objd_unref(int id);

void lttng_ust_abi_exit(void);
void lttng_ust_events_exit(void);

#endif /* _LTTNG_UST_ABI_H */
