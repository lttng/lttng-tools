#ifndef _LTTNG_UST_ABI_H
#define _LTTNG_UST_ABI_H

/*
 * lttng/ust-abi.h
 *
 * Copyright 2010-2011 (c) - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * LTTng-UST ABI header
 *
 * Dual LGPL v2.1/GPL v2 license.
 */

#include <stdint.h>

#define LTTNG_UST_SYM_NAME_LEN	256

#define LTTNG_UST_COMM_VERSION_MAJOR		0
#define LTTNG_UST_COMM_VERSION_MINOR		1

enum lttng_ust_instrumentation {
	LTTNG_UST_TRACEPOINT		= 0,
	LTTNG_UST_PROBE			= 1,
	LTTNG_UST_FUNCTION		= 2,
	LTTNG_UST_TRACEPOINT_LOGLEVEL	= 3,
};

enum lttng_ust_output {
	LTTNG_UST_MMAP		= 0,
};

struct lttng_ust_tracer_version {
	uint32_t version;
	uint32_t patchlevel;
	uint32_t sublevel;
};

struct lttng_ust_channel {
	int overwrite;				/* 1: overwrite, 0: discard */
	uint64_t subbuf_size;			/* in bytes */
	uint64_t num_subbuf;
	unsigned int switch_timer_interval;	/* usecs */
	unsigned int read_timer_interval;	/* usecs */
	enum lttng_ust_output output;		/* output mode */
};

struct lttng_ust_event {
	char name[LTTNG_UST_SYM_NAME_LEN];	/* event name */
	enum lttng_ust_instrumentation instrumentation;
	/* Per instrumentation type configuration */
	union {
	} u;
};

enum lttng_ust_context_type {
	LTTNG_UST_CONTEXT_VTID			= 0,
	LTTNG_UST_CONTEXT_VPID			= 1,
	LTTNG_UST_CONTEXT_PTHREAD_ID		= 2,
	LTTNG_UST_CONTEXT_PROCNAME		= 3,
};

struct lttng_ust_context {
	enum lttng_ust_context_type ctx;
	union {
	} u;
};

/*
 * Tracer channel attributes.
 */
struct lttng_ust_channel_attr {
	int overwrite;				/* 1: overwrite, 0: discard */
	uint64_t subbuf_size;			/* bytes */
	uint64_t num_subbuf;			/* power of 2 */
	unsigned int switch_timer_interval;	/* usec */
	unsigned int read_timer_interval;	/* usec */
	enum lttng_ust_output output;		/* splice, mmap */
};

struct lttng_ust_tracepoint_iter {
	char name[LTTNG_UST_SYM_NAME_LEN];	/* provider:name */
	char loglevel[LTTNG_UST_SYM_NAME_LEN];	/* loglevel */
	int64_t loglevel_value;
};

struct lttng_ust_object_data {
	int handle;
	int shm_fd;
	int wait_fd;
	uint64_t memory_map_size;
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
		int *wait_fd;
		uint64_t *memory_map_size;
	} channel;
	struct {
		int *shm_fd;
		int *wait_fd;
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
