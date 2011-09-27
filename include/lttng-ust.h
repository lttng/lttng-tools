#ifndef _LTTNG_UST_H
#define _LTTNG_UST_H

/*
 * Taken from the lttng-ust-abi.h in the UST 2.0 git tree
 *
 * Copyright 2010-2011 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright 2011 - David Goulet <david.goulet@polymtl.ca>
 *
 * LTTng-UST ABI header
 *
 * Dual LGPL v2.1/GPL v2 license.
 */

#include <stdint.h>

#define LTTNG_UST_SYM_NAME_LEN         128

#define LTTNG_UST_COMM_VERSION_MAJOR   0
#define LTTNG_UST_COMM_VERSION_MINOR   1

enum lttng_ust_instrumentation {
	LTTNG_UST_TRACEPOINT    = 0,
	LTTNG_UST_PROBE         = 1,
	LTTNG_UST_FUNCTION      = 2,
};

enum lttng_ust_output {
	LTTNG_UST_MMAP          = 0,
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
	/* The following fields are used internally within UST. */
	int shm_fd;
	int wait_fd;
	uint64_t memory_map_size;
};

struct lttng_ust_event {
	char name[LTTNG_UST_SYM_NAME_LEN];	/* event name */
	enum lttng_ust_instrumentation instrumentation;
	/* Per instrumentation type configuration */
	union {
	} u;
};

enum lttng_ust_context_type {
	LTTNG_UST_CONTEXT_VTID      = 0,
};

struct lttng_ust_context {
	enum lttng_ust_context_type ctx;
	union {
	} u;
};

#define _UST_CMD(minor)                 (minor)
#define _UST_CMDR(minor, type)          (minor)
#define _UST_CMDW(minor, type)          (minor)

/* Handled by object descriptor */
#define LTTNG_UST_RELEASE               _UST_CMD(0x1)

/* Handled by object cmd */

/* LTTng-UST commands */
#define LTTNG_UST_SESSION               _UST_CMD(0x40)
#define LTTNG_UST_TRACER_VERSION        \
	_UST_CMDR(0x41, struct lttng_ust_tracer_version)
#define LTTNG_UST_TRACEPOINT_LIST       _UST_CMD(0x42)
#define LTTNG_UST_WAIT_QUIESCENT        _UST_CMD(0x43)
#define LTTNG_UST_REGISTER_DONE         _UST_CMD(0x44)

/* Session FD ioctl */
#define LTTNG_UST_METADATA             \
	_UST_CMDW(0x50, struct lttng_ust_channel)
#define LTTNG_UST_CHANNEL              \
	_UST_CMDW(0x51, struct lttng_ust_channel)
#define LTTNG_UST_SESSION_START        _UST_CMD(0x52)
#define LTTNG_UST_SESSION_STOP         _UST_CMD(0x53)

/* Channel FD ioctl */
#define LTTNG_UST_STREAM               _UST_CMD(0x60)
#define LTTNG_UST_EVENT                \
	_UST_CMDW(0x61, struct lttng_ust_event)

/* Event and Channel FD ioctl */
#define LTTNG_UST_CONTEXT              \
	_UST_CMDW(0x70, struct lttng_ust_context)

/* Event, Channel and Session ioctl */
#define LTTNG_UST_ENABLE               _UST_CMD(0x80)
#define LTTNG_UST_DISABLE              _UST_CMD(0x81)

#define LTTNG_UST_ROOT_HANDLE          0

#endif /* _LTTNG_UST_H */
