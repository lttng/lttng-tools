/*
 * lttng.h
 *
 * Linux Trace Toolkit Control Library Header File
 *
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef _LTTNG_H
#define _LTTNG_H

#include <asm/types.h>
#include <stdint.h>
#include <limits.h>

/* Default unix group name for tracing. */
#define LTTNG_DEFAULT_TRACING_GROUP "tracing"

/* Environment variable to set session daemon binary path. */
#define LTTNG_SESSIOND_PATH_ENV "LTTNG_SESSIOND_PATH"

/*
 * Event symbol length.
 */
#define LTTNG_SYMBOL_NAME_LEN 128

enum lttng_event_type {
	LTTNG_EVENT_TRACEPOINTS,
	LTTNG_EVENT_KPROBES,
	LTTNG_EVENT_FUNCTION,
};

/* Kernel context possible type */
enum lttng_kernel_context_type {
	LTTNG_KERNEL_CONTEXT_PID                = 0,
	LTTNG_KERNEL_CONTEXT_PERF_COUNTER       = 1,
	LTTNG_KERNEL_CONTEXT_COMM               = 2,
	LTTNG_KERNEL_CONTEXT_PRIO               = 3,
	LTTNG_KERNEL_CONTEXT_NICE               = 4,
	LTTNG_KERNEL_CONTEXT_VPID               = 5,
	LTTNG_KERNEL_CONTEXT_TID                = 6,
	LTTNG_KERNEL_CONTEXT_VTID               = 7,
	LTTNG_KERNEL_CONTEXT_PPID               = 8,
	LTTNG_KERNEL_CONTEXT_VPPID              = 9,
};

/* Perf counter attributes */
struct lttng_kernel_perf_counter_ctx {
	uint32_t type;
	uint64_t config;
	char name[LTTNG_SYMBOL_NAME_LEN];
};

/* Event/Channel context */
struct lttng_kernel_context {
	enum lttng_kernel_context_type ctx;
	union {
		struct lttng_kernel_perf_counter_ctx perf_counter;
	} u;
};

/*
 * LTTng consumer mode
 */
enum lttng_kernel_output {
	LTTNG_KERNEL_SPLICE       = 0,
	LTTNG_KERNEL_MMAP         = 1,
};

/*
 * Either addr is used or symbol_name and offset.
 */
struct lttng_event_kprobe_attr {
	uint64_t addr;

	uint64_t offset;
	char symbol_name[LTTNG_SYMBOL_NAME_LEN];
};

/*
 * Function tracer
 */
struct lttng_event_function_attr {
	char symbol_name[LTTNG_SYMBOL_NAME_LEN];
};

/*
 * Generic lttng event
 */
struct lttng_event {
	char name[LTTNG_SYMBOL_NAME_LEN];
	enum lttng_event_type type;
	/* Per event type configuration */
	union {
		struct lttng_event_kprobe_attr kprobe;
		struct lttng_event_function_attr ftrace;
	} attr;
};

/* Tracer channel attributes */
struct lttng_channel_attr {
	int overwrite;				/* 1: overwrite, 0: discard */
	uint64_t subbuf_size;			/* bytes */
	uint64_t num_subbuf;			/* power of 2 */
	unsigned int switch_timer_interval;	/* usec */
	unsigned int read_timer_interval;	/* usec */
	enum lttng_kernel_output output;	/* splice, mmap */
};

/*
 * Basic session information.
 */
struct lttng_session {
	char name[NAME_MAX];
	char path[PATH_MAX];
};

/* Channel information structure */
struct lttng_channel {
	char name[NAME_MAX];
	struct lttng_channel_attr attr;
};

/*
 * Session daemon control
 */
extern int lttng_connect_sessiond(void);

extern int lttng_create_session(char *name, char *path);

extern int lttng_destroy_session(char *name);

extern int lttng_disconnect_sessiond(void);

/* Return an allocated array of lttng_session */
extern int lttng_list_sessions(struct lttng_session **sessions);

extern int lttng_session_daemon_alive(void);

/* Set tracing group for the current execution */
extern int lttng_set_tracing_group(const char *name);

extern void lttng_set_session_name(char *name);

extern const char *lttng_get_readable_code(int code);

extern int lttng_start_tracing(char *session_name);

extern int lttng_stop_tracing(char *session_name);

//extern int lttng_ust_list_traceable_apps(pid_t **pids);

/*
 * LTTng Kernel tracer control
 */
extern int lttng_kernel_add_context(struct lttng_kernel_context *ctx,
		char *event_name, char *channel_name);

extern int lttng_kernel_create_channel(struct lttng_channel *chan);

extern int lttng_kernel_enable_event(struct lttng_event *ev, char *channel_name);

extern int lttng_kernel_enable_channel(char *name);

extern int lttng_kernel_disable_event(char *name, char *channel_name);

extern int lttng_kernel_disable_channel(char *name);

extern int lttng_kernel_list_events(char **event_list);

/*
 * LTTng User-space tracer control
 */

#endif /* _LTTNG_H */
