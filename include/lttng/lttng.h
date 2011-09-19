/*
 * lttng.h
 *
 * Linux Trace Toolkit Control Library Header File
 *
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; only
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _LTTNG_H
#define _LTTNG_H

#include <limits.h>
#include <stdint.h>
#include <sys/types.h>

/* Default unix group name for tracing. */
#define LTTNG_DEFAULT_TRACING_GROUP "tracing"

/* Environment variable to set session daemon binary path. */
#define LTTNG_SESSIOND_PATH_ENV "LTTNG_SESSIOND_PATH"

/* Default trace output directory name */
#define LTTNG_DEFAULT_TRACE_DIR_NAME "lttng-traces"

/*
 * Event symbol length. Copied from LTTng kernel ABI.
 */
#define LTTNG_SYMBOL_NAME_LEN 128

/*
 * Every lttng_event_* structure both apply to kernel event and user-space
 * event.
 */

/*
 * Domain type are the different possible tracers.
 */
enum lttng_domain_type {
	LTTNG_DOMAIN_KERNEL                   = 1,
	LTTNG_DOMAIN_UST                      = 2,
	LTTNG_DOMAIN_UST_EXEC_NAME            = 3,
	LTTNG_DOMAIN_UST_PID                  = 4,
	LTTNG_DOMAIN_UST_PID_FOLLOW_CHILDREN  = 5,
};

/*
 * Instrumentation type of tracing event.
 */
enum lttng_event_type {
	LTTNG_EVENT_TRACEPOINT,
	LTTNG_EVENT_PROBE,
	LTTNG_EVENT_FUNCTION,
	LTTNG_EVENT_FUNCTION_ENTRY,
	LTTNG_EVENT_NOOP,
	LTTNG_EVENT_SYSCALL,
};

/*
 * LTTng consumer mode
 */
enum lttng_event_output {
	LTTNG_EVENT_SPLICE = 0,
	LTTNG_EVENT_MMAP   = 1,
};

/* Event context possible type */
enum lttng_event_context_type {
	LTTNG_EVENT_CONTEXT_PID                = 0,
	LTTNG_EVENT_CONTEXT_PERF_COUNTER       = 1,
	LTTNG_EVENT_CONTEXT_COMM               = 2,
	LTTNG_EVENT_CONTEXT_PRIO               = 3,
	LTTNG_EVENT_CONTEXT_NICE               = 4,
	LTTNG_EVENT_CONTEXT_VPID               = 5,
	LTTNG_EVENT_CONTEXT_TID                = 6,
	LTTNG_EVENT_CONTEXT_VTID               = 7,
	LTTNG_EVENT_CONTEXT_PPID               = 8,
	LTTNG_EVENT_CONTEXT_VPPID              = 9,
};

enum lttng_calibrate_type {
	LTTNG_CALIBRATE_FUNCTION               = 0,
};

struct lttng_domain {
	enum lttng_domain_type type;
	union {
		pid_t pid;
		char exec_name[NAME_MAX];
	} attr;
};

/* Perf counter attributes */
struct lttng_event_perf_counter_ctx {
	uint32_t type;
	uint64_t config;
	char name[LTTNG_SYMBOL_NAME_LEN];
};

/* Event/Channel context */
struct lttng_event_context {
	enum lttng_event_context_type ctx;
	union {
		struct lttng_event_perf_counter_ctx perf_counter;
	} u;
};

/*
 * Event probe.
 *
 * Either addr is used or symbol_name and offset.
 */
struct lttng_event_probe_attr {
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
	uint32_t enabled;
	/* Per event type configuration */
	union {
		struct lttng_event_probe_attr probe;
		struct lttng_event_function_attr ftrace;
	} attr;
};

/*
 * Tracer channel attributes. For both kernel and user-space.
 */
struct lttng_channel_attr {
	int overwrite;                      /* 1: overwrite, 0: discard */
	uint64_t subbuf_size;               /* bytes */
	uint64_t num_subbuf;                /* power of 2 */
	unsigned int switch_timer_interval; /* usec */
	unsigned int read_timer_interval;   /* usec */
	enum lttng_event_output output;     /* splice, mmap */
};

/*
 * Channel information structure. For both kernel and user-space.
 */
struct lttng_channel {
	char name[NAME_MAX];
	uint32_t enabled;
	struct lttng_channel_attr attr;
};

struct lttng_calibrate {
	enum lttng_calibrate_type type;
};

/*
 * Basic session information.
 *
 * This is an 'output data' meaning that it only comes *from* the session
 * daemon *to* the lttng client. It's basically a 'human' representation of
 * tracing entities (here a session).
 */
struct lttng_session {
	char name[NAME_MAX];
	/* The path where traces are written */
	char path[PATH_MAX];
};

/*
 * Handle used as a context for commands.
 */
struct lttng_handle {
	char session_name[NAME_MAX];
	struct lttng_domain domain;
};

/*
 * Public LTTng control API
 *
 * For functions having a lttng domain type as parameter, if a bad value is
 * given, NO default is applied and an error is returned.
 *
 * On success, all functions of the API return 0 or the size of the allocated
 * array.
 *
 * On error, a negative value is returned being a specific lttng-tools error
 * code which can be humanly interpreted with lttng_get_readable_code(err).
 */

/*
 * Create an handle used as a context for every request made to the library.
 *
 * This handle contains the session name and lttng domain on which the command
 * will be executed on.
 */
extern struct lttng_handle *lttng_create_handle(const char *session_name,
		struct lttng_domain *domain);

/*
 * Destroy an handle. This will simply free(3) the data pointer returned by
 * lttng_create_handle() and rendering it unsuable.
 */
extern void lttng_destroy_handle(struct lttng_handle *handle);

/*
 * Create tracing session using a name and a path where trace will be written.
 */
extern int lttng_create_session(const char *name, const char *path);

/*
 * Destroy tracing session.
 *
 * The session will not be useable anymore, tracing will stopped for all
 * registered trace and tracing buffers will be flushed.
 */
extern int lttng_destroy_session(struct lttng_handle *handle);

/*
 * List all tracing sessions.
 *
 * Return the size of the "lttng_session" array. Caller must free(3).
 */
extern int lttng_list_sessions(struct lttng_session **sessions);

/*
 * List registered domain(s) of a session.
 *
 * Return the size of the "lttng_domain" array. Caller must free(3).
 */
extern int lttng_list_domains(struct lttng_handle *handle,
		struct lttng_domain **domains);

/*
 * List channel(s) of a session.
 *
 * Return the size of the "lttng_channel" array. Caller must free(3).
 */
extern int lttng_list_channels(struct lttng_handle *handle,
		struct lttng_channel **channels);

/*
 * List event(s) of a session channel.
 *
 * Return the size of the "lttng_event" array. Caller must free(3).
 */
extern int lttng_list_events(struct lttng_handle *handle,
		const char *channel_name, struct lttng_event **events);

/*
 * List available tracepoints of a specific lttng domain.
 *
 * Return the size of the "lttng_event" array. Caller must free(3).
 */
extern int lttng_list_tracepoints(struct lttng_handle *handle,
		struct lttng_event **events);

/*
 * Check if a session daemon is alive.
 */
extern int lttng_session_daemon_alive(void);

/*
 * Set tracing group for the *current* flow of execution.
 */
extern int lttng_set_tracing_group(const char *name);

/*
 * Return a human readable error message of a lttng-tools error code.
 *
 * Parameter MUST be a negative value or else you'll get a generic message.
 */
extern const char *lttng_get_readable_code(int code);

/*
 * This call permits to register an "outside consumer" to a session and a lttng
 * domain. No consumer will be spawned and all fds/commands will go through the
 * socket path given (socket_path).
 *
 * NOTE: At the moment, if you use the liblttngkconsumerd, you can only use the
 * command socket. The error socket is not supported yet for roaming consumers.
 */
extern int lttng_register_consumer(struct lttng_handle *handle,
		const char *socket_path);

/*
 * Start tracing for *all* registered trace (kernel and user-space).
 */
extern int lttng_start_tracing(struct lttng_handle *handle);

/*
 * Stop tracing for *all* registered trace (kernel and user-space).
 */
extern int lttng_stop_tracing(struct lttng_handle *handle);

/*
 * Add context to event for a specific channel.
 *
 * If event_name is NULL, the context is applied to all event of the channel.
 * If channel_name is NULL, a lookup of the event's channel is done.
 * If both are NULL, the context is applied on all events of all channels.
 */
extern int lttng_add_context(struct lttng_handle *handle,
		struct lttng_event_context *ctx, const char *event_name,
		const char *channel_name);

/*
 * Create or enable a kernel event.
 *
 * If the event you are trying to enable does not exist, it will be created,
 * else it is enabled.
 *
 * If channel_name is NULL, the default channel is used (channel0).
 */
extern int lttng_enable_event(struct lttng_handle *handle,
		struct lttng_event *ev, const char *channel_name);

/*
 * Create or enable a kernel channel.
 *
 * If name is NULL, the default channel is enabled (channel0).
 */
extern int lttng_enable_channel(struct lttng_handle *handle,
		struct lttng_channel *chan);

/*
 * Disable kernel event.
 *
 * If channel_name is NULL, the default channel is used (channel0).
 */
extern int lttng_disable_event(struct lttng_handle *handle,
		const char *name, const char *channel_name);

/*
 * Disable kernel channel.
 *
 * If channel_name is NULL, the default channel is disabled (channel0).
 */
extern int lttng_disable_channel(struct lttng_handle *handle,
		const char *name);

/*
 * Calibrate LTTng overhead.
 */
extern int lttng_calibrate(struct lttng_handle *handle,
		struct lttng_calibrate *calibrate);

#endif /* _LTTNG_H */
