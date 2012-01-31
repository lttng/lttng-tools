/*
 * lttng.h
 *
 * Linux Trace Toolkit Control Library Header File
 *
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; only version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _LTTNG_H
#define _LTTNG_H

#include <limits.h>
#include <stdint.h>
#include <sys/types.h>

/*
 * Event symbol length. Copied from LTTng kernel ABI.
 */
#define LTTNG_SYMBOL_NAME_LEN 256

/*
 * Every lttng_event_* structure both apply to kernel event and user-space
 * event.
 */

/*
 * Domain types: the different possible tracers.
 */
enum lttng_domain_type {
	LTTNG_DOMAIN_KERNEL                   = 1,
	LTTNG_DOMAIN_UST                      = 2,

	/*
	 * For now, the domains below are not implemented. However, we keep them
	 * here in order to retain their enum values for future development. Note
	 * that it is on the roadmap to implement them.
	 *
	LTTNG_DOMAIN_UST_EXEC_NAME            = 3,
	LTTNG_DOMAIN_UST_PID                  = 4,
	LTTNG_DOMAIN_UST_PID_FOLLOW_CHILDREN  = 5,
	*/
};

/*
 * Instrumentation type of tracing event.
 */
enum lttng_event_type {
	LTTNG_EVENT_ALL                       = -1,
	LTTNG_EVENT_TRACEPOINT                = 0,
	LTTNG_EVENT_PROBE                     = 1,
	LTTNG_EVENT_FUNCTION                  = 2,
	LTTNG_EVENT_FUNCTION_ENTRY            = 3,
	LTTNG_EVENT_NOOP                      = 4,
	LTTNG_EVENT_SYSCALL                   = 5,
};

/*
 * Loglevel information.
 */
enum lttng_loglevel_type {
	LTTNG_EVENT_LOGLEVEL                  = 0,
	LTTNG_EVENT_LOGLEVEL_ONLY             = 1,
};

/*
 * LTTng consumer mode
 */
enum lttng_event_output {
	LTTNG_EVENT_SPLICE                    = 0,
	LTTNG_EVENT_MMAP                      = 1,
};

/* Event context possible type */
enum lttng_event_context_type {
	LTTNG_EVENT_CONTEXT_PID               = 0,
	LTTNG_EVENT_CONTEXT_PERF_COUNTER      = 1,
	LTTNG_EVENT_CONTEXT_PROCNAME          = 2,
	LTTNG_EVENT_CONTEXT_PRIO              = 3,
	LTTNG_EVENT_CONTEXT_NICE              = 4,
	LTTNG_EVENT_CONTEXT_VPID              = 5,
	LTTNG_EVENT_CONTEXT_TID               = 6,
	LTTNG_EVENT_CONTEXT_VTID              = 7,
	LTTNG_EVENT_CONTEXT_PPID              = 8,
	LTTNG_EVENT_CONTEXT_VPPID             = 9,
	LTTNG_EVENT_CONTEXT_PTHREAD_ID        = 10,
};

enum lttng_calibrate_type {
	LTTNG_CALIBRATE_FUNCTION              = 0,
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
	enum lttng_event_type type;
	char name[LTTNG_SYMBOL_NAME_LEN];

	enum lttng_loglevel_type loglevel_type;
	char loglevel[LTTNG_SYMBOL_NAME_LEN];
	int64_t loglevel_value;		/* for printing */

	uint32_t enabled;
	pid_t pid;
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
	char name[LTTNG_SYMBOL_NAME_LEN];
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
	uint32_t enabled;	/* enabled/started: 1, disabled/stopped: 0 */
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
 * For functions having an lttng domain type as parameter, if a bad value is
 * given, NO default is applied and an error is returned.
 *
 * On success, all functions of the API return 0 or the size of the allocated
 * array (in bytes).
 *
 * On error, a negative value is returned being a specific lttng-tools error
 * code which can be humanly interpreted with lttng_strerror(err).
 *
 * Exceptions to this are noted below.
 */

/*
 * Create a handle used as a context for every request made to the library.
 *
 * This handle contains the session name and lttng domain on which the command
 * will be executed.
 * The returned pointer will be NULL in case of malloc() error.
 */
extern struct lttng_handle *lttng_create_handle(const char *session_name,
		struct lttng_domain *domain);

/*
 * Destroy a handle. This will simply free(3) the data pointer returned by
 * lttng_create_handle(), rendering it unusable.
 */
extern void lttng_destroy_handle(struct lttng_handle *handle);

/*
 * Create a tracing session using a name and a path where the trace will be
 * written.
 */
extern int lttng_create_session(const char *name, const char *path);

/*
 * Destroy a tracing session.
 *
 * The session will not be usable anymore, tracing will be stopped for all
 * registered traces, and the tracing buffers will be flushed.
 */
extern int lttng_destroy_session(const char *name);

/*
 * List all the tracing sessions.
 *
 * Return the size (number of entries) of the "lttng_session" array. Caller
 * must free(3).
 */
extern int lttng_list_sessions(struct lttng_session **sessions);

/*
 * List the registered domain(s) of a session.
 *
 * Return the size (number of entries) of the "lttng_domain" array. Caller
 * must free(3).
 */
extern int lttng_list_domains(const char *session_name,
		struct lttng_domain **domains);

/*
 * List the channel(s) of a session.
 *
 * Return the size (number of entries) of the "lttng_channel" array. Caller
 * must free(3).
 */
extern int lttng_list_channels(struct lttng_handle *handle,
		struct lttng_channel **channels);

/*
 * List the event(s) of a session channel.
 *
 * Return the size (number of entries) of the "lttng_event" array.
 * Caller must free(3).
 */
extern int lttng_list_events(struct lttng_handle *handle,
		const char *channel_name, struct lttng_event **events);

/*
 * List the available tracepoints of a specific lttng domain.
 *
 * Return the size (number of entries) of the "lttng_event" array.
 * Caller must free(3).
 */
extern int lttng_list_tracepoints(struct lttng_handle *handle,
		struct lttng_event **events);

/*
 * Check if a session daemon is alive.
 *
 * Return 1 if alive or 0 if not. On error returns a negative value.
 */
extern int lttng_session_daemon_alive(void);

/*
 * Set the tracing group for the *current* flow of execution.
 *
 * On success, returns 0, on error, returns -1 (null name) or -ENOMEM.
 */
extern int lttng_set_tracing_group(const char *name);

/*
 * Return a human-readable error message for an lttng-tools error code.
 *
 * Parameter MUST be a negative value or else you'll get a generic message.
 */
extern const char *lttng_strerror(int code);

/*
 * This call registers an "outside consumer" for a session and an lttng domain.
 * No consumer will be spawned and all fds/commands will go through the socket
 * path given (socket_path).
 *
 * NOTE: At the moment, if you use the liblttng-kconsumer, you can only use the
 * command socket. The error socket is not supported yet for roaming consumers.
 */
extern int lttng_register_consumer(struct lttng_handle *handle,
		const char *socket_path);

/*
 * Start tracing for *all* registered traces (kernel and user-space).
 */
extern int lttng_start_tracing(const char *session_name);

/*
 * Stop tracing for *all* registered traces (kernel and user-space).
 */
extern int lttng_stop_tracing(const char *session_name);

/*
 * Add context to event(s) for a specific channel (or for all).
 *
 * If event_name is NULL, the context is applied to all events of the channel.
 * If channel_name is NULL, a lookup of the event's channel is done.
 * If both are NULL, the context is applied to all events of all channels.
 */
extern int lttng_add_context(struct lttng_handle *handle,
		struct lttng_event_context *ctx, const char *event_name,
		const char *channel_name);

/*
 * Create or enable a kernel event (or events) for a channel.
 *
 * If the event you are trying to enable does not exist, it will be created,
 * else it is enabled.
 * If event_name is NULL, all events are enabled.
 * If channel_name is NULL, the default channel is used (channel0).
 */
extern int lttng_enable_event(struct lttng_handle *handle,
		struct lttng_event *ev, const char *channel_name);

/*
 * Create or enable a kernel channel.
 * The channel name cannot be NULL.
 */
extern int lttng_enable_channel(struct lttng_handle *handle,
		struct lttng_channel *chan);

/*
 * Disable kernel event(s) of a channel and domain.
 *
 * If event_name is NULL, all events are disabled.
 * If channel_name is NULL, the default channel is used (channel0).
 */
extern int lttng_disable_event(struct lttng_handle *handle,
		const char *name, const char *channel_name);

/*
 * Disable kernel channel.
 *
 * The channel name cannot be NULL.
 */
extern int lttng_disable_channel(struct lttng_handle *handle,
		const char *name);

/*
 * Calibrate LTTng overhead.
 */
extern int lttng_calibrate(struct lttng_handle *handle,
		struct lttng_calibrate *calibrate);

/*
 * Set the default channel attributes for a specific domain and an allocated
 * lttng_channel_attr pointer.
 *
 * If either or both of the arguments are NULL, nothing happens.
 */
extern void lttng_channel_set_default_attr(struct lttng_domain *domain,
		struct lttng_channel_attr *attr);

#endif /* _LTTNG_H */
