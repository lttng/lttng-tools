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
#include <sys/types.h>
#include <stdint.h>
#include <limits.h>

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
	LTTNG_DOMAIN_KERNEL,
	LTTNG_DOMAIN_UST,
	LTTNG_DOMAIN_UST_EXEC_NAME,
	LTTNG_DOMAIN_UST_PID,
	LTTNG_DOMAIN_UST_PID_FOLLOW_CHILDREN,
};

struct lttng_domain {
	enum lttng_domain_type type;
	union {
		pid_t pid;
		char exec_name[NAME_MAX];
	} attr;
};

/*
 * Instrumentation type of tracing event.
 */
enum lttng_event_type {
	LTTNG_EVENT_TRACEPOINT,
	LTTNG_EVENT_PROBE,
	LTTNG_EVENT_FUNCTION,
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
	struct lttng_channel_attr attr;
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
 * Session daemon control
 */

/*
 * Create tracing session using a name and a path where trace will be written.
 */
extern int lttng_create_session(char *name, char *path);

/*
 * Destroy tracing session.
 *
 * The session will not be useable anymore, tracing will stopped for all
 * registered trace and tracing buffers will be flushed.
 */
extern int lttng_destroy_session(char *name);

/*
 * List tracing sessions.
 *
 * Return the size of the "lttng_session" array. Caller must free(3) the
 * returned data.
 */
extern int lttng_list_sessions(struct lttng_session **sessions);

/*
 * Check if a session daemon is alive.
 */
extern int lttng_session_daemon_alive(void);

/*
 * Set tracing group for the *current* flow of execution.
 */
extern int lttng_set_tracing_group(const char *name);

/*
 * Set the session name of the *current* flow of execution.
 *
 * This is a VERY important things to do before doing any tracing actions. If
 * it's not done, you'll get an error saying that the session is not found.
 * It avoids the use of a session name on every API call.
 */
extern void lttng_set_session_name(char *name);

/*
 * Return a human readable error message of a lttng-tools error code.
 *
 * Parameter MUST be a negative value or else you'll get a generic message.
 */
extern const char *lttng_get_readable_code(int code);

/*
 * Start tracing for *all* registered trace (kernel and user-space).
 */
extern int lttng_start_tracing(char *session_name);

/*
 * Stop tracing for *all* registered trace (kernel and user-space).
 */
extern int lttng_stop_tracing(char *session_name);

/*
 * Add context to event for a specific channel.
 *
 * If event_name is NULL, the context is applied to all event of the channel.
 * If channel_name is NULL, a lookup of the event's channel is done.
 * If both are NULL, the context is applied on all events of all channels.
 */

extern int lttng_add_context(struct lttng_domain *domain,
		struct lttng_event_context *ctx, char *event_name, char *channel_name);

/*
 * Create or enable a kernel event.
 *
 * If the event you are trying to enable does not exist, it will be created,
 * else it is enabled.
 *
 * If channel_name is NULL, the default channel is used (channel0).
 */
extern int lttng_enable_event(struct lttng_domain *domain, struct lttng_event *ev,
		char *channel_name);

/*
 * Create or enable a kernel channel.
 *
 * If name is NULL, the default channel is enabled (channel0).
 */
extern int lttng_enable_channel(struct lttng_domain *domain, struct lttng_channel *chan);

/*
 * Disable kernel event.
 *
 * If channel_name is NULL, the default channel is used (channel0).
 */
extern int lttng_disable_event(struct lttng_domain *domain, char *name,
		char *channel_name);

/*
 * Disable kernel channel.
 *
 * If channel_name is NULL, the default channel is disabled (channel0).
 */
extern int lttng_disable_channel(struct lttng_domain *domain, char *name);

/*
 * List kernel events.
 *
 * Return the size of the allocated event list. Caller must free(3) the data.
 */
extern int lttng_list_events(struct lttng_domain *domain, char **event_list);

#endif /* _LTTNG_H */
