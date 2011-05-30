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

#include <limits.h>
#include <uuid/uuid.h>

/* Default unix group name for tracing. */
#define LTTNG_DEFAULT_TRACING_GROUP "tracing"

/* Environment variable to set session daemon binary path. */
#define LTTNG_SESSIOND_PATH_ENV "LTTNG_SESSIOND_PATH"

/*
 * Trace type for lttng_trace.
 */
enum lttng_trace_type {
	KERNEL,
	USERSPACE,
};

/*
 * Basic trace information exposed.
 */
struct lttng_trace {
	char name[NAME_MAX];
	pid_t pid;      /* Only useful for user-space trace */
	enum lttng_trace_type type;
};

/*
 * Basic session information exposed.
 */
struct lttng_session {
	char name[NAME_MAX];
	uuid_t uuid;
};

/*
 * Session daemon control
 */
extern int lttng_connect_sessiond(void);
extern int lttng_create_session(char *name);
extern int lttng_destroy_session(uuid_t *uuid);
extern int lttng_disconnect_sessiond(void);
/* Return an allocated array of lttng_session */
extern int lttng_list_sessions(struct lttng_session **sessions);
/* Return an allocated array of lttng_traces */
extern int lttng_list_traces(uuid_t *uuid, struct lttng_trace **traces);
extern int lttng_session_daemon_alive(void);
/* Set tracing group for the current execution */
extern int lttng_set_tracing_group(const char *name);
/* Set session uuid for the current execution */
extern void lttng_set_current_session_uuid(uuid_t *uuid);
extern const char *lttng_get_readable_code(int code);

/*
 * User-space tracer control
 */
extern int lttng_ust_create_trace(pid_t pid);
/* Return an allocated array of pids */
extern int lttng_ust_list_apps(pid_t **pids);
extern int lttng_ust_start_trace(pid_t pid);
extern int lttng_ust_stop_trace(pid_t pid);

/*
 * Kernel tracer control
 */
extern int lttng_kernel_create_channel(void);
extern int lttng_kernel_create_session(void);
extern int lttng_kernel_create_stream(void);
extern int lttng_kernel_disable_event(char *event_name);
extern int lttng_kernel_enable_event(char *event_name);
extern int lttng_kernel_list_events(char **event_list);
extern int lttng_kernel_open_metadata(void);
extern int lttng_kernel_start_tracing(void);
extern int lttng_kernel_stop_tracing(void);

#endif /* _LTTNG_H */
