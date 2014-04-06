/*
 * lttng.h
 *
 * Linux Trace Toolkit Control Library Header File
 *
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License, version 2.1 only,
 * as published by the Free Software Foundation.
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

#ifndef LTTNG_H
#define LTTNG_H

#include <limits.h>
/*
 * Necessary to include the fixed width type limits on glibc versions older
 * than 2.18 when building with a C++ compiler.
 */
#ifndef __STDC_LIMIT_MACROS
#define __STDC_LIMIT_MACROS
#include <stdint.h>
#undef __STDC_LIMIT_MACROS
#else /* #ifndef __STDC_LIMIT_MACROS */
#include <stdint.h>
#endif /* #else #ifndef __STDC_LIMIT_MACROS */
#include <sys/types.h>

/* Error codes that can be returned by API calls */
#include <lttng/lttng-error.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Event symbol length. Copied from LTTng kernel ABI.
 */
#define LTTNG_SYMBOL_NAME_LEN             256

/*
 * Every lttng_event_* structure both apply to kernel event and user-space
 * event.
 */

/*
 * Domain types: the different possible tracers.
 */
enum lttng_domain_type {
	LTTNG_DOMAIN_KERNEL                   = 1,	/* Linux Kernel tracer. */
	LTTNG_DOMAIN_UST                      = 2,	/* Global Userspace tracer. */
	LTTNG_DOMAIN_JUL                      = 3,	/* Java Util Logging. */
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
	LTTNG_EVENT_LOGLEVEL_ALL              = 0,
	LTTNG_EVENT_LOGLEVEL_RANGE            = 1,
	LTTNG_EVENT_LOGLEVEL_SINGLE           = 2,
};

/*
 * Available loglevels.
 */
enum lttng_loglevel {
	LTTNG_LOGLEVEL_EMERG                  = 0,
	LTTNG_LOGLEVEL_ALERT                  = 1,
	LTTNG_LOGLEVEL_CRIT                   = 2,
	LTTNG_LOGLEVEL_ERR                    = 3,
	LTTNG_LOGLEVEL_WARNING                = 4,
	LTTNG_LOGLEVEL_NOTICE                 = 5,
	LTTNG_LOGLEVEL_INFO                   = 6,
	LTTNG_LOGLEVEL_DEBUG_SYSTEM           = 7,
	LTTNG_LOGLEVEL_DEBUG_PROGRAM          = 8,
	LTTNG_LOGLEVEL_DEBUG_PROCESS          = 9,
	LTTNG_LOGLEVEL_DEBUG_MODULE           = 10,
	LTTNG_LOGLEVEL_DEBUG_UNIT             = 11,
	LTTNG_LOGLEVEL_DEBUG_FUNCTION         = 12,
	LTTNG_LOGLEVEL_DEBUG_LINE             = 13,
	LTTNG_LOGLEVEL_DEBUG                  = 14,
};

/*
 * Available loglevels for the JUL domain. Those are an exact map from the
 * class java.util.logging.Level.
 */
enum lttng_loglevel_jul {
	LTTNG_LOGLEVEL_JUL_OFF                = INT32_MAX,
	LTTNG_LOGLEVEL_JUL_SEVERE             = 1000,
	LTTNG_LOGLEVEL_JUL_WARNING            = 900,
	LTTNG_LOGLEVEL_JUL_INFO               = 800,
	LTTNG_LOGLEVEL_JUL_CONFIG             = 700,
	LTTNG_LOGLEVEL_JUL_FINE               = 500,
	LTTNG_LOGLEVEL_JUL_FINER              = 400,
	LTTNG_LOGLEVEL_JUL_FINEST             = 300,
	LTTNG_LOGLEVEL_JUL_ALL                = INT32_MIN,
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
	LTTNG_EVENT_CONTEXT_HOSTNAME          = 11,
	LTTNG_EVENT_CONTEXT_IP                = 12,
};

enum lttng_calibrate_type {
	LTTNG_CALIBRATE_FUNCTION              = 0,
};

/* Health component for the health check function. */
enum lttng_health_component {
	LTTNG_HEALTH_CMD,
	LTTNG_HEALTH_APP_MANAGE,
	LTTNG_HEALTH_APP_REG,
	LTTNG_HEALTH_KERNEL,
	LTTNG_HEALTH_CONSUMER,
	LTTNG_HEALTH_HT_CLEANUP,
	LTTNG_HEALTH_APP_MANAGE_NOTIFY,
	LTTNG_HEALTH_APP_REG_DISPATCH,
	LTTNG_HEALTH_ALL,
};

/* Buffer type for a specific domain. */
enum lttng_buffer_type {
	LTTNG_BUFFER_PER_PID,	/* Only supported by UST being the default. */
	LTTNG_BUFFER_PER_UID,	/* Only supported by UST. */
	LTTNG_BUFFER_GLOBAL,	/* Only supported by the Kernel. */
};

/* Machine interface output type */
enum lttng_mi_output_type {
	LTTNG_MI_XML                          = 1 /* XML output */
};

/*
 * The structures should be initialized to zero before use.
 */
#define LTTNG_DOMAIN_PADDING1              12
#define LTTNG_DOMAIN_PADDING2              LTTNG_SYMBOL_NAME_LEN + 32
struct lttng_domain {
	enum lttng_domain_type type;
	enum lttng_buffer_type buf_type;
	char padding[LTTNG_DOMAIN_PADDING1];

	union {
		pid_t pid;
		char exec_name[NAME_MAX];
		char padding[LTTNG_DOMAIN_PADDING2];
	} attr;
};

/*
 * Perf counter attributes
 *
 * The structures should be initialized to zero before use.
 */
#define LTTNG_PERF_EVENT_PADDING1          16
struct lttng_event_perf_counter_ctx {
	uint32_t type;
	uint64_t config;
	char name[LTTNG_SYMBOL_NAME_LEN];

	char padding[LTTNG_PERF_EVENT_PADDING1];
};

/*
 * Event/channel context
 *
 * The structures should be initialized to zero before use.
 */
#define LTTNG_EVENT_CONTEXT_PADDING1       16
#define LTTNG_EVENT_CONTEXT_PADDING2       LTTNG_SYMBOL_NAME_LEN + 32
struct lttng_event_context {
	enum lttng_event_context_type ctx;
	char padding[LTTNG_EVENT_CONTEXT_PADDING1];

	union {
		struct lttng_event_perf_counter_ctx perf_counter;
		char padding[LTTNG_EVENT_CONTEXT_PADDING2];
	} u;
};

/*
 * Event probe.
 *
 * Either addr is used or symbol_name and offset.
 *
 * The structures should be initialized to zero before use.
 */
#define LTTNG_EVENT_PROBE_PADDING1         16
struct lttng_event_probe_attr {
	uint64_t addr;

	uint64_t offset;
	char symbol_name[LTTNG_SYMBOL_NAME_LEN];

	char padding[LTTNG_EVENT_PROBE_PADDING1];
};

/*
 * Function tracer
 *
 * The structures should be initialized to zero before use.
 */
#define LTTNG_EVENT_FUNCTION_PADDING1      16
struct lttng_event_function_attr {
	char symbol_name[LTTNG_SYMBOL_NAME_LEN];

	char padding[LTTNG_EVENT_FUNCTION_PADDING1];
};

/*
 * Generic lttng event
 *
 * The structures should be initialized to zero before use.
 */
#define LTTNG_EVENT_PADDING1               14
#define LTTNG_EVENT_PADDING2               LTTNG_SYMBOL_NAME_LEN + 32
struct lttng_event {
	enum lttng_event_type type;
	char name[LTTNG_SYMBOL_NAME_LEN];

	enum lttng_loglevel_type loglevel_type;
	int loglevel;

	int32_t enabled;	/* Does not apply: -1 */
	pid_t pid;
	unsigned char filter;	/* filter enabled ? */
	unsigned char exclusion; /* exclusions added ? */

	char padding[LTTNG_EVENT_PADDING1];

	/* Per event type configuration */
	union {
		struct lttng_event_probe_attr probe;
		struct lttng_event_function_attr ftrace;

		char padding[LTTNG_EVENT_PADDING2];
	} attr;
};

enum lttng_event_field_type {
	LTTNG_EVENT_FIELD_OTHER			= 0,
	LTTNG_EVENT_FIELD_INTEGER		= 1,
	LTTNG_EVENT_FIELD_ENUM			= 2,
	LTTNG_EVENT_FIELD_FLOAT			= 3,
	LTTNG_EVENT_FIELD_STRING		= 4,
};

#define LTTNG_EVENT_FIELD_PADDING	LTTNG_SYMBOL_NAME_LEN + 32
struct lttng_event_field {
	char field_name[LTTNG_SYMBOL_NAME_LEN];
	enum lttng_event_field_type type;
	char padding[LTTNG_EVENT_FIELD_PADDING];
	struct lttng_event event;
	int nowrite;
};

/*
 * Tracer channel attributes. For both kernel and user-space.
 *
 * The structures should be initialized to zero before use.
 */
#define LTTNG_CHANNEL_ATTR_PADDING1        LTTNG_SYMBOL_NAME_LEN + 12
struct lttng_channel_attr {
	int overwrite;                      /* 1: overwrite, 0: discard */
	uint64_t subbuf_size;               /* bytes */
	uint64_t num_subbuf;                /* power of 2 */
	unsigned int switch_timer_interval; /* usec */
	unsigned int read_timer_interval;   /* usec */
	enum lttng_event_output output;     /* splice, mmap */
	/* LTTng 2.1 padding limit */
	uint64_t tracefile_size;            /* bytes */
	uint64_t tracefile_count;           /* number of tracefiles */
	/* LTTng 2.3 padding limit */
	unsigned int live_timer_interval;   /* usec */

	char padding[LTTNG_CHANNEL_ATTR_PADDING1];
};

/*
 * Channel information structure. For both kernel and user-space.
 *
 * The structures should be initialized to zero before use.
 */
#define LTTNG_CHANNEL_PADDING1             16
struct lttng_channel {
	char name[LTTNG_SYMBOL_NAME_LEN];
	uint32_t enabled;
	struct lttng_channel_attr attr;

	char padding[LTTNG_CHANNEL_PADDING1];
};

#define LTTNG_CALIBRATE_PADDING1           16
struct lttng_calibrate {
	enum lttng_calibrate_type type;

	char padding[LTTNG_CALIBRATE_PADDING1];
};

/*
 * Basic session information.
 *
 * This is an 'output data' meaning that it only comes *from* the session
 * daemon *to* the lttng client. It's basically a 'human' representation of
 * tracing entities (here a session).
 *
 * The structures should be initialized to zero before use.
 */
#define LTTNG_SESSION_PADDING1             12
struct lttng_session {
	char name[NAME_MAX];
	/* The path where traces are written */
	char path[PATH_MAX];
	uint32_t enabled;	/* enabled/started: 1, disabled/stopped: 0 */
	uint32_t snapshot_mode;
	unsigned int live_timer_interval;	/* usec */

	char padding[LTTNG_SESSION_PADDING1];
};

/*
 * Handle used as a context for commands.
 *
 * The structures should be initialized to zero before use.
 */
#define LTTNG_HANDLE_PADDING1              16
struct lttng_handle {
	char session_name[NAME_MAX];
	struct lttng_domain domain;

	char padding[LTTNG_HANDLE_PADDING1];
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
 * Destroy an handle.
 *
 * It free(3) the data pointer returned by lttng_create_handle(), rendering it
 * unusable.
 */
extern void lttng_destroy_handle(struct lttng_handle *handle);

/*
 * Create a tracing session using a name and an optional URL.
 *
 * If _url_ is NULL, no consumer is created for the session. The name can't be
 * NULL here.
 */
extern int lttng_create_session(const char *name, const char *url);

/*
 * Create a tracing session that will exclusively be used for snapshot meaning
 * the session will be in no output mode and every channel enabled for that
 * session will be set in overwrite mode and in mmap output since splice is not
 * supported.
 *
 * If an url is given, it will be used to create a default snapshot output
 * using it as a destination. If NULL, no output will be defined and an
 * add-output call will be needed.
 *
 * Name can't be NULL.
 */
extern int lttng_create_session_snapshot(const char *name,
		const char *snapshot_url);

/*
 * Create a session exclusively used for live reading.
 *
 * In this mode, the switch-timer parameter is forced for each UST channel, a
 * live-switch-timer is enabled for kernel channels, manually setting
 * switch-timer is forbidden. Synchronization beacons are sent to the relayd,
 * indexes are sent and metadata is checked for each packet.
 *
 * Returns LTTNG_OK on success or a negative error code.
 */
extern int lttng_create_session_live(const char *name, const char *url,
		unsigned int timer_interval);

/*
 * Destroy a tracing session.
 *
 * The session will not be usable anymore, tracing will be stopped for all
 * registered traces, and the tracing buffers will be flushed.
 *
 * The name can't be NULL here.
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
 * List the available tracepoints fields of a specific lttng domain.
 *
 * Return the size (number of entries) of the "lttng_event_field" array.
 * Caller must free(3).
 */
extern int lttng_list_tracepoint_fields(struct lttng_handle *handle,
		struct lttng_event_field **fields);

/*
 * Check if a session daemon is alive.
 *
 * Return 1 if alive or 0 if not. On error returns a negative value.
 */
extern int lttng_session_daemon_alive(void);

/*
 * Set the tracing group for the *current* flow of execution.
 *
 * On success, returns 0 else a negative value on error being a lttng error
 * code found in lttng-error.h
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
 *
 * This call will wait for data availability for each domain of the session so
 * this can take an abritrary amount of time. However, when returning you have
 * the guarantee that the data is ready to be read and analyse. Use the
 * _no_wait call below to avoid this behavior.
 *
 * The session_name can't be NULL.
 */
extern int lttng_stop_tracing(const char *session_name);

/*
 * Behave exactly like lttng_stop_tracing but does not wait for data
 * availability.
 */
extern int lttng_stop_tracing_no_wait(const char *session_name);

/*
 * Add context to event(s) for a specific channel (or for all).
 *
 * If channel_name is NULL, a lookup of the event's channel is done. If both
 * are NULL, the context is applied to all events of all channels.
 *
 * Note that whatever event_name value is, a context can not be added to an
 * event, so we just ignore it for now.
 */
extern int lttng_add_context(struct lttng_handle *handle,
		struct lttng_event_context *ctx, const char *event_name,
		const char *channel_name);

/*
 * Create or enable an event (or events) for a channel.
 *
 * If the event you are trying to enable does not exist, it will be created,
 * else it is enabled.
 * If channel_name is NULL, the default channel is used (channel0).
 *
 * The handle and ev params can not be NULL.
 */
extern int lttng_enable_event(struct lttng_handle *handle,
		struct lttng_event *ev, const char *channel_name);

/*
 * Create or enable an event with a specific filter.
 *
 * If the event you are trying to enable does not exist, it will be created,
 * else it is enabled.
 * If ev is NULL, all events are enabled with that filter.
 * If channel_name is NULL, the default channel is used (channel0) and created
 * if not found.
 * If filter_expression is NULL, an event without associated filter is
 * created.
 */
extern int lttng_enable_event_with_filter(struct lttng_handle *handle,
		struct lttng_event *event, const char *channel_name,
		const char *filter_expression);

/*
 * Create or enable an event with a filter and/or exclusions.
 *
 * If the event you are trying to enable does not exist, it will be created,
 * else it is enabled.
 * If ev is NULL, all events are enabled with the filter and exclusion options.
 * If channel_name is NULL, the default channel is used (channel0) and created
 * if not found.
 * If filter_expression is NULL, an event without associated filter is
 * created.
 * If exclusion count is zero, the event will be created without exclusions.
 */
extern int lttng_enable_event_with_exclusions(struct lttng_handle *handle,
		struct lttng_event *event, const char *channel_name,
		const char *filter_expression,
		int exclusion_count, char **exclusion_names);

/*
 * Create or enable a channel.
 *
 * The chan and handle params can not be NULL.
 */
extern int lttng_enable_channel(struct lttng_handle *handle,
		struct lttng_channel *chan);

/*
 * Disable event(s) of a channel and domain.
 *
 * If name is NULL, all events are disabled.
 * If channel_name is NULL, the default channel is used (channel0).
 */
extern int lttng_disable_event(struct lttng_handle *handle,
		const char *name, const char *channel_name);

/*
 * Disable channel.
 *
 */
extern int lttng_disable_channel(struct lttng_handle *handle,
		const char *name);

/*
 * Calibrate LTTng overhead.
 *
 * The chan and handle params can not be NULL.
 */
extern int lttng_calibrate(struct lttng_handle *handle,
		struct lttng_calibrate *calibrate);

/*
 * Set the default channel attributes for a specific domain and an allocated
 * lttng_channel_attr pointer.
 *
 * If one or both arguments are NULL, nothing happens.
 */
extern void lttng_channel_set_default_attr(struct lttng_domain *domain,
		struct lttng_channel_attr *attr);

/*
 * Set URL for a consumer for a session and domain.
 *
 * Both data and control URL must be defined. If both URLs are the same, only
 * the control URL is used even for network streaming.
 *
 * Default port are 5342 and 5343 respectively for control and data which uses
 * the TCP protocol.
 */
extern int lttng_set_consumer_url(struct lttng_handle *handle,
		const char *control_url, const char *data_url);

/*
 * Enable the consumer for a session and domain.
 */
extern LTTNG_DEPRECATED("This call is now obsolete.")
int lttng_enable_consumer(struct lttng_handle *handle);

/*
 * Disable consumer for a session and domain.
 */
extern LTTNG_DEPRECATED("This call is now obsolete.")
int lttng_disable_consumer(struct lttng_handle *handle);

/*
 * Check session daemon health for a specific component.
 *
 * Return 0 if health is OK or 1 if BAD. A returned value of -1 indicate that
 * the control library was not able to connect to the session daemon health
 * socket.
 *
 * Any other positive value is an lttcomm error which can be translate with
 * lttng_strerror().
 *
 * Please see lttng-health-check(3) man page for more information.
 */
extern LTTNG_DEPRECATED("This call is now obsolete.")
int lttng_health_check(enum lttng_health_component c);

/*
 * For a given session name, this call checks if the data is ready to be read
 * or is still being extracted by the consumer(s) (pending) hence not ready to
 * be used by any readers.
 *
 * Return 0 if there is _no_ data pending in the buffers thus having a
 * guarantee that the data can be read safely. Else, return 1 if there is still
 * traced data is pending. On error, a negative value is returned and readable
 * by lttng_strerror().
 */
extern int lttng_data_pending(const char *session_name);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_H */
