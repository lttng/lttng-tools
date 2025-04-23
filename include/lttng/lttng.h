/*
 * lttng.h
 *
 * Linux Trace Toolkit Control Library Header File
 *
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_H
#define LTTNG_H

#include <lttng/lttng-export.h>

/* Error codes that can be returned by API calls */
#include <lttng/lttng-error.h>

/* Include every LTTng ABI/API available. */
#include <lttng/action/action.h>
#include <lttng/action/list.h>
#include <lttng/action/notify.h>
#include <lttng/action/path.h>
#include <lttng/action/rate-policy.h>
#include <lttng/action/rotate-session.h>
#include <lttng/action/snapshot-session.h>
#include <lttng/action/start-session.h>
#include <lttng/action/stop-session.h>
#include <lttng/channel.h>
#include <lttng/clear-handle.h>
#include <lttng/clear.h>
#include <lttng/condition/buffer-usage.h>
#include <lttng/condition/condition.h>
#include <lttng/condition/evaluation.h>
#include <lttng/condition/event-rule-matches.h>
#include <lttng/condition/session-consumed-size.h>
#include <lttng/condition/session-rotation.h>
#include <lttng/constant.h>
#include <lttng/destruction-handle.h>
#include <lttng/domain.h>
#include <lttng/endpoint.h>
#include <lttng/error-query.h>
#include <lttng/event-expr.h>
#include <lttng/event-field-value.h>
#include <lttng/event-rule/event-rule.h>
#include <lttng/event-rule/jul-logging.h>
#include <lttng/event-rule/kernel-kprobe.h>
#include <lttng/event-rule/kernel-syscall.h>
#include <lttng/event-rule/kernel-tracepoint.h>
#include <lttng/event-rule/kernel-uprobe.h>
#include <lttng/event-rule/log4j-logging.h>
#include <lttng/event-rule/log4j2-logging.h>
#include <lttng/event-rule/python-logging.h>
#include <lttng/event-rule/user-tracepoint.h>
#include <lttng/event.h>
#include <lttng/handle.h>
#include <lttng/health.h>
#include <lttng/kernel-probe.h>
#include <lttng/kernel.h>
#include <lttng/load.h>
#include <lttng/location.h>
#include <lttng/log-level-rule.h>
#include <lttng/lttng-error.h>
#include <lttng/notification/channel.h>
#include <lttng/notification/notification.h>
#include <lttng/rotation.h>
#include <lttng/save.h>
#include <lttng/session-descriptor.h>
#include <lttng/session.h>
#include <lttng/snapshot.h>
#include <lttng/tracker.h>
#include <lttng/trigger/trigger.h>
#include <lttng/userspace-probe.h>

#ifdef __cplusplus
extern "C" {
#endif

enum lttng_calibrate_type {
	LTTNG_CALIBRATE_FUNCTION = 0,
};

/* Machine interface output type */
enum lttng_mi_output_type {
	LTTNG_MI_XML = 1 /* XML output */
};

#define LTTNG_CALIBRATE_PADDING1 16
struct lttng_calibrate {
	enum lttng_calibrate_type type;

	char padding[LTTNG_CALIBRATE_PADDING1];
};

/*!
@brief
    Returns whether or not liblttng-ctl is able to connect to a
    listening session daemon.

@ingroup api_gen

How this function tries to
\ref api-gen-sessiond-conn "connect to a session daemon" depends on the
current Unix tracing group (initially \c tracing) of the library. Set
the tracing group with lttng_set_tracing_group().

@returns
    @parblock
    One of:

    <dl>
      <dt>1</dt>
      <dd>
	liblttng-ctl is able to connect to a session daemon.

      <dt>0
      <dd>
	liblttng-ctl isn't able to connect to a session daemon.

      <dt>\em Negative #lttng_error_code enumerator
      <dd>
	Error.
    </dl>
    @endparblock

@sa lttng_set_tracing_group() --
    Sets the current Unix tracing group of liblttng-ctl.
*/
LTTNG_EXPORT extern int lttng_session_daemon_alive(void);

/*!
@brief
    Sets the current Unix tracing group of liblttng-ctl to \lt_p{group}.

@ingroup api_gen

How the liblttng-ctl functions
\ref api-gen-sessiond-conn "connect to a session daemon" depends on
the current Unix tracing group (initially \c tracing) of the library.

@param[in] group
    New Unix tracing group of liblttng-ctl.

@returns
    <dl>
      <dt>0
      <dd>Success.

      <dt>-#LTTNG_ERR_INVALID (negative)
      <dd>Unsatisfied precondition.

      <dt>-#LTTNG_ERR_FATAL (negative)
      <dd>Out of memory.
    </dl>

@pre
    @lt_pre_not_null{group}
    - \lt_p{group} names an existing Unix group.
*/
LTTNG_EXPORT extern int lttng_set_tracing_group(const char *group);

/*
 * This call registers an "outside consumer" for a session and an lttng domain.
 * No consumer will be spawned and all fds/commands will go through the socket
 * path given (socket_path).
 *
 * NOTE that this is not recommended unless you absolutely know what you are
 * doing.
 *
 * Return 0 on success else a negative LTTng error code.
 */
LTTNG_EXPORT extern int lttng_register_consumer(struct lttng_handle *handle,
						const char *socket_path);

/*!
@brief
    Makes the recording session named \lt_p{session_name} active,
    starting all the tracers for its
    \ref api-channel-channel "channels".

@ingroup api_session

@note
    An #LTTNG_ACTION_TYPE_START_SESSION trigger action can also activate
    (start) a recording session.

@param[in] session_name
    Name of the recording session to activate/start.

@returns
    <dl>
      <dt>0 or a positive value
      <dd>Success

      <dt>\em Negative #lttng_error_code enumerator
      <dd>Error
    </dl>

@pre
    @lt_pre_conn
    @lt_pre_not_null{session_name}
    @lt_pre_sess_exists{session_name}
    @lt_pre_sess_inactive{session_name}

@sa lttng_stop_tracing() --
    Stops a recording session.
@sa \lt_man{lttng-start,1}
*/
LTTNG_EXPORT extern int lttng_start_tracing(const char *session_name);

/*!
@brief
    Makes the recording session named \lt_p{session_name} inactive,
    stopping all the tracers for its
    \ref api-channel-channel "channels", blocking until the operation
    completes.

@ingroup api_session

This function blocks until the trace data of the
recording session named \lt_p{session_name} is valid. Use
lttng_stop_tracing_no_wait() to avoid a blocking call.

If LTTng \ref api_session_rotation "archived the current trace chunk"
of the recording session named \lt_p{session_name} at least
once during its lifetime, then this function renames the current trace
chunk subdirectory. Although it's safe to
read the content of this renamed subdirectory while the recording
session remains inactive, it's \em not a trace chunk archive: you need to
\link lttng_destroy_session_ext() destroy\endlink the recording session
or a rotation needs to occur to archive it.

@note
    An #LTTNG_ACTION_TYPE_STOP_SESSION trigger action can also
    deactivate (stop) a recording session.

@param[in] session_name
    Name of the recording session to deactivate/stop.

@returns
    <dl>
      <dt>0 or a positive value
      <dd>Success

      <dt>\em Negative #lttng_error_code enumerator
      <dd>Error
    </dl>

@pre
    @lt_pre_conn
    @lt_pre_not_null{session_name}
    @lt_pre_sess_exists{session_name}
    @lt_pre_sess_active{session_name}

@sa lttng_stop_tracing_no_wait() --
    Deactivates a recording session without waiting for the operation
    to complete.
@sa lttng_start_tracing() --
    Starts a recording session.
@sa \lt_man{lttng-stop,1}
*/
LTTNG_EXPORT extern int lttng_stop_tracing(const char *session_name);

/*!
@brief
    Makes the recording session named \lt_p{session_name} inactive,
    stopping all the tracers for its
    \ref api-channel-channel "channels" without waiting for the
    operation to complete.

@ingroup api_session

Unlike lttng_stop_tracing(), this function does \em not block until
the operation is complete: it returns immediately. This
means the traces(s) of the recording session might not be valid when
this function returns, and there's no way to know when it/they become
valid.

@note
    An #LTTNG_ACTION_TYPE_STOP_SESSION trigger action can also
    deactivate (stop) a recording session.

@param[in] session_name
    Name of the recording session to deactivate/stop.

@returns
    <dl>
      <dt>0 or a positive value
      <dd>Success

      <dt>\em Negative #lttng_error_code enumerator
      <dd>Error
    </dl>

@pre
    @lt_pre_conn
    @lt_pre_not_null{session_name}
    @lt_pre_sess_exists{session_name}
    @lt_pre_sess_active{session_name}
    - No deactivation operation is in progress for the recording session
      named \lt_p{session_name}.

@sa lttng_stop_tracing() --
    Deactivates a recording session, blocking until the operation
    completes.
@sa lttng_start_tracing() --
    Starts a recording session.
@sa \lt_man{lttng-stop,1}
*/
LTTNG_EXPORT extern int lttng_stop_tracing_no_wait(const char *session_name);

/*
 * Deprecated: As of LTTng 2.9, this function always returns
 * -LTTNG_ERR_UND.
 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
LTTNG_EXPORT extern int lttng_calibrate(struct lttng_handle *handle,
					struct lttng_calibrate *calibrate);
#pragma GCC diagnostic pop

/*
 * Set URL for a consumer for a session and domain.
 *
 * Both data and control URL must be defined. If both URLs are the same, only
 * the control URL is used even for network streaming.
 *
 * Default port are 5342 and 5343 respectively for control and data which uses
 * the TCP protocol.
 *
 * URL format: proto://[HOST|IP][:PORT1[:PORT2]][/TRACE_PATH]
 *
 * Possible protocols are:
 * > file://...
 *   Local filesystem full path.
 *
 * > net[6]://...
 *   This will use the default network transport layer which is TCP for both
 *   control (PORT1) and data port (PORT2).
 *
 * > tcp[6]://...
 *   TCP only streaming. For this one, both data and control URL must be given.
 *
 * Return 0 on success else a negative LTTng error code.
 */
LTTNG_EXPORT extern int
lttng_set_consumer_url(struct lttng_handle *handle, const char *control_url, const char *data_url);

/*!
@brief
    Returns whether or not you may read the traces of the recording
    session named \lt_p{session_name}.

@ingroup api_session

It's not safe to read the traces of a recording session while
LTTng is still consuming data from the tracers for its
\ref api-channel-channel "channels".

This function makes it possible to know when LTTng is done consuming
trace data from tracers for the channels of the recording session
named \lt_p{session_name}.

@param[in] session_name
    Name of the recording session of which get whether or not
    you may read its traces.

@returns
    @parblock
    One of:

    <dl>
      <dt>0
      <dd>
	You may read the traces of the recording session named
	\lt_p{session_name}.

	This remains true as long as the recording session remains
	\link lttng_session::enabled inactive\endlink (stopped).

      <dt>1</dt>
      <dd>
	You may \em not read the traces of the recording session named
	\lt_p{session_name}.

      <dt>\em Negative #lttng_error_code enumerator
      <dd>
	Error.
    </dl>
    @endparblock

@pre
    @lt_pre_conn
    @lt_pre_not_null{session_name}
    @lt_pre_sess_exists{session_name}
    @lt_pre_sess_inactive{session_name}
*/
LTTNG_EXPORT extern int lttng_data_pending(const char *session_name);

/*!
@brief
    Sets \lt_p{*status} to the current status of the
    LTTng kernel tracer.

@ingroup api_gen

@param[out] status
    <strong>On success</strong>, this function sets \lt_p{*status} to
    the current status of the kernel tracer.

@retval #LTTNG_OK
    Success.
@retval #LTTNG_ERR_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_conn
    @lt_pre_not_null{status}
*/
LTTNG_EXPORT extern enum lttng_error_code
lttng_get_kernel_tracer_status(enum lttng_kernel_tracer_status *status);

/*!
@brief
    Regenerates the metadata streams of the recording session named
    \lt_p{session_name}.

@ingroup api_session

@deprecated
    Use lttng_regenerate_metadata().

@param[in] session_name
    Name of the recording session of which to regenerate the metadata
    streams.

@returns
    <dl>
      <dt>0
      <dd>Success

      <dt>\em Negative #lttng_error_code enumerator
      <dd>Error
    </dl>

@pre
    @lt_pre_conn
    @lt_pre_not_null{session_name}
    @lt_pre_sess_exists{session_name}
*/
/// @cond DEPRECATED
LTTNG_DEPRECATED()
/// @endcond
LTTNG_EXPORT extern int lttng_metadata_regenerate(const char *session_name);

/*!
@brief
    Regenerates the metadata streams of the recording session named
    \lt_p{session_name}.

@ingroup api_session

Use this function to resample the offset between the monotonic clock and
the wall time of the system, and then regenerate (overwrite) all the
metadata stream files (local or remote) of the recording session
named \lt_p{session_name}.

More specifically, you may want to resample the wall time following a
major <a href="https://en.wikipedia.org/wiki/Network_Time_Protocol">NTP</a>
correction. As such, LTTng can trace a system booting with an incorrect
wall time before its wall time is NTP-corrected. Regenerating the
metadata of a recording session ensures that trace readers
can accurately determine the event record timestamps relative to the
Unix epoch.

Note that if you plan to \ref api_session_rotation "rotate" the
recording session named \lt_p{session_name}, this function only
regenerates the metadata stream files of the \em current and \em next
trace chunks.

See the preconditions of this function which show important limitations.

@param[in] session_name
    Name of the recording session of which to regenerate the metadata
    streams.

@returns
    <dl>
      <dt>0
      <dd>Success

      <dt>\em Negative #lttng_error_code enumerator
      <dd>Error
    </dl>

@pre
    @lt_pre_conn
    @lt_pre_not_null{session_name}
    @lt_pre_sess_exists{session_name}
    - The recording session named \lt_p{session_name} was \em not
      created in \ref api-session-live-mode "live mode".
    - All the \ref api-channel-channel "channels" of the
      recording session named \lt_p{session_name} use a
      \ref api-channel-per-user-buf "per-user buffering scheme".

@sa lttng_regenerate_statedump() --
    Regenerates the state dump event records of a recording session.
@sa \lt_man{lttng-regenerate,1}
*/
LTTNG_EXPORT extern int lttng_regenerate_metadata(const char *session_name);

/*!
@brief
    Regenerates the state dump event records of the recording session
    named \lt_p{session_name}.

@ingroup api_session

Use this function to collect up-to-date state dump information and
append corresponding event records to the
\ref api-channel-channel "sub-buffers" of the recording session named
\lt_p{session_name}.

This is particularly useful if you created the recording session in
\ref api-session-snapshot-mode "snapshot mode"
or if LTTng \ref api_session_rotation "rotates" trace files for one of
its \ref api-channel-channel "channels": in both cases, the state dump
information may be lost.

@param[in] session_name
    Name of the recording session of which to regenerate the
    state dump event records.

@returns
    <dl>
      <dt>0
      <dd>Success

      <dt>\em Negative #lttng_error_code enumerator
      <dd>Error
    </dl>

@pre
    @lt_pre_conn
    @lt_pre_not_null{session_name}
    @lt_pre_sess_exists{session_name}

@sa lttng_regenerate_metadata() --
    Regenerates the metadata streams of a recording session.
@sa \lt_man{lttng-regenerate,1}
*/
LTTNG_EXPORT extern int lttng_regenerate_statedump(const char *session_name);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_H */
