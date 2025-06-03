/*
 * lttng-error.h
 *
 * Linux Trace Toolkit Control Library Error Header File
 *
 * The following values are all the possible errors the lttng command line
 * client can quit with.
 *
 * SPDX-FileCopyrightText: 2012 David Goulet <dgoulet@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_ERROR_H
#define LTTNG_ERROR_H

#ifdef __cplusplus
extern "C" {
#endif

#include <lttng/lttng-export.h>

/*!
@addtogroup api_gen
@{
*/

/*!
@brief
    General error codes.

Many functions, most of them dating from older liblttng-ctl versions,
return this type (or an \c int value which is equal to the negation of
one of those enumerators).

Not all error codes are relevant to a given function: this API
documentation makes an effort to document the most relevant status codes
for each function. This is not always possible, however, as LTTng is
made of multiple interacting components (tracers, consumer daemons,
session daemons, and the rest); those error codes can move from one to
another and the possible error codes of a given liblttng-ctl function
can change from version to version.

@sa lttng_strerror() --
    Returns a human-readable message for a general error code, positive
    or negative.
*/
enum lttng_error_code {
	/* Internal codes */
	/// @cond INTERNAL_ERR_CODES
	LTTNG_ERR_SELECT_SESS = 27, /* Must select a session */
	LTTNG_ERR_NO_STREAM = 52, /* Index without stream on relay. */
	LTTNG_ERR_UST_CALIBRATE_FAIL = 54, /* UST calibration failed */
	LTTNG_ERR_UST_CHAN_ENABLE_FAIL = 61, /* UST enable channel failed */
	LTTNG_ERR_CHAN_EXIST = 62, /* Channel already exists. */
	LTTNG_ERR_UST_META_FAIL = 65, /* UST open metadata failed */
	LTTNG_ERR_UST_STREAM_FAIL = 70, /* UST create stream failed */
	LTTNG_ERR_SNAPSHOT_NODATA = 71, /* No data in snapshot. */
	LTTNG_ERR_MI_OUTPUT_TYPE = 91, /* Invalid MI output format */
	LTTNG_ERR_MI_IO_FAIL = 92, /* IO error while writing machine interface output */
	LTTNG_ERR_MI_NOT_IMPLEMENTED = 93, /* Mi feature not implemented */
	LTTNG_ERR_EVENT_EXIST_LOGLEVEL = 100, /* Event enabled with different loglevel */
	LTTNG_ERR_FILTER_EXIST = 108, /* Filter already exist */
	LTTNG_ERR_COMMAND_CANCELLED = 128, /* Command cancelled. */
	LTTNG_ERR_ROTATE_RENAME_FAIL_CONSUMER = 142, /* Rotation rename failure on consumer */
	LTTNG_ERR_ROTATION_PENDING_LOCAL_FAIL_CONSUMER = 143, /* Rotation pending check (local)
								 failure on consumer */
	LTTNG_ERR_ROTATION_PENDING_RELAY_FAIL_CONSUMER = 144, /* Rotation pending check (relay)
								 failure on consumer */
	LTTNG_ERR_MKDIR_FAIL_CONSUMER = 145, /* mkdir failure on consumer */
	LTTNG_ERR_TRACE_CHUNK_EXISTS_FAIL_CONSUMER = 151, /* failed to query consumer for trace
							     chunk existence */
	/// @endcond

	/// Success.
	LTTNG_OK = 10,

	/// Unknown error.
	LTTNG_ERR_UNK = 11,

	/// Undefined command.
	LTTNG_ERR_UND = 12,

	/*!
	\lt_obj_c_session already
	\link lttng_session::enabled started\endlink (active).
	*/
	LTTNG_ERR_SESSION_STARTED = 13,

	/// Unknown \lt_obj_domain.
	LTTNG_ERR_UNKNOWN_DOMAIN = 14,

	/// Unsupported operation.
	LTTNG_ERR_NOT_SUPPORTED = 15,

	/// No \lt_obj_session found.
	LTTNG_ERR_NO_SESSION = 16,

	/// Failed to create a directory.
	LTTNG_ERR_CREATE_DIR_FAIL = 17,

	/// Failed to create a \lt_obj_session.
	LTTNG_ERR_SESSION_FAIL = 18,

	/*!
	No available
	\ref api-gen-sessiond-conn "session daemon to connect to".
	*/
	LTTNG_ERR_NO_SESSIOND = 19,

	/// Failed to set an URL.
	LTTNG_ERR_SET_URL = 20,

	/// URL already exists.
	LTTNG_ERR_URL_EXIST = 21,

	/*!
	Unsupported
	\ref api-channel-buf-ownership-model "buffer ownership model".
	*/
	LTTNG_ERR_BUFFER_NOT_SUPPORTED = 22,

	/// Nonexistent \lt_obj_session name.
	LTTNG_ERR_SESS_NOT_FOUND = 23,

	/*!
	A \lt_obj_channel within the given \lt_obj_domain already exists
	and is configured with another
	\ref api-channel-buf-ownership-model "buffer ownership model".
	*/
	LTTNG_ERR_BUFFER_TYPE_MISMATCH = 24,

	/// Fatal error.
	LTTNG_ERR_FATAL = 25,

	/// Failed to allocate memory.
	LTTNG_ERR_NOMEM = 26,

	/// \lt_obj_c_session name already exists.
	LTTNG_ERR_EXIST_SESS = 28,

	/// \lt_obj_c_rer not found.
	LTTNG_ERR_NO_EVENT = 29,

	/// Failed to connect to Unix socket.
	LTTNG_ERR_CONNECT_FAIL = 30,

	/// \ref api_session_snapshot "Snapshot" output already exists.
	LTTNG_ERR_SNAPSHOT_OUTPUT_EXIST = 31,

	/// Permission denied.
	LTTNG_ERR_EPERM = 32,

	/// Linux kernel tracer isn't available.
	LTTNG_ERR_KERN_NA = 33,

	/// Incompatible Linux kernel tracer.
	LTTNG_ERR_KERN_VERSION = 34,

	/// Linux kernel \lt_obj_rer already exists.
	LTTNG_ERR_KERN_EVENT_EXIST = 35,

	/// Linux kernel tracer: failed to create a \lt_obj_session.
	LTTNG_ERR_KERN_SESS_FAIL = 36,

	/// Linux kernel \lt_obj_channel already exists.
	LTTNG_ERR_KERN_CHAN_EXIST = 37,

	/// Failed to create a Linux kernel \lt_obj_channel.
	LTTNG_ERR_KERN_CHAN_FAIL = 38,

	/// Linux kernel \lt_obj_channel not found.
	LTTNG_ERR_KERN_CHAN_NOT_FOUND = 39,

	/// Failed to disable a Linux kernel \lt_obj_channel.
	LTTNG_ERR_KERN_CHAN_DISABLE_FAIL = 40,

	/// Failed to create/enable a Linux kernel \lt_obj_channel.
	LTTNG_ERR_KERN_CHAN_ENABLE_FAIL = 41,

	/*!
	Failed to add a context field to be recorded to the event
	records of a Linux kernel \lt_obj_channel.
	*/
	LTTNG_ERR_KERN_CONTEXT_FAIL = 42,

	/// Failed to create/enable a Linux kernel \lt_obj_rer.
	LTTNG_ERR_KERN_ENABLE_FAIL = 43,

	/// Failed to disable a Linux kernel \lt_obj_rer.
	LTTNG_ERR_KERN_DISABLE_FAIL = 44,

	/// Failed to open a Linux kernel trace metadata stream.
	LTTNG_ERR_KERN_META_FAIL = 45,

	/*!
	Linux kernel tracer: failed to
	\link lttng_start_tracing() start tracing\endlink.
	*/
	LTTNG_ERR_KERN_START_FAIL = 46,

	/*!
	Linux kernel tracer: failed to
	\link lttng_stop_tracing stop tracing\endlink.
	*/
	LTTNG_ERR_KERN_STOP_FAIL = 47,

	/// Failed to start a Linux kernel consumer daemon.
	LTTNG_ERR_KERN_CONSUMER_FAIL = 48,

	/// Failed to create a Linux kernel trace data stream.
	LTTNG_ERR_KERN_STREAM_FAIL = 49,

	/*!
	The \lt_obj_session never became
	\link lttng_session::enabled active\endlink.
	*/
	LTTNG_ERR_START_SESSION_ONCE = 50,

	/*!
	Failed to take a recording session
	\ref api_session_snapshot "snapshot".
	*/
	LTTNG_ERR_SNAPSHOT_FAIL = 51,

	/// Failed to list Linux kernel \lt_obj_rers.
	LTTNG_ERR_KERN_LIST_FAIL = 53,

	/// User space \lt_obj_rer already enabled.
	LTTNG_ERR_UST_EVENT_ENABLED = 55,

	/*!
	User space tracer: failed to
	\link lttng_create_session_ext() create\endlink a
	\lt_obj_session.
	*/
	LTTNG_ERR_UST_SESS_FAIL = 56,

	/// User space \lt_obj_channel already exists.
	LTTNG_ERR_UST_CHAN_EXIST = 57,

	/*!
	Failed to
	\link lttng_enable_channel() create\endlink a user space
	\lt_obj_channel.
	*/
	LTTNG_ERR_UST_CHAN_FAIL = 58,

	/// User space \lt_obj_channel not found.
	LTTNG_ERR_UST_CHAN_NOT_FOUND = 59,

	/*!
	Failed to \link lttng_disable_channel() disable\endlink
	a user space \lt_obj_channel.
	*/
	LTTNG_ERR_UST_CHAN_DISABLE_FAIL = 60,

	/// Failed to create/enable a user space \lt_obj_rer.
	LTTNG_ERR_UST_ENABLE_FAIL = 63,

	/// Failed to disable a user space \lt_obj_rer.
	LTTNG_ERR_UST_DISABLE_FAIL = 64,

	/*!
	User space tracer: failed to
	\link lttng_start_tracing() start tracing\endlink.
	*/
	LTTNG_ERR_UST_START_FAIL = 66,

	/*!
	User space tracer: failed to
	\link lttng_stop_tracing() stop tracing\endlink.
	*/
	LTTNG_ERR_UST_STOP_FAIL = 67,

	/// Failed to start a 64-bit user space consumer daemon.
	LTTNG_ERR_UST_CONSUMER64_FAIL = 68,

	/// Failed to start a 32-bit user space consumer daemon.
	LTTNG_ERR_UST_CONSUMER32_FAIL = 69,

	/// \lt_obj_c_session has no \lt_obj_channels.
	LTTNG_ERR_NO_CHANNEL = 72,

	/// \lt_obj_c_session name contains an invalid character.
	LTTNG_ERR_SESSION_INVALID_CHAR = 73,

	/// Failed to list user space \lt_obj_rers.
	LTTNG_ERR_UST_LIST_FAIL = 74,

	/// User space \lt_obj_rer already exists.
	LTTNG_ERR_UST_EVENT_EXIST = 75,

	/// User space \lt_obj_rer not found.
	LTTNG_ERR_UST_EVENT_NOT_FOUND = 76,

	/*!
	\link lttng_add_context() Context field\endlink to be recorded
	to the event records of a user space
	\lt_obj_channel already exists.
	*/
	LTTNG_ERR_UST_CONTEXT_EXIST = 77,

	/*!
	Invalid/unknown
	\link #lttng_event_context_type context field type\endlink.
	*/
	LTTNG_ERR_UST_CONTEXT_INVAL = 78,

	/*!
	A root session daemon is required, but isn't available.

	See \ref api-gen-sessiond-conn "Session daemon connection".
	*/
	LTTNG_ERR_NEED_ROOT_SESSIOND = 79,

	/*!
	\lt_obj_c_session is already
	\link lttng_session::enabled active\endlink (started).
	*/
	LTTNG_ERR_TRACE_ALREADY_STARTED = 80,

	/*!
	\lt_obj_c_session is already
	\link lttng_session::enabled inactive\endlink (stopped).
	*/
	LTTNG_ERR_TRACE_ALREADY_STOPPED = 81,

	/// Linux kernel instrumentation point type not supported.
	LTTNG_ERR_KERN_EVENT_ENOSYS = 82,

	/*!
	A \lt_obj_channel name is required because
	a non-default channel exists within the selected
	\lt_obj_session and \lt_obj_domain.
	*/
	LTTNG_ERR_NEED_CHANNEL_NAME = 83,

	/*!
	\lt_obj_c_channel name is required because a
	non-default channel exists within the \lt_obj_session.
	*/
	LTTNG_ERR_NO_UST = 84,

	/*!
	\ref api_session_save_load "Recording session configuration file"
	already exists.
	*/
	LTTNG_ERR_SAVE_FILE_EXIST = 85,

	/*!
	I/O error while writing a
	\ref api_session_save_load "recording session configuration file".
	*/
	LTTNG_ERR_SAVE_IO_FAIL = 86,

	/*!
	Invalid
	\ref api_session_save_load "recording session configuration file".
	*/
	LTTNG_ERR_LOAD_INVALID_CONFIG = 87,

	/*!
	I/O error while reading a
	\ref api_session_save_load "recording session configuration file".
	*/
	LTTNG_ERR_LOAD_IO_FAIL = 88,

	/*!
	\ref api_session_save_load "Recording session configuration file"
	not found.
	*/
	LTTNG_ERR_LOAD_SESSION_NOENT = 89,

	/*!
	Maximum total size of all the
	\ref api_session_snapshot "snapshot" trace files is invalid.
	*/
	LTTNG_ERR_MAX_SIZE_INVALID = 90,

	/* 94 */
	/* 95 */
	/* 96 */

	/// Unsatisfied precondition (invalid parameter, for example).
	LTTNG_ERR_INVALID = 97,

	/// No user space consumer daemon available.
	LTTNG_ERR_NO_USTCONSUMERD = 98,

	/// No Linux kernel consumer daemon available.
	LTTNG_ERR_NO_KERNCONSUMERD = 99,

	/// Missing network data \ref api-session-url "URL".
	LTTNG_ERR_URL_DATA_MISS = 101,

	/// Missing network control \ref api-session-url "URL".
	LTTNG_ERR_URL_CTRL_MISS = 102,

	/// Failed to communicate with a consumer daemon.
	LTTNG_ERR_ENABLE_CONSUMER_FAIL = 103,

	/*!
	Failed to connect to or communicate with a relay daemon
	(see \lt_man{lttng-relayd,8}).
	*/
	LTTNG_ERR_RELAYD_CONNECT_FAIL = 104,

	/// Incompatible relay daemon (see \lt_man{lttng-relayd,8}) version.
	LTTNG_ERR_RELAYD_VERSION_FAIL = 105,

	/*!
	Invalid \link lttng_enable_event_with_filter() context and event
	payload filter expression\endlink.
	*/
	LTTNG_ERR_FILTER_INVAL = 106,

	/*!
	Failed to allocate memory for a context and event payload filter
	object.
	*/
	LTTNG_ERR_FILTER_NOMEM = 107,

	/// No available consumer daemon.
	LTTNG_ERR_NO_CONSUMER = 109,

	/*!
	Invalid event name
	\link lttng_enable_event_with_exclusions() exclusion\endlink
	data.
	*/
	LTTNG_ERR_EXCLUSION_INVAL = 110,

	/// Failed to allocate memory for an event name exclusion object.
	LTTNG_ERR_EXCLUSION_NOMEM = 111,

	/// Invalid event name condition part of a \lt_obj_rer.
	LTTNG_ERR_INVALID_EVENT_NAME = 112,

	/// Invalid \lt_obj_channel name.
	LTTNG_ERR_INVALID_CHANNEL_NAME = 113,

	/*!
	Process attribute is already part of an
	\ref api_proc_filter "inclusion set".
	*/
	LTTNG_ERR_PROCESS_ATTR_EXISTS = 114,

	/*!
	Process attribute isn't part of an
	\ref api_proc_filter "inclusion set".
	*/
	LTTNG_ERR_PROCESS_ATTR_MISSING = 115,

	/// Invalid \lt_obj_domain for \lt_obj_channel.
	LTTNG_ERR_INVALID_CHANNEL_DOMAIN = 116,

	/// Overflow.
	LTTNG_ERR_OVERFLOW = 117,

	/*!
	\lt_obj_c_session isn't
	\link lttng_session::enabled active\endlink (started).
	*/
	LTTNG_ERR_SESSION_NOT_STARTED = 118,

	/*!
	Unsupported LTTng \ref api-session-live-mode "live" recording
	session mode.
	*/
	LTTNG_ERR_LIVE_SESSION = 119,

	/*!
	Unsupported
	\ref api-channel-per-proc-buf "process buffer ownership model".
	*/
	LTTNG_ERR_PER_PID_SESSION = 120,

	/*!
	\link #lttng_event_context_type Context field type\endlink
	isn't available on the current Linux kernel.
	*/
	LTTNG_ERR_KERN_CONTEXT_UNAVAILABLE = 121,

	/*!
	Failed to \link lttng_regenerate_statedump() regenerate the
	LTTng state dump event records\endlink.
	*/
	LTTNG_ERR_REGEN_STATEDUMP_FAIL = 122,

	/*!
	Failed to allocate memory to \link lttng_regenerate_statedump()
	regenerate the LTTng state dump event records\endlink.
	*/
	LTTNG_ERR_REGEN_STATEDUMP_NOMEM = 123,

	/*!
	\lt_obj_c_session isn't in
	\ref api-session-snapshot-mode "snapshot mode".
	*/
	LTTNG_ERR_NOT_SNAPSHOT_SESSION = 124,

	/// Invalid \lt_obj_trigger.
	LTTNG_ERR_INVALID_TRIGGER = 125,

	/// \lt_obj_c_trigger already exists (registered).
	LTTNG_ERR_TRIGGER_EXISTS = 126,

	/// \lt_obj_c_trigger not found.
	LTTNG_ERR_TRIGGER_NOT_FOUND = 127,

	/*!
	\ref api_session_rotation "Recording session rotation" operation
	already in progress.
	*/
	LTTNG_ERR_ROTATION_PENDING = 129,

	/*!
	\ref api_session_rotation "Recording session rotation" feature
	isn't available for the \ref api-session-modes "mode" of the
	given recording session.
	*/
	LTTNG_ERR_ROTATION_NOT_AVAILABLE = 130,

	/*!
	\ref api_session_rotation "Recording session rotation" schedule
	already set.
	*/
	LTTNG_ERR_ROTATION_SCHEDULE_SET = 131,

	/*!
	\ref api_session_rotation "Recording session rotation" schedule
	isn't set.
	*/
	LTTNG_ERR_ROTATION_SCHEDULE_NOT_SET = 132,

	/*!
	LTTng already
	\ref api_session_rotation "archived the current trace chunk" of
	the recording session since it became
	\link lttng_session::enabled inactive\endlink (stopped).
	*/
	LTTNG_ERR_ROTATION_MULTIPLE_AFTER_STOP = 133,

	/*!
	Linux kernel tracer: unavailable
	\ref api_session_rotation "recording session rotation" feature.
	*/
	LTTNG_ERR_ROTATION_WRONG_VERSION = 134,

	/// \lt_obj_c_session has no configured output.
	LTTNG_ERR_NO_SESSION_OUTPUT = 135,

	/*!
	Relay daemon: unavailable
	\ref api_session_rotation "recording session rotation" feature.
	*/
	LTTNG_ERR_ROTATION_NOT_AVAILABLE_RELAY = 136,

	/// Unavailable logging instrumentation point feature.
	LTTNG_ERR_AGENT_TRACING_DISABLED = 137,

	/// Invalid user space probe location.
	LTTNG_ERR_PROBE_LOCATION_INVAL = 138,

	/// Failed to parse ELF file.
	LTTNG_ERR_ELF_PARSING = 139,

	/*!
	SystemTap User-level Statically Defined Tracing (USDT) probe
	guarded by a semaphore.
	*/
	LTTNG_ERR_SDT_PROBE_SEMAPHORE = 140,

	/*!
	Consumer daemon failed to perform a
	\ref api_session_rotation "recording session rotation"
	operation.
	*/
	LTTNG_ERR_ROTATION_FAIL_CONSUMER = 141,

	/// \lt_obj_c_channel not found.
	LTTNG_ERR_CHAN_NOT_FOUND = 146,

	/*!
	Cannot take a
	\ref api_session_snapshot "snapshot" with the current
	recording session configuration.
	*/
	LTTNG_ERR_SNAPSHOT_UNSUPPORTED = 147,

	/// Nonexistent \lt_obj_session.
	LTTNG_ERR_SESSION_NOT_EXIST = 148,

	/*!
	Consumer daemon failed to create a
	\ref api_session_rotation "trace chunk archive".
	*/
	LTTNG_ERR_CREATE_TRACE_CHUNK_FAIL_CONSUMER = 149,

	/*!
	Consumer daemon failed to close a
	\ref api_session_rotation "trace chunk archive".
	*/
	LTTNG_ERR_CLOSE_TRACE_CHUNK_FAIL_CONSUMER = 150,

	/// Invalid protocol.
	LTTNG_ERR_INVALID_PROTOCOL = 152,

	/// Failed to create a file.
	LTTNG_ERR_FILE_CREATION_ERROR = 153,

	/// Failed to stop a timer.
	LTTNG_ERR_TIMER_STOP_ERROR = 154,

	/*!
	Linux kernel tracer:
	\ref api_session_rotation "recording session rotation" feature
	isn't available.
	*/
	LTTNG_ERR_ROTATION_NOT_AVAILABLE_KERNEL = 155,

	/*!
	The relay daemon (see \lt_man{lttng-relayd,8}) doesn't allow
	\ref api_session_clear "recording session clearing" operations.
	*/
	LTTNG_ERR_CLEAR_RELAY_DISALLOWED = 156,

	/*!
	The relay daemon (see \lt_man{lttng-relayd,8}) doesn't support
	the
	\ref api_session_clear "recording session clearing" operation.
	*/
	LTTNG_ERR_CLEAR_NOT_AVAILABLE_RELAY = 157,

	/*!
	Consumer daemon failed to
	\ref api_session_clear "clear the recording session".
	*/
	LTTNG_ERR_CLEAR_FAIL_CONSUMER = 158,

	/*!
	LTTng already
	\ref api_session_clear "cleared the recording session" since it
	became \link lttng_session::enabled inactive\endlink (stopped).
	*/
	LTTNG_ERR_ROTATION_AFTER_STOP_CLEAR = 159,

	/* Unix user not found. */
	LTTNG_ERR_USER_NOT_FOUND = 160,

	/* Unix group not found. */
	LTTNG_ERR_GROUP_NOT_FOUND = 161,

	/* Unsupported \lt_obj_domain. */
	LTTNG_ERR_UNSUPPORTED_DOMAIN = 162,

	/*!
	Invalid operation considering the policy of the
	\ref api_proc_filter "process filter".
	*/
	LTTNG_ERR_PROCESS_ATTR_TRACKER_INVALID_TRACKING_POLICY = 163,

	/*!
	Failed to initialize the file descriptor of the event notifier
	group notification.
	*/
	LTTNG_ERR_EVENT_NOTIFIER_GROUP_NOTIFICATION_FD = 164,

	/// Invalid event field capture expression.
	LTTNG_ERR_INVALID_CAPTURE_EXPRESSION = 165,

	/// Failed to register the event notifier to the tracer.
	LTTNG_ERR_EVENT_NOTIFIER_REGISTRATION = 166,

	/// Failed to initialize the event notifier error accounting.
	LTTNG_ERR_EVENT_NOTIFIER_ERROR_ACCOUNTING = 167,

	/// Event notifier error accouting is full.
	LTTNG_ERR_EVENT_NOTIFIER_ERROR_ACCOUNTING_FULL = 168,

	/// Invalid error query target.
	LTTNG_ERR_INVALID_ERROR_QUERY_TARGET = 169,

	/// Failed to flush a buffer.
	LTTNG_ERR_BUFFER_FLUSH_FAILED = 170,

	/* MUST be last element of the manually-assigned section of the enum */
	/// @cond INTERNAL_ERR_CODES
	LTTNG_ERR_NR,
	/// @endcond

	/* Backward-compatibility assignments */
	/*!
	Process attribute is already part of an
	\ref api_proc_filter "inclusion set".

	@deprecated
	    Use #LTTNG_ERR_PROCESS_ATTR_EXISTS.
	*/
	LTTNG_ERR_PID_TRACKED = LTTNG_ERR_PROCESS_ATTR_EXISTS,

	/*!
	Process attribute isn't part of an
	\ref api_proc_filter "inclusion set".

	@deprecated
	    Use #LTTNG_ERR_PROCESS_ATTR_MISSING.
	 */
	LTTNG_ERR_PID_NOT_TRACKED = LTTNG_ERR_PROCESS_ATTR_MISSING,
};

/*!
@brief
    Returns a human-readable message for the general error code
    \lt_p{error_code}.

@param[in] error_code
    Error code (one of the #lttng_error_code enumerators), positive or
    negative, for which to get a corresponding human-readable message.

@returns
    Human-readable message which corresponds to \lt_p{error_code}.

@pre
    - \lt_p{error_code} is a valid #lttng_error_code enumerator.
*/
LTTNG_EXPORT extern const char *lttng_strerror(int error_code);

/// @}

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_ERROR_H */
