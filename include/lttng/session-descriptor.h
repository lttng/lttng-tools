/*
 * SPDX-FileCopyrightText: 2019 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_SESSION_DESCRIPTOR_H
#define LTTNG_SESSION_DESCRIPTOR_H

#ifdef __cplusplus
extern "C" {
#endif

#include <lttng/lttng-export.h>

/*!
@addtogroup api_session_descr
@{
*/

/*!
@struct lttng_session_descriptor

@brief
    Recording session descriptor (opaque type).
*/
struct lttng_session_descriptor;

/*!
@brief
    Return type of recording session descriptor functions.

Error status enumerators have a negative value.
*/
enum lttng_session_descriptor_status {
	/// Success.
	LTTNG_SESSION_DESCRIPTOR_STATUS_OK = 0,

	/// Unsatisfied precondition.
	LTTNG_SESSION_DESCRIPTOR_STATUS_INVALID = -1,

	/// Recording session descriptor property is not set.
	LTTNG_SESSION_DESCRIPTOR_STATUS_UNSET = 1,
};

/*!
@brief
    Creates a recording session descriptor to create a no-output,
    \ref api-session-local-mode "local" recording session
    named \lt_p{session_name}.

LTTng won't write any trace data for a recording session created from
the returned descriptor.

@param[in] session_name
    @parblock
    Recording session name.

    If \c NULL, LTTng automatically generates a recording session name
    when you call lttng_create_session_ext().

    Call lttng_session_descriptor_get_session_name() with the returned
    recording session descriptor after successfully calling
    lttng_create_session_ext() to get the generated name.
    @endparblock

@returns
    @parblock
    Recording session descriptor on success, or \c NULL on error.

    Destroy the returned descriptor with
    lttng_session_descriptor_destroy().
    @endparblock

@sa lttng_session_descriptor_local_create() --
    Creates a recording session descriptor to create a
    \ref api-session-local-mode "local" recording session with an
    output.

@pre
    @lt_pre_sess_name_not_auto{session_name}
*/
LTTNG_EXPORT extern struct lttng_session_descriptor *
lttng_session_descriptor_create(const char *session_name);

/*!
@brief
    Creates a recording session descriptor to create a
    \ref api-session-local-mode "local" recording session
    named \lt_p{session_name}.

@param[in] session_name
    @parblock
    Recording session name.

    If \c NULL, LTTng automatically generates a recording session name
    when you call lttng_create_session_ext().

    Call lttng_session_descriptor_get_session_name() with the returned
    recording session descriptor after successfully calling
    lttng_create_session_ext() to get the generated name.
    @endparblock
@param[in] trace_dir
    @parblock
    Absolute path of the directory containing the traces of the
    recording session you create from the returned descriptor
    (copied).

    If \c NULL, the output directory is, after calling
    lttng_create_session_ext(),
    <code><em>$LTTNG_HOME</em>/lttng-traces/<em>NAME</em>-<em>TS</em></code>,
    with:

    <dl>
      <dt><code><em>$LTTNG_HOME</em></code>
      <dd>
	The value of the \c LTTNG_HOME environment variable, or
	of the \c HOME environment variable if \c LTTNG_HOME isn't
	set.

      <dt><code><em>NAME</em></code>
      <dd>
	Recording session name (\lt_p{session_name} if not \c NULL, or
	an automatically generated name otherwise).

      <dt><code><em>TS</em></code>
      <dd>
	\link lttng_session_get_creation_time() Timestamp of the
	creation\endlink of the recording session using the
	<code>YYYYmmdd-HHMMSS</code> form.
    </dl>
    @endparblock

@returns
    @parblock
    Recording session descriptor on success, or \c NULL on error.

    Destroy the returned descriptor with
    lttng_session_descriptor_destroy().
    @endparblock

@pre
    @lt_pre_sess_name_not_auto{session_name}
    - <strong>If not \c NULL</strong>, \lt_p{trace_dir} is a valid path.

@sa lttng_session_descriptor_create() --
    Creates a recording session descriptor to create a
    \ref api-session-local-mode "local" recording session without an
    output.
*/
LTTNG_EXPORT extern struct lttng_session_descriptor *
lttng_session_descriptor_local_create(const char *session_name, const char *trace_dir);

/*!
@brief
    Creates a recording session descriptor to create a
    \ref api-session-net-mode "network streaming" recording session
    named \lt_p{session_name}.

The valid combinations of \lt_p{control_url} and \lt_p{data_url} are:

<table>
  <tr>
    <th>\lt_p{control_url}
    <th>\lt_p{data_url}
    <th>Behaviour
  <tr>
    <td>\c NULL
    <td>\c NULL
    <td>
      Use \lt_def_net_ctrl_url as \lt_p{control_url}.

      Use \lt_def_net_data_url as \lt_p{data_url}.
  <tr>
    <td>\ref api-session-one-port-url "Single-port output URL"
    <td>\c NULL
    <td>
      Use the protocol, host, and trace directory (if any) of
      \lt_p{control_url} and the port \lt_def_net_data_port
      as \lt_p{data_url}.
  <tr>
    <td>Single-port output URL
    <td>
      Single-port output URL with the exact same protocol, host,
      and trace directory (if any) as \lt_p{control_url}.
    <td>
      Use the specified output URLs.
  <tr>
    <td>\ref api-session-two-port-url "Two-port output URL"
    <td>\c NULL
    <td>
      Use the protocol, host, data port, and trace directory (if any)
      of \lt_p{control_url} as \lt_p{data_url}.
</table>

@param[in] session_name
    @parblock
    Recording session name.

    If \c NULL, LTTng automatically generates a recording session name
    when you call lttng_create_session_ext().

    Call lttng_session_descriptor_get_session_name() with the returned
    recording session descriptor after successfully calling
    lttng_create_session_ext() to get the generated name.
    @endparblock
@param[in] control_url
    @parblock
    One of:

    <dl>
      <dt>\ref api-session-one-port-url "Single-port output URL"
      <dd>
	Indicates where (to which relay daemon; see
	\lt_man{lttng-relayd,8}) to send the control data.

      <dt>\ref api-session-two-port-url "Two-port output URL"
      <dd>
	Indicates where to send the control \em and trace data.
    </dl>

    This function copies \lt_p{control_url}.

    If \c NULL, this function uses \lt_def_net_url.
    @endparblock
@param[in] data_url
    @parblock
    \ref api-session-one-port-url "Single-port output URL" which
    indicates where to send the trace data (copied).

    May be <code>NULL</code>: see the table above for the default value
    depending on \lt_p{control_url}.
    @endparblock

@returns
    @parblock
    Recording session descriptor on success, or \c NULL on error.

    Destroy the returned descriptor with
    lttng_session_descriptor_destroy().
    @endparblock

@pre
    @lt_pre_sess_name_not_auto{session_name}
    - \lt_p{control_url} and \lt_p{data_url} satisfy one of the valid
      combinations shown in the table above.
*/
LTTNG_EXPORT extern struct lttng_session_descriptor *lttng_session_descriptor_network_create(
	const char *session_name, const char *control_url, const char *data_url);

/*!
@brief
    Creates a recording session descriptor to create a
    \ref api-session-snapshot-mode "snapshot" recording session
    named \lt_p{session_name} without an initial output.

A recording session which lttng_create_session_ext() creates from the
returned descriptor has no initial snapshot output: you need to either
add one with lttng_snapshot_add_output() or provide one when you take a
snapshot with lttng_snapshot_record().

@param[in] session_name
    @parblock
    Recording session name.

    If \c NULL, LTTng automatically generates a recording session name
    when you call lttng_create_session_ext().

    Call lttng_session_descriptor_get_session_name() with the returned
    recording session descriptor after successfully calling
    lttng_create_session_ext() to get the generated name.
    @endparblock

@returns
    @parblock
    Recording session descriptor on success, or \c NULL on error.

    Destroy the returned descriptor with
    lttng_session_descriptor_destroy().
    @endparblock

@pre
    @lt_pre_sess_name_not_auto{session_name}

@sa lttng_session_descriptor_snapshot_local_create() --
    Creates a recording session descriptor to create a
    \ref api-session-snapshot-mode "snapshot" recording session
    with an initial local output.
@sa lttng_session_descriptor_snapshot_network_create() --
    Creates a recording session descriptor to create a
    \ref api-session-snapshot-mode "snapshot" recording session
    with an initial remote output.
*/
LTTNG_EXPORT extern struct lttng_session_descriptor *
lttng_session_descriptor_snapshot_create(const char *session_name);

/*!
@brief
    Creates a recording session descriptor to create a
    \ref api-session-snapshot-mode "snapshot" recording session
    named \lt_p{session_name} and having an initial local output.

Using the returned descriptor when you call lttng_create_session_ext()
to create a snapshot recording session is similar to using a descriptor
which lttng_session_descriptor_snapshot_create() returns and calling
lttng_snapshot_add_output() after creating the recording session.

The name of this initial snapshot output is <code>snapshot-0</code>.

@param[in] session_name
    @parblock
    Recording session name.

    If \c NULL, LTTng automatically generates a recording session name
    when you call lttng_create_session_ext().

    Call lttng_session_descriptor_get_session_name() with the returned
    recording session descriptor after successfully calling
    lttng_create_session_ext() to get the generated name.
    @endparblock
@param[in] trace_dir
    @parblock
    Absolute path of an initial snapshot output (copied).

    If \c NULL, the snapshot output directory is, after calling
    lttng_create_session_ext(),
    <code><em>$LTTNG_HOME</em>/lttng-traces/<em>NAME</em>-<em>TS</em></code>,
    with:

    <dl>
      <dt><code><em>$LTTNG_HOME</em></code>
      <dd>
	The value of the \c LTTNG_HOME environment variable, or
	of the \c HOME environment variable if \c LTTNG_HOME isn't
	set.

      <dt><code><em>NAME</em></code>
      <dd>
	Recording session name (\lt_p{session_name} if not \c NULL, or
	an automatically generated name otherwise).

      <dt><code><em>TS</em></code>
      <dd>
	\link lttng_session_get_creation_time() Timestamp of the
	creation\endlink of the recording session using the
	<code>YYYYmmdd-HHMMSS</code> form.
    </dl>
    @endparblock

@returns
    @parblock
    Recording session descriptor on success, or \c NULL on error.

    Destroy the returned descriptor with
    lttng_session_descriptor_destroy().
    @endparblock

@pre
    @lt_pre_sess_name_not_auto{session_name}
    - <strong>If not \c NULL</strong>, \lt_p{trace_dir} is a valid path.

@sa lttng_session_descriptor_snapshot_create() --
    Creates a recording session descriptor to create a
    \ref api-session-snapshot-mode "snapshot" recording session
    without an initial output.
@sa lttng_session_descriptor_snapshot_network_create() --
    Creates a recording session descriptor to create a
    \ref api-session-snapshot-mode "snapshot" recording session
    with an initial remote output.
*/
LTTNG_EXPORT extern struct lttng_session_descriptor *
lttng_session_descriptor_snapshot_local_create(const char *session_name, const char *trace_dir);

/*!
@brief
    Creates a recording session descriptor to create a
    \ref api-session-snapshot-mode "snapshot" recording session
    named \lt_p{session_name} and having an initial remote output.

Using the returned descriptor when you call lttng_create_session_ext()
to create a snapshot recording session is similar to using a descriptor
which lttng_session_descriptor_snapshot_create() returns and calling
lttng_snapshot_add_output() after creating the recording session.

The name of this initial snapshot output is <code>snapshot-0</code>.

The valid combinations of \lt_p{control_url} and \lt_p{data_url} are:

<table>
  <tr>
    <th>\lt_p{control_url}
    <th>\lt_p{data_url}
    <th>Behaviour
  <tr>
    <td>\c NULL
    <td>\c NULL
    <td>
      Use \lt_def_net_ctrl_url as \lt_p{control_url}.

      Use \lt_def_net_data_url as \lt_p{data_url}.
  <tr>
    <td>\ref api-session-one-port-url "Single-port output URL"
    <td>\c NULL
    <td>
      Use the protocol, host, and trace directory (if any) of
      \lt_p{control_url} and the port \lt_def_net_data_port
      as \lt_p{data_url}.
  <tr>
    <td>Single-port output URL
    <td>
      Single-port output URL with the exact same protocol, host,
      and trace directory (if any) as \lt_p{control_url}.
    <td>
      Use the specified output URLs.
  <tr>
    <td>\ref api-session-two-port-url "Two-port output URL"
    <td>\c NULL
    <td>
      Use the protocol, host, data port, and trace directory (if any)
      of \lt_p{control_url} as \lt_p{data_url}.
</table>

@param[in] session_name
    @parblock
    Recording session name.

    If \c NULL, LTTng automatically generates a recording session name
    when you call lttng_create_session_ext().

    Call lttng_session_descriptor_get_session_name() with the returned
    recording session descriptor after successfully calling
    lttng_create_session_ext() to get the generated name.
    @endparblock
@param[in] control_url
    @parblock
    Control data URL of an initial snapshot output.

    One of:

    <dl>
      <dt>\ref api-session-one-port-url "Single-port output URL"
      <dd>
	Indicates where (to which relay daemon; see
	\lt_man{lttng-relayd,8}) to send the control data.

      <dt>\ref api-session-two-port-url "Two-port output URL"
      <dd>
	Indicates where to send the control \em and trace data.
    </dl>

    This function copies \lt_p{control_url}.

    If \c NULL, this function uses \lt_def_net_url.
    @endparblock
@param[in] data_url
    @parblock
    Trace data URL of an initial snapshot output (copied).

    \ref api-session-one-port-url "Single-port output URL" which
    indicates where to send the trace data.

    May be <code>NULL</code>: see the table above for the default value
    depending on \lt_p{control_url}.
    @endparblock

@returns
    @parblock
    Recording session descriptor on success, or \c NULL on error.

    Destroy the returned descriptor with
    lttng_session_descriptor_destroy().
    @endparblock

@pre
    @lt_pre_sess_name_not_auto{session_name}
    - \lt_p{control_url} and \lt_p{data_url} satisfy one of the valid
      combinations shown in the table above.

@sa lttng_session_descriptor_snapshot_create() --
    Creates a recording session descriptor to create a
    \ref api-session-snapshot-mode "snapshot" recording session
    without an initial output.
@sa lttng_session_descriptor_snapshot_local_create() --
    Creates a recording session descriptor to create a
    \ref api-session-snapshot-mode "snapshot" recording session
    with an initial local output.
*/
LTTNG_EXPORT extern struct lttng_session_descriptor *
lttng_session_descriptor_snapshot_network_create(const char *session_name,
						 const char *control_url,
						 const char *data_url);

/*
 * NOTE: Not documented with Doxygen as what lttng_create_session_ext()
 * creates from such a descriptor is useless (a live recording session
 * without any output). Original documentation follows.
 *
 * Create a live session descriptor without an output.
 *
 * The 'name' parameter can be left NULL to auto-generate a session name.
 *
 * The 'live_timer_interval_us' parameter is the live timer's period, specified
 * in microseconds.
 *
 * This parameter can't be 0. There is no default value defined for a live
 * timer's period.
 *
 * Returns an lttng_session_descriptor instance on success, NULL on error.
 */
LTTNG_EXPORT extern struct lttng_session_descriptor *
lttng_session_descriptor_live_create(const char *name, unsigned long long live_timer_interval_us);

/*!
@brief
    Creates a recording session descriptor to create a
    \ref api-session-live-mode "live" recording session
    named \lt_p{session_name}.

The valid combinations of \lt_p{control_url} and \lt_p{data_url} are:

<table>
  <tr>
    <th>\lt_p{control_url}
    <th>\lt_p{data_url}
    <th>Behaviour
  <tr>
    <td>\c NULL
    <td>\c NULL
    <td>
      Use \lt_def_net_ctrl_url as \lt_p{control_url}.

      Use \lt_def_net_data_url as \lt_p{data_url}.
  <tr>
    <td>\ref api-session-one-port-url "Single-port output URL"
    <td>\c NULL
    <td>
      Use the protocol, host, and trace directory (if any) of
      \lt_p{control_url} and the port \lt_def_net_data_port
      as \lt_p{data_url}.
  <tr>
    <td>Single-port output URL
    <td>
      Single-port output URL with the exact same protocol, host,
      and trace directory (if any) as \lt_p{control_url}.
    <td>
      Use the specified output URLs.
  <tr>
    <td>\ref api-session-two-port-url "Two-port output URL"
    <td>\c NULL
    <td>
      Use the protocol, host, data port, and trace directory (if any)
      of \lt_p{control_url} as \lt_p{data_url}.
</table>

@param[in] session_name
    @parblock
    Recording session name.

    If \c NULL, LTTng automatically generates a recording session name
    when you call lttng_create_session_ext().

    Call lttng_session_descriptor_get_session_name() with the returned
    recording session descriptor after successfully calling
    lttng_create_session_ext() to get the generated name.
    @endparblock
@param[in] control_url
    @parblock
    One of:

    <dl>
      <dt>\ref api-session-one-port-url "Single-port output URL"
      <dd>
	Indicates where (to which relay daemon; see
	\lt_man{lttng-relayd,8}) to send the control data.

      <dt>\ref api-session-two-port-url "Two-port output URL"
      <dd>
	Indicates where to send the control \em and trace data.
    </dl>

    This function copies \lt_p{control_url}.

    If \c NULL, this function uses \lt_def_net_url.
    @endparblock
@param[in] data_url
    @parblock
    \ref api-session-one-port-url "Single-port output URL" which
    indicates where to send the trace data (copied).

    May be <code>NULL</code>: see the table above for the default value
    depending on \lt_p{control_url}.
    @endparblock
@param[in] live_timer_period
    Period (µs) of the \ref api-channel-live-timer "live timers" of all
    the channels of a recording session which lttng_create_session_ext()
    creates from the returned descriptor.

@returns
    @parblock
    Recording session descriptor on success, or \c NULL on error.

    Destroy the returned descriptor with
    lttng_session_descriptor_destroy().
    @endparblock

@pre
    @lt_pre_sess_name_not_auto{session_name}
    - \lt_p{control_url} and \lt_p{data_url} satisfy one of the valid
      combinations shown in the table above.
    - \lt_p{live_timer_period}&nbsp;≥&nbsp;1
*/
LTTNG_EXPORT extern struct lttng_session_descriptor *
lttng_session_descriptor_live_network_create(const char *session_name,
					     const char *control_url,
					     const char *data_url,
					     unsigned long long live_timer_period);

/*!
@brief
    Sets \lt_p{*session_name} to the name of the recording session
    which lttng_create_session_ext() created from the recording
    session descriptor \lt_p{session_descriptor}.

Call this function after successfully calling lttng_create_session_ext()
when \lt_p{session_descriptor} wasn't created with a specific recording
session name to get the automatically generated name of the created
recording session.

@param[in] session_descriptor
    Recording session descriptor from which lttng_create_session_ext()
    previously created the recording session of which to get the name.
@param[out] session_name
    @parblock
    <strong>On success</strong>, this function sets \lt_p{*session_name}
    to the name of the recording session which
    lttng_create_session_ext() previously created from
    \lt_p{session_descriptor}.

    \lt_p{session_descriptor} owns \lt_p{*session_name}.

    \lt_p{*session_name} remains valid until the next recording
    session descriptor function call with \lt_p{session_descriptor}.
    @endparblock

@retval #LTTNG_SESSION_DESCRIPTOR_STATUS_OK
    Success.
@retval #LTTNG_SESSION_DESCRIPTOR_STATUS_INVALID
    Unsatisfied precondition.
@retval #LTTNG_SESSION_DESCRIPTOR_STATUS_UNSET
    The name property of \lt_p{session_descriptor} is not set.

@pre
    @lt_pre_not_null{session_descriptor}
    - You successfully called lttng_create_session_ext() with
      \lt_p{session_descriptor}.
    @lt_pre_not_null{session_name}
*/
LTTNG_EXPORT extern enum lttng_session_descriptor_status
lttng_session_descriptor_get_session_name(const struct lttng_session_descriptor *session_descriptor,
					  const char **session_name);

/*!
@brief
    Destroys the recording session descriptor \lt_p{session_descriptor}.

@note
    @parblock
    This function doesn't destroy the recording session which
    lttng_create_session_ext() created from \lt_p{session_descriptor},
    but only the descriptor itself.

    Use lttng_destroy_session_ext() to destroy a recording session.
    @endparblock

@param[in] session_descriptor
    @parblock
    Recording session descriptor to destroy.

    May be \c NULL.
    @endparblock
*/
LTTNG_EXPORT extern void
lttng_session_descriptor_destroy(struct lttng_session_descriptor *session_descriptor);

/// @}

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_SESSION_DESCRIPTOR_H */
