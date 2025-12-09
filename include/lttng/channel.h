/*
 * SPDX-FileCopyrightText: 2014 David Goulet <dgoulet@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_CHANNEL_H
#define LTTNG_CHANNEL_H

#include <lttng/domain.h>
#include <lttng/event.h>
#include <lttng/lttng-error.h>
#include <lttng/lttng-export.h>

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*!
@brief
    \ref api-channel-buf-alloc-policy "Buffer allocation policy"
    of a channel.

@ingroup api_channel
*/
enum lttng_channel_allocation_policy {
	/// \ref api-channel-per-cpu-buf "Per-CPU buffering"
	LTTNG_CHANNEL_ALLOCATION_POLICY_PER_CPU = 0,

	/// \ref api-channel-per-chan-buf "Per-channel buffering"
	LTTNG_CHANNEL_ALLOCATION_POLICY_PER_CHANNEL = 1,
};

enum lttng_channel_preallocation_policy {
	LTTNG_CHANNEL_PREALLOCATION_POLICY_PREALLOCATE = 0,
	LTTNG_CHANNEL_PREALLOCATION_POLICY_ON_DEMAND = 1,
};

/*!
@brief
    Status code for \lt_obj_channel property accessors.

@ingroup api_channel
*/
enum lttng_channel_status {
	/// Success
	LTTNG_CHANNEL_STATUS_OK = 0,
	/// Property is unset
	LTTNG_CHANNEL_STATUS_UNSET = 1,
	/// Invalid arguments
	LTTNG_CHANNEL_STATUS_INVALID = -1,
};

/*
 * Tracer channel attributes. For both kernel and user-space.
 *
 * The structures should be initialized to zero before use.
 */
#define LTTNG_CHANNEL_ATTR_PADDING1 (LTTNG_SYMBOL_NAME_LEN + 12)

/*!
@brief
    Attributes of a \link #lttng_channel channel summary\endlink.

@ingroup api_channel

The lttng_channel::attr member is an instance of such a structure.

lttng_channel_set_default_attr() sets the members of such a structure
to their default values given a specific \lt_obj_domain summary.

\anchor api-channel-valid-attr-struct A \em valid #lttng_channel_attr
structure satisfies the following constraints:

<table>
  <tr>
    <th>Member
    <th>Constraints
  <tr>
    <td>lttng_channel_attr::overwrite
    <td>0, 1, or -1
  <tr>
    <td>lttng_channel_attr::subbuf_size
    <td>
      - Greater than 0
      - Power of two
  <tr>
    <td>lttng_channel_attr::num_subbuf
    <td>
      - Greater than 0
      - Power of two
</table>
*/
struct lttng_channel_attr {
	/*!
	@brief
	    \ref api-channel-er-loss-mode "Event record loss mode".

	One of:

	<dl>
	  <dt>0
	  <dd>
	    The \ref api-channel-er-loss-mode "event record loss mode"
	    of the channel is
	    <em>\ref api-channel-discard-mode "discard"</em>.

	  <dt>1
	  <dd>
	    The event record loss mode of the channel is
	    <em>\ref api-channel-overwrite-mode "overwrite"</em>.

	  <dt>-1
	  <dd>
	    The event record loss mode of the channel is the default
	    value of its \lt_obj_session:

	    <dl>
	      <dt>\ref api-session-snapshot-mode "Snapshot mode"
	      <dd>Overwrite mode

	      <dt>Other modes
	      <dd>Discard mode
	    </dl>
	</dl>
	*/
	int overwrite; /* -1: session default, 1: overwrite, 0: discard */

	/*!
	@brief
	    \ref api-channel-sub-buf-size-count "Sub-buffer size"
	    (bytes).
	*/
	uint64_t subbuf_size; /* bytes, power of 2 */

	/*!
	@brief
	    \ref api-channel-sub-buf-size-count "Sub-buffer count".
	*/
	uint64_t num_subbuf; /* power of 2 */

	/*!
	@brief
	    \ref api-channel-switch-timer "Switch timer period" (µs),
	    if applicable.

	Only available if the \lt_obj_session which
	owns this channel is \em not in
	\ref api-session-live-mode "live mode".
	*/
	unsigned int switch_timer_interval; /* usec */

	/// \ref api-channel-read-timer "Read timer period" (µs).
	unsigned int read_timer_interval; /* usec */

	/// Output type (Linux kernel channel).
	enum lttng_event_output output; /* splice, mmap */

	/* LTTng 2.1 padding limit */

	/*!
	@brief
	    \ref api-channel-max-trace-file-size-count "Maximum trace file size"
	    (bytes), or 0 for unlimited.
	*/
	uint64_t tracefile_size; /* bytes */

	/*!
	@brief
	    \ref api-channel-max-trace-file-size-count "Maximum trace file count",
	    or 0 for unlimited.
	*/
	uint64_t tracefile_count; /* number of tracefiles */

	/* LTTng 2.3 padding limit */

	/*!
	@brief
	    \ref api-channel-live-timer "Live timer period" (µs), if
	    applicable.

	You may \em not set this member: use the
	\lt_p{live_timer_period} parameter of
	lttng_session_descriptor_live_network_create() when you create
	the descriptor of a \ref api-session-live-mode "live" recording
	session to contain the channel to create.

	Only available if the \lt_obj_session which
	owns this channel is in \ref api-session-live-mode "live mode".
	*/
	unsigned int live_timer_interval; /* usec */

	/* LTTng 2.7 padding limit */
	uint32_t align_to_64;
	union {
		uint64_t padding;
		void *ptr;
	} extended;

	char padding[LTTNG_CHANNEL_ATTR_PADDING1];
};

/*
 * Channel information structure. For both kernel and user-space.
 *
 * The structures should be initialized to zero before use.
 */
#define LTTNG_CHANNEL_PADDING1 16

/*!
@brief
    \lt_obj_c_channel summary.

@ingroup api_channel

The purpose of such a structure is to provide information about a
channel itself, but not about its \lt_obj_rers
(use lttng_list_events() for this).

lttng_list_channels() sets a pointer to an array of all the
channel summaries of a given \lt_obj_session and \lt_obj_domain.

Most properties are part of the lttng_channel::attr member, but the
following ones have their own dedicated accessors:

<dl>
  <dt>\ref api-channel-buf-alloc-policy "Buffer allocation policy"
  <dd>
    - lttng_channel_get_allocation_policy()
    - lttng_channel_set_allocation_policy()

  <dt>\ref api-channel-monitor-timer "Monitor timer" period
  <dd>
    - lttng_channel_get_monitor_timer_interval()
    - lttng_channel_set_monitor_timer_interval()

  <dt>\ref api-channel-watchdog-timer "Watchdog timer" period
  <dd>
    - lttng_channel_get_watchdog_timer_interval()
    - lttng_channel_set_watchdog_timer_interval()

  <dt>\ref api-channel-blocking-timeout "Blocking timeout"
  <dd>
    - lttng_channel_get_blocking_timeout()
    - lttng_channel_set_blocking_timeout()
</dl>

Create a channel summary with lttng_channel_create().

Destroy a channel summary with lttng_channel_destroy().
*/
struct lttng_channel {
	/// Name.
	char name[LTTNG_SYMBOL_NAME_LEN];

	/*!
	@brief
	    1 if this \lt_obj_channel is enabled, or 0 otherwise.

	@sa lttng_enable_channel() --
	    Creates or enables a channel.
	@sa lttng_disable_channel() --
	    Disables a channel.
	*/
	uint32_t enabled;

	/// Other properties.
	struct lttng_channel_attr attr;

	char padding[LTTNG_CHANNEL_PADDING1];
};

/*!
@brief
    Creates and returns a \lt_obj_channel summary,
    setting the members of its lttng_channel::attr member to default
    values according to the \lt_obj_domain summary \lt_p{domain}.

@ingroup api_channel

This function internally calls

@code
lttng_channel_set_default_attr(domain, &channel->attr);
@endcode

where \c channel is the returned channel summary.

After you create a channel summary with this function, you can modify
its \ref api-channel-channel-props "properties" and call
lttng_enable_channel() to create and enable a channel.

@param[in] domain
    Tracing domain summary to consider to set the members of the
    lttng_channel::attr member of the returned structure to default
    values.

@returns
    @parblock
    New channel summary.

    Destroy the returned channel summary with lttng_channel_destroy().
    @endparblock

@pre
    @lt_pre_not_null{domain}

@sa lttng_channel_destroy() --
    Destroys a channel summary.
*/
LTTNG_EXPORT extern struct lttng_channel *lttng_channel_create(struct lttng_domain *domain);

/*!
@brief
    Destroys the \lt_obj_channel summary \lt_p{channel}.

@ingroup api_channel

@note
    This function doesn't destroy the \lt_obj_channel
    which \lt_p{channel} summarizes: the only way to destroy a channel
    is to \link lttng_destroy_session_ext() destroy its recording
    session\endlink.

@param[in] channel
    @parblock
    Channel summary to destroy.

    May be \c NULL.
    @endparblock
*/
LTTNG_EXPORT extern void lttng_channel_destroy(struct lttng_channel *channel);

/*!
@brief
    Sets \lt_p{*channels} to the summaries of the
    \lt_obj_channels of the recording session handle \lt_p{handle}.

@ingroup api_session

@param[in] handle
    Recording session handle which contains the name of the recording
    session and the summary of the \lt_obj_domain which own the channels
    of which to get the summaries.
@param[out] channels
    @parblock
    <strong>On success</strong>, this function sets \lt_p{*channels} to
    the summaries of the channels.

    Free \lt_p{*channels} with <code>free()</code>.
    @endparblock

@returns
    The number of items in \lt_p{*channels} on success, or a \em
    negative #lttng_error_code enumerator otherwise.

@pre
    @lt_pre_conn
    @lt_pre_not_null{handle}
    @lt_pre_valid_c_str{handle->session_name}
    @lt_pre_sess_exists{handle->session_name}
    - \lt_p{handle->domain} is valid as per the documentation of
      #lttng_domain.
    @lt_pre_not_null{channels}
*/
LTTNG_EXPORT extern int lttng_list_channels(const struct lttng_handle *handle,
					    struct lttng_channel **channels);

/*!
@brief
    Creates or enables a \lt_obj_channel summarized by \lt_p{channel}
    within the recording session handle \lt_p{handle}.

@ingroup api_channel

This function, depending on \lt_p{channel->name}:

<dl>
  <dt>
    \lt_p{channel-&gt;name} names an existing
    channel within the \lt_obj_session and
    \lt_obj_domain of \lt_p{handle}
  <dd>
    Enables the existing channel.

    In this case, this function only uses \lt_p{channel->name}, ignoring
    all the other properties of \lt_p{channel}.

  <dt>Otherwise
  <dd>
    Creates and enables a new channel, considering all the properties of
    \lt_p{channel}.
</dl>

@param[in] handle
    Recording session handle which contains the name of the
    recording session and the summary of the \lt_obj_domain which own
    the channel to create or enable.
@param[in] channel
    Summary of the channel to create or enable.

@returns
    <dl>
      <dt>0 or a positive value
      <dd>Success

      <dt>\em Negative #lttng_error_code enumerator
      <dd>Error
    </dl>

@pre
    @lt_pre_conn
    @lt_pre_not_null{handle}
    @lt_pre_valid_c_str{handle->session_name}
    @lt_pre_sess_exists{handle->session_name}
    - \lt_p{handle->domain} is valid as per the documentation of
      #lttng_domain.
    @lt_pre_not_null{channel}
    - <strong>If this function must create a new channel</strong>, then
      \lt_p{channel->attr} is
      \ref api-channel-valid-attr-struct "valid".
    - <strong>If this function must create a new channel</strong>, then
      \lt_p{handle->session_name} names a
      \lt_obj_session which never became
      \link lttng_session::enabled active\endlink (started) since its
      creation.
    - <strong>If this function must create a new channel</strong>, then
      all the existing channels of \lt_p{handle} have the same
      \ref api-channel-buf-ownership-model "buffer ownership model".

@sa lttng_disable_channel() --
    Disables a channel.
*/
LTTNG_EXPORT extern int lttng_enable_channel(struct lttng_handle *handle,
					     struct lttng_channel *channel);

/*!
@brief
    Disables the \lt_obj_channel named \lt_p{channel_name} within the
    recording session handle \lt_p{handle}.

@ingroup api_channel

@param[in] handle
    Recording session handle which contains the name of the
    recording session and the summary of the \lt_obj_domain which own
    the channel to disable.
@param[in] channel_name
    Name of the channel to disable within \lt_p{handle}.

@returns
    <dl>
      <dt>0 or a positive value
      <dd>Success

      <dt>\em Negative #lttng_error_code enumerator
      <dd>Error
    </dl>

@pre
    @lt_pre_conn
    @lt_pre_not_null{handle}
    @lt_pre_valid_c_str{handle->session_name}
    @lt_pre_sess_exists{handle->session_name}
    - \lt_p{handle->domain} is valid as per the documentation of
      #lttng_domain.
    @lt_pre_not_null{channel_name}
    - \lt_p{channel_name} names an existing channel within the recording
      session and tracing domain of \lt_p{handle}.

@sa lttng_enable_channel() --
    Creates or enables a channel.
*/
LTTNG_EXPORT extern int lttng_disable_channel(struct lttng_handle *handle,
					      const char *channel_name);

/*!
@brief
    Sets the members of \lt_p{attr} to their default values considering
    the \lt_obj_domain summary \lt_p{domain}.

@ingroup api_channel

Use this function on an lttng_channel::attr member.

@param[in] domain
    Tracing domain summary to consider to set the members of \lt_p{attr}
    to their default values.
@param[in] attr
    Structure of which to set the members to their default values.

@pre
    @lt_pre_not_null{domain}
    @lt_pre_not_null{attr}
*/
LTTNG_EXPORT extern void lttng_channel_set_default_attr(struct lttng_domain *domain,
							struct lttng_channel_attr *attr);

/*!
@brief
    Sets \lt_p{*count} to the number of discarded event
    records of the \lt_obj_channel summarized by \lt_p{channel}.

@ingroup api_channel

In \ref api-channel-discard-mode "discard mode", LTTng discards an event
record when there's no sub-buffer left to write it.

lttng_list_channels() sets a pointer to an array of all the
channel summaries of a given \lt_obj_session and \lt_obj_domain.

@param[in] channel
    Summary of the channel of which to get the number of discarded
    event records.
@param[out] count
    <strong>On success</strong>, this function sets \lt_p{*count} to
    the number of discarded event records of the channel summarized
    by \lt_p{channel}.

@returns
    <dl>
      <dt>0
      <dd>Success.

      <dt>-#LTTNG_ERR_INVALID (negative)
      <dd>Unsatisfied precondition.
    </dl>

@pre
    @lt_pre_not_null{channel}
    - You obtained \lt_p{channel} with lttng_list_channels().
    - The lttng_channel_attr::overwrite member of \lt_p{channel->attr}
      is 0.
    @lt_pre_not_null{count}

@sa lttng_channel_get_lost_packet_count() --
    Returns the number of discarded packets (sub-buffers) of a channel.
*/
LTTNG_EXPORT extern int lttng_channel_get_discarded_event_count(const struct lttng_channel *channel,
								uint64_t *count);

/*!
@brief
    Sets \lt_p{*count} to the number of discarded packets (sub-buffers)
    of the \lt_obj_channel summarized by \lt_p{channel}.

@ingroup api_channel

In \ref api-channel-overwrite-mode "overwrite mode", LTTng discards a
whole sub-buffer when there's no sub-buffer left to record an event.

lttng_list_channels() sets a pointer to an array of all the
channel summaries of a given \lt_obj_session and \lt_obj_domain.

@param[in] channel
    Summary of the channel of which to get the number of discarded
    packets.
@param[out] count
    <strong>On success</strong>, this function sets \lt_p{*count} to
    the number of discarded packets of the channel summarized
    by \lt_p{channel}.

@returns
    <dl>
      <dt>0
      <dd>Success.

      <dt>-#LTTNG_ERR_INVALID (negative)
      <dd>Unsatisfied precondition.
    </dl>

@pre
    @lt_pre_not_null{channel}
    - You obtained \lt_p{channel} with lttng_list_channels().
    - The lttng_channel_attr::overwrite member of \lt_p{channel->attr}
      is 1.
    @lt_pre_not_null{count}

@sa lttng_channel_get_discarded_event_count() --
    Returns the number of discarded event records of a channel.
*/
LTTNG_EXPORT extern int lttng_channel_get_lost_packet_count(const struct lttng_channel *channel,
							    uint64_t *count);

/*!
@brief
    Sets \lt_p{*period} to the
    \ref api-channel-monitor-timer "monitor timer" period (µs)
    property of the \lt_obj_channel summary \lt_p{channel}.

@ingroup api_channel

@param[in] channel
    Summary of the channel of which to get the monitor timer period.
@param[out] period
    <strong>On success</strong>, this function sets \lt_p{*period} to
    the monitor timer period (µs) property of \lt_p{channel}.

@returns
    <dl>
      <dt>0
      <dd>Success.

      <dt>-#LTTNG_ERR_INVALID (negative)
      <dd>Unsatisfied precondition.
    </dl>

@pre
    @lt_pre_not_null{channel}
    @lt_pre_not_null{period}

@sa lttng_channel_set_monitor_timer_interval() --
    Sets the monitor timer period property of a channel summary.
*/
LTTNG_EXPORT extern int
lttng_channel_get_monitor_timer_interval(const struct lttng_channel *channel, uint64_t *period);

/*!
@brief
    Sets the \ref api-channel-monitor-timer "monitor timer" period
    property of the channel summary \lt_p{channel} to
    \lt_p{period}&nbsp;µs.

@ingroup api_channel

@param[in] channel
    Channel summary of which to set the monitor timer period
    to \lt_p{period}&nbsp;µs.
@param[in] period
    Monitor timer period property to set.

@returns
    <dl>
      <dt>0
      <dd>Success.

      <dt>-#LTTNG_ERR_INVALID (negative)
      <dd>Unsatisfied precondition.
    </dl>

@pre
    @lt_pre_not_null{channel}

@sa lttng_channel_get_monitor_timer_interval() --
    Returns the monitor timer period property of a channel summary.
*/
LTTNG_EXPORT extern int lttng_channel_set_monitor_timer_interval(struct lttng_channel *channel,
								 uint64_t period);

/*!
@brief
    Sets \lt_p{*period} to the
    \ref api-channel-watchdog-timer "watchdog timer" period (µs)
    property of the \lt_obj_channel summary \lt_p{channel}.

@ingroup api_channel

@param[in] channel
    Summary of the channel of which to get the watchdog timer period.
@param[out] period
    <strong>On success</strong>, this function sets \lt_p{*period} to
    the watchdog timer period (µs) property of \lt_p{channel}.

@retval #LTTNG_CHANNEL_STATUS_OK
    Success.
@retval #LTTNG_CHANNEL_STATUS_INVALID
    Unsatisfied precondition.
@retval #LTTNG_CHANNEL_STATUS_UNSET
    Watchdog timer isn't set.

@pre
    @lt_pre_not_null{channel}
    @lt_pre_not_null{period}

@sa lttng_channel_get_watchdog_timer_interval() --
    Returns the watchdog timer period property of a channel summary.
*/
LTTNG_EXPORT extern enum lttng_channel_status
lttng_channel_get_watchdog_timer_interval(const struct lttng_channel *channel, uint64_t *period);

/*!
@brief
    Sets the \ref api-channel-watchdog-timer "watchdog timer" period
    property of the channel summary \lt_p{channel} to
    \lt_p{period}&nbsp;µs.

@ingroup api_channel

@param[in] channel
    Channel summary of which to set the watchdog timer period
    to \lt_p{period}&nbsp;µs.
@param[in] period
    Watchdog timer period property to set.

@retval #LTTNG_CHANNEL_STATUS_OK
    Success.
@retval #LTTNG_CHANNEL_STATUS__INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{channel}
    - The \lt_obj_domain of \lt_p{channel} is #LTTNG_DOMAIN_UST.
    - The \ref api-channel-buf-ownership-model "buffer ownership model"
      of \lt_p{channel} is #LTTNG_BUFFER_PER_UID.

@sa lttng_channel_set_watchdog_timer_interval() --
    Sets the watchdog timer period property of a channel summary.
*/
LTTNG_EXPORT extern enum lttng_channel_status
lttng_channel_set_watchdog_timer_interval(struct lttng_channel *channel, uint64_t period);

/*!
@brief
    Sets \lt_p{*timeout} to the
    \ref api-channel-blocking-timeout "blocking timeout"
    property of the \lt_obj_channel summary \lt_p{channel}.

@ingroup api_channel

This property only applies to \link #LTTNG_DOMAIN_UST user space\endlink
channels.

@param[in] channel
    Summary of the channel of which to get the blocking timeout.
@param[out] timeout
    @parblock
    <strong>On success</strong>, this function sets \lt_p{*timeout} to
    one of:

    <dl>
      <dt>-1
      <dd>
	The blocking timeout of \lt_p{channel} is infinite.

      <dt>0
      <dd>
	Blocking is disabled for \lt_p{channel}.

      <dt>Otherwise
      <dd>
	The blocking timeout of \lt_p{channel} is
	\lt_p{*timeout}&nbsp;µs.
    </dl>
    @endparblock

@returns
    <dl>
      <dt>0
      <dd>Success.

      <dt>-#LTTNG_ERR_INVALID (negative)
      <dd>Unsatisfied precondition.
    </dl>

@pre
    @lt_pre_not_null{channel}
    - The \lt_obj_domain type of \lt_p{channel} is #LTTNG_DOMAIN_UST.
    @lt_pre_not_null{timeout}

@sa lttng_channel_set_blocking_timeout() --
    Sets the blocking timeout property of a channel summary.
*/
LTTNG_EXPORT extern int lttng_channel_get_blocking_timeout(const struct lttng_channel *channel,
							   int64_t *timeout);

/*!
@brief
    Sets the \ref api-channel-blocking-timeout "blocking timeout"
    property of the channel summary \lt_p{channel} to
    \lt_p{timeout}.

@ingroup api_channel

This property only applies to \link #LTTNG_DOMAIN_UST user space\endlink
channels.

@param[in] channel
    Channel summary of which to set the blocking timeout
    to \lt_p{timeout}.
@param[in] timeout
    @parblock
    One of:

    <dl>
      <dt>-1
      <dd>
	The blocking timeout of \lt_p{channel} is infinite.

      <dt>0
      <dd>
	Blocking is disabled for \lt_p{channel}.

      <dt>Otherwise
      <dd>
	The blocking timeout of \lt_p{channel} is
	\lt_p{timeout}&nbsp;µs.
    </dl>
    @endparblock

@returns
    <dl>
      <dt>0
      <dd>Success.

      <dt>-#LTTNG_ERR_INVALID (negative)
      <dd>Unsatisfied precondition.
    </dl>

@pre
    @lt_pre_not_null{channel}
    - The \lt_obj_domain type of \lt_p{channel} is #LTTNG_DOMAIN_UST.
    - \lt_p{timeout}&nbsp;≥&nbsp;-1

@sa lttng_channel_get_blocking_timeout() --
    Returns the blocking timeout property of a channel summary.
*/
LTTNG_EXPORT extern int lttng_channel_set_blocking_timeout(struct lttng_channel *channel,
							   int64_t timeout);

/*!
@brief
    Sets \lt_p{*policy} to the
    \ref api-channel-buf-alloc-policy "buffer allocation policy"
    property of the \lt_obj_channel summary \lt_p{channel}.

@ingroup api_channel

This property only applies to \link #LTTNG_DOMAIN_UST user space\endlink
channels.

@param[in] channel
    Summary of the channel of which to get the buffer allocation policy.
@param[out] policy
    <strong>On success</strong>, this function sets \lt_p{*policy} to
    the buffer allocation policy of \lt_p{channel}.

@retval #LTTNG_OK
    Success.
@retval #LTTNG_ERR_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{channel}
    - The \lt_obj_domain type of \lt_p{channel} is #LTTNG_DOMAIN_UST.
    @lt_pre_not_null{policy}

@sa lttng_channel_set_allocation_policy() --
    Sets the buffer allocation policy property of a channel summary.
*/
LTTNG_EXPORT extern enum lttng_error_code
lttng_channel_get_allocation_policy(const struct lttng_channel *channel,
				    enum lttng_channel_allocation_policy *policy);

/*!
@brief
    Sets the \ref api-channel-buf-alloc-policy
    "buffer allocation policy" property of the channel
    summary \lt_p{channel} to \lt_p{policy}.

@ingroup api_channel

This property only applies to \link #LTTNG_DOMAIN_UST user space\endlink
channels.

@param[in] channel
    Channel summary of which to set the buffer allocation policy
    to \lt_p{policy}.
@param[in] policy
    Buffer allocation policy to set.

@retval #LTTNG_OK
    Success.
@retval #LTTNG_ERR_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{channel}
    - The \lt_obj_domain type of \lt_p{channel} is #LTTNG_DOMAIN_UST.

@sa lttng_channel_get_allocation_policy() --
    Returns the buffer allocation policy property of a channel summary.
*/
LTTNG_EXPORT extern enum lttng_error_code
lttng_channel_set_allocation_policy(struct lttng_channel *channel,
				    enum lttng_channel_allocation_policy policy);

LTTNG_EXPORT extern enum lttng_channel_status
lttng_channel_get_preallocation_policy(const struct lttng_channel *channel,
				       enum lttng_channel_preallocation_policy *policy);

LTTNG_EXPORT extern enum lttng_channel_status
lttng_channel_set_preallocation_policy(struct lttng_channel *channel,
				       enum lttng_channel_preallocation_policy policy);

LTTNG_EXPORT extern enum lttng_channel_status
lttng_channel_get_automatic_memory_reclamation_policy(const struct lttng_channel *channel,
						      uint64_t *maximal_age_us);

LTTNG_EXPORT extern enum lttng_channel_status
lttng_channel_set_automatic_memory_reclamation_policy(struct lttng_channel *channel,
						      uint64_t maximal_age_us);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_CHANNEL_H */
