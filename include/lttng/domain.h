/*
 * Copyright (C) 2014 David Goulet <dgoulet@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_DOMAIN_H
#define LTTNG_DOMAIN_H

#ifdef __cplusplus
extern "C" {
#endif

/*!
@addtogroup api_channel
@{
*/

#include <lttng/constant.h>
#include <lttng/lttng-export.h>

/*!
@brief
    Tracing domain type (tracer type).
*/
enum lttng_domain_type {
	/// None.
	LTTNG_DOMAIN_NONE = 0,

	/// Linux kernel.
	LTTNG_DOMAIN_KERNEL = 1,

	/// User space.
	LTTNG_DOMAIN_UST = 2,

	/// <code>java.util.logging</code> (JUL).
	LTTNG_DOMAIN_JUL = 3,

	/// Apache log4j.
	LTTNG_DOMAIN_LOG4J = 4,

	/// Python logging.
	LTTNG_DOMAIN_PYTHON = 5,
};

/*!
@brief
    Buffering scheme of a channel.

See \ref api-channel-buf-scheme "Buffering scheme" to learn more.
*/
enum lttng_buffer_type {
	/// Per-process buffering.
	LTTNG_BUFFER_PER_PID,

	/// Per-user buffering.
	LTTNG_BUFFER_PER_UID,

	/// Global (Linux kernel) buffering.
	LTTNG_BUFFER_GLOBAL,
};

/*
 * The structures should be initialized to zero before use.
 */
#define LTTNG_DOMAIN_PADDING1 12
#define LTTNG_DOMAIN_PADDING2 LTTNG_SYMBOL_NAME_LEN + 32

/*!
@brief
    Tracing domain summary.

Such a structure is involved:

- As a member of a \link #lttng_handle recording session handle\endlink.

  Some functions which require both a \lt_obj_session
  and a tracing domain accept an #lttng_handle structure.

- When you list the tracing domains of a recording session with
  lttng_list_domains().

- When you create a \link #lttng_channel channel summary
  structure\endlink with lttng_channel_create().

You must initialize such a structure to zeros before setting its
members and using it, for example:

@code
struct lttng_domain domain;

memset(&domain, 0, sizeof(domain));
@endcode
*/
struct lttng_domain {
	/// Tracing domain type.
	enum lttng_domain_type type;

	/*!
	@brief
	    Buffering scheme of all the channels associated to this tracing
	    domain.
	*/
	enum lttng_buffer_type buf_type;

	char padding[LTTNG_DOMAIN_PADDING1];

	union {
		pid_t pid;
		char exec_name[LTTNG_NAME_MAX];
		char padding[LTTNG_DOMAIN_PADDING2];
	} attr;
};

/// @}

/*!
@brief
    Sets \lt_p{*domains} to the summaries of the tracing domains which
    contain at least one channel within the recording session
    named \lt_p{session_name}.

@ingroup api_session

@param[in] session_name
    Name of the recording session for which to get the tracing domain
    summaries.
@param[out] domains
    @parblock
    <strong>On success</strong>, this function sets \lt_p{*domains} to
    the summaries of the tracing domains.

    Free \lt_p{*domains} with <code>free()</code>.
    @endparblock

@returns
    The number of items in \lt_p{*domains} on success, or a \em negative
    #lttng_error_code enumerator otherwise.

@lt_pre_conn
@lt_pre_not_null{session_name}
@lt_pre_sess_exists{session_name}
@lt_pre_not_null{domains}
*/
LTTNG_EXPORT extern int lttng_list_domains(const char *session_name, struct lttng_domain **domains);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_DOMAIN_H */
