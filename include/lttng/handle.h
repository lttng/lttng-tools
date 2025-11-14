/*
 * SPDX-FileCopyrightText: 2014 David Goulet <dgoulet@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_HANDLE_H
#define LTTNG_HANDLE_H

#include <lttng/domain.h>
#include <lttng/lttng-export.h>

#ifdef __cplusplus
extern "C" {
#endif

/*!
@addtogroup api_session
@{
*/

/*
 * Handle used as a context for commands.
 *
 * The structures should be initialized to zero before use.
 */
#define LTTNG_HANDLE_PADDING1 16

/*!
@brief
    Recording session handle.

Such a structure is a pair of a \ref api_session "recording session"
name and a \ref api-channel-domain "tracing domain" summary.

Some functions which accept a recording session handle parameter ignore
the recording session name or the tracing domain summary.

Create a recording session handle with lttng_create_handle().

Destroy a recording session handle with lttng_destroy_handle().
*/
struct lttng_handle {
	/// \ref api_session "Recording session" name.
	char session_name[LTTNG_NAME_MAX];

	/// \ref api-channel-domain "Tracing domain" summary.
	struct lttng_domain domain;

	char padding[LTTNG_HANDLE_PADDING1];
};

/*!
@brief
    Creates and returns a recording session handle from the
    \ref api_session "recording session" name
    \lt_p{session_name} and the optional
    \ref api-channel-domain "tracing domain" summary \lt_p{domain}.

@param[in] session_name
    @parblock
    Recording session name part of the recording session handle to
    create.

    May be \c NULL.
    @endparblock
@param[in] domain
    @parblock
    Tracing domain summary part of the recording session handle to
    create.

    May be \c NULL.
    @endparblock

@returns
    @parblock
    New recording session handle.

    Destroy the returned handle with lttng_destroy_handle().
    @endparblock

@sa lttng_destroy_handle() --
    Destroys a recording session handle.
*/
LTTNG_EXPORT extern struct lttng_handle *lttng_create_handle(const char *session_name,
							     const struct lttng_domain *domain);

/*!
@brief
    Destroys the recording session handle \lt_p{handle}.

@note
    @parblock
    This function doesn't destroy the recording session named
    \lt_p{handle->session_name}, but only the handle itself.

    Use lttng_destroy_session_ext() to destroy a recording session.
    @endparblock

@param[in] handle
    @parblock
    Recording session handle to destroy.

    May be \c NULL.
    @endparblock
*/
LTTNG_EXPORT extern void lttng_destroy_handle(struct lttng_handle *handle);

/// @}

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_HANDLE_H */
