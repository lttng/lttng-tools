/*
 * SPDX-FileCopyrightText: 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_ENDPOINT_H
#define LTTNG_ENDPOINT_H

#include <lttng/lttng-export.h>

#ifdef __cplusplus
extern "C" {
#endif

/*!
@struct lttng_endpoint

@brief
    LTTng endpoint (opaque type).

@ingroup api_notif
*/
struct lttng_endpoint;

/*!
@brief
    LTTng session daemon notification endpoint.

@ingroup api_notif

This endpoint follows the typical
\ref api-gen-sessiond-conn "session daemon connection" procedure.

The purpose of this endpoint is to create a notification channel with
lttng_notification_channel_create().
*/
LTTNG_EXPORT extern struct lttng_endpoint *lttng_session_daemon_notification_endpoint;

/*!
@brief
    LTTng session daemon command endpoint.

@ingroup api_error

This endpoint follows the typical
\ref api-gen-sessiond-conn "session daemon connection" procedure.

The purpose of this endpoint is to execute an
error query with lttng_error_query_execute().
*/
LTTNG_EXPORT extern struct lttng_endpoint *lttng_session_daemon_command_endpoint;

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_ENDPOINT_H */
