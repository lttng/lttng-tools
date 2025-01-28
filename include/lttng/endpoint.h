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

/*
 * Default LTTng session daemon notification endpoint singleton.
 *
 * For use during the creation of a notification channel. This endpoint
 * implements the following policy to connect to a session daemon's
 * notification delivery channel:
 *   - If the caller is root or part of the tracing group:
 *     - Attempt to connect to the "root" (global) session daemon,
 *     - Fallback to the session daemon running as the caller's user.
 *   - Otherwise (caller is an unpriviliged user):
 *     - Attempt to connect to the session daemon running as the caller's user.
 */
LTTNG_EXPORT extern struct lttng_endpoint *lttng_session_daemon_notification_endpoint;

/*
 * Default LTTng session daemon command endpoint singleton.
 *
 * For use as part of the invocation of a command. This endpoint
 * implements the following policy to connect to a session daemon's
 * command channel:
 *   - If the caller is root or part of the tracing group:
 *     - Attempt to connect to the "root" (global) session daemon,
 *     - Fallback to the session daemon running as the caller's user.
 *   - Otherwise (caller is an unpriviliged user):
 *     - Attempt to connect to the session daemon running as the caller's user.
 */
LTTNG_EXPORT extern struct lttng_endpoint *lttng_session_daemon_command_endpoint;

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_ENDPOINT_H */
