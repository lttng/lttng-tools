/*
 * Copyright (C) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_ENDPOINT_H
#define LTTNG_ENDPOINT_H

#ifdef __cplusplus
extern "C" {
#endif

/* Default LTTng session daemon endpoint singleton. */
extern struct lttng_endpoint *lttng_session_daemon_notification_endpoint;

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_ENDPOINT_H */
