/*
 * SPDX-FileCopyrightText: 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <lttng/endpoint-internal.hpp>

static struct lttng_endpoint lttng_session_daemon_notification_endpoint_instance = {
	.type = LTTNG_ENDPOINT_TYPE_DEFAULT_SESSIOND_NOTIFICATION,
};

static struct lttng_endpoint lttng_session_daemon_command_endpoint_instance = {
	.type = LTTNG_ENDPOINT_TYPE_DEFAULT_SESSIOND_COMMAND,
};

struct lttng_endpoint *lttng_session_daemon_notification_endpoint =
	&lttng_session_daemon_notification_endpoint_instance;

struct lttng_endpoint *lttng_session_daemon_command_endpoint =
	&lttng_session_daemon_command_endpoint_instance;
