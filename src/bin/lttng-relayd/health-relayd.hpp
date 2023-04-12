#ifndef HEALTH_RELAYD_H
#define HEALTH_RELAYD_H

/*
 * Copyright (C) 2012 David Goulet <dgoulet@efficios.com>
 * Copyright (C) 2013 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include <lttng/health-internal.hpp>

#include <limits.h>

#define LTTNG_RELAYD_HEALTH_ENV "LTTNG_RELAYD_HEALTH"

enum health_type_relayd {
	HEALTH_RELAYD_TYPE_DISPATCHER = 0,
	HEALTH_RELAYD_TYPE_WORKER = 1,
	HEALTH_RELAYD_TYPE_LISTENER = 2,
	HEALTH_RELAYD_TYPE_LIVE_DISPATCHER = 3,
	HEALTH_RELAYD_TYPE_LIVE_WORKER = 4,
	HEALTH_RELAYD_TYPE_LIVE_LISTENER = 5,

	NR_HEALTH_RELAYD_TYPES,
};

extern struct health_app *health_relayd;

extern int health_quit_pipe[2];

void *thread_manage_health_relayd(void *data);

#endif /* HEALTH_RELAYD_H */
