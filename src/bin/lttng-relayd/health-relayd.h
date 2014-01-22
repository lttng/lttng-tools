#ifndef HEALTH_RELAYD_H
#define HEALTH_RELAYD_H

/*
 * Copyright (C) 2012 - David Goulet <dgoulet@efficios.com>
 * Copyright (C) 2013 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <limits.h>
#include <lttng/health-internal.h>

#define LTTNG_RELAYD_HEALTH_ENV		"LTTNG_RELAYD_HEALTH"

enum health_type_relayd {
	HEALTH_RELAYD_TYPE_DISPATCHER		= 0,
	HEALTH_RELAYD_TYPE_WORKER		= 1,
	HEALTH_RELAYD_TYPE_LISTENER		= 2,
	HEALTH_RELAYD_TYPE_LIVE_DISPATCHER	= 3,
	HEALTH_RELAYD_TYPE_LIVE_WORKER		= 4,
	HEALTH_RELAYD_TYPE_LIVE_LISTENER	= 5,

	NR_HEALTH_RELAYD_TYPES,
};

extern struct health_app *health_relayd;

extern int health_quit_pipe[2];

void *thread_manage_health(void *data);

#endif /* HEALTH_RELAYD_H */
