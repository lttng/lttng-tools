#ifndef HEALTH_CONSUMERD_H
#define HEALTH_CONSUMERD_H

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

#include <lttng/health-internal.h>

enum health_type_consumerd {
	HEALTH_CONSUMERD_TYPE_CHANNEL		= 0,
	HEALTH_CONSUMERD_TYPE_METADATA		= 1,
	HEALTH_CONSUMERD_TYPE_DATA		= 2,
	HEALTH_CONSUMERD_TYPE_SESSIOND		= 3,
	HEALTH_CONSUMERD_TYPE_METADATA_TIMER	= 4,

	NR_HEALTH_CONSUMERD_TYPES,
};

/* Consumerd health monitoring */
extern struct health_app *health_consumerd;

void *thread_manage_health(void *data);

extern int health_quit_pipe[2];

#endif /* HEALTH_CONSUMERD_H */
