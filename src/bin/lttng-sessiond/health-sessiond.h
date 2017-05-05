#ifndef HEALTH_SESSIOND_H
#define HEALTH_SESSIOND_H

/*
 * Copyright (C) 2012 - David Goulet <dgoulet@efficios.com>
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

enum health_type_sessiond {
	HEALTH_SESSIOND_TYPE_CMD		= 0,
	HEALTH_SESSIOND_TYPE_APP_MANAGE		= 1,
	HEALTH_SESSIOND_TYPE_APP_REG		= 2,
	HEALTH_SESSIOND_TYPE_KERNEL		= 3,
	HEALTH_SESSIOND_TYPE_CONSUMER		= 4,
	HEALTH_SESSIOND_TYPE_HT_CLEANUP		= 5,
	HEALTH_SESSIOND_TYPE_APP_MANAGE_NOTIFY	= 6,
	HEALTH_SESSIOND_TYPE_APP_REG_DISPATCH	= 7,
	HEALTH_SESSIOND_TYPE_NOTIFICATION	= 8,

	NR_HEALTH_SESSIOND_TYPES,
};

/* Application health monitoring */
extern struct health_app *health_sessiond;

#endif /* HEALTH_SESSIOND_H */
