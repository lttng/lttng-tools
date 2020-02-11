#ifndef HEALTH_SESSIOND_H
#define HEALTH_SESSIOND_H

/*
 * Copyright (C) 2012 David Goulet <dgoulet@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include <lttng/health-internal.h>
#include <stdbool.h>

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
	HEALTH_SESSIOND_TYPE_ROTATION		= 9,
	HEALTH_SESSIOND_TYPE_TIMER		= 10,
	HEALTH_SESSIOND_TYPE_ACTION_EXECUTOR	= 11,

	NR_HEALTH_SESSIOND_TYPES,
};

/* Application health monitoring */
extern struct health_app *health_sessiond;

bool launch_health_management_thread(void);

#endif /* HEALTH_SESSIOND_H */
