#ifndef HEALTH_CONSUMERD_H
#define HEALTH_CONSUMERD_H

/*
 * Copyright (C) 2012 David Goulet <dgoulet@efficios.com>
 * Copyright (C) 2013 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <lttng/health-internal.hpp>

enum health_type_consumerd {
	HEALTH_CONSUMERD_TYPE_CHANNEL = 0,
	HEALTH_CONSUMERD_TYPE_METADATA = 1,
	HEALTH_CONSUMERD_TYPE_DATA = 2,
	HEALTH_CONSUMERD_TYPE_SESSIOND = 3,
	HEALTH_CONSUMERD_TYPE_METADATA_TIMER = 4,

	NR_HEALTH_CONSUMERD_TYPES,
};

/* Consumerd health monitoring */
extern struct health_app *health_consumerd;

void *thread_manage_health_consumerd(void *data);

extern int health_quit_pipe[2];

#endif /* HEALTH_CONSUMERD_H */
