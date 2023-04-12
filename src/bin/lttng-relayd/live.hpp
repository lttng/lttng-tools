#ifndef LTTNG_RELAYD_LIVE_H
#define LTTNG_RELAYD_LIVE_H

/*
 * Copyright (C) 2013 Julien Desfossez <jdesfossez@efficios.com>
 * Copyright (C) 2013 David Goulet <dgoulet@efficios.com>
 * Copyright (C) 2015 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "lttng-relayd.hpp"

#include <common/uri.hpp>

int relayd_live_create(struct lttng_uri *live_uri);
int relayd_live_stop(void);
int relayd_live_join(void);

#endif /* LTTNG_RELAYD_LIVE_H */
