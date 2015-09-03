#ifndef LTTNG_RELAYD_LIVE_H
#define LTTNG_RELAYD_LIVE_H

/*
 * Copyright (C) 2013 - Julien Desfossez <jdesfossez@efficios.com>
 *                      David Goulet <dgoulet@efficios.com>
 *               2015 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

#include <common/uri.h>

#include "lttng-relayd.h"

int relayd_live_create(struct lttng_uri *live_uri);
int relayd_live_stop(void);
int relayd_live_join(void);

struct relay_viewer_stream *live_find_viewer_stream_by_id(uint64_t stream_id);

#endif /* LTTNG_RELAYD_LIVE_H */
