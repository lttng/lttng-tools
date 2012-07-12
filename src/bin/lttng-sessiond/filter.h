/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 * Copyright (C) 2012 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _LTT_FILTER_H
#define _LTT_FILTER_H

#include <lttng/lttng.h>

#include "trace-kernel.h"
#include "trace-ust.h"
#include "ust-ctl.h"

struct lttng_filter_bytecode;

int filter_ust_set(struct ltt_ust_session *usess, int domain,
		struct lttng_filter_bytecode *bytecode, char *event_name,
		char *channel_name);

#endif /* _LTT_FILTER_H */
