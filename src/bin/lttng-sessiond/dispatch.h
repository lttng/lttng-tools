/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *                      Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *               2013 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
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

#ifndef SESSIOND_UST_DISPATCH_THREAD_H
#define SESSIOND_UST_DISPATCH_THREAD_H

#include <stdbool.h>
#include "lttng-sessiond.h"

bool launch_ust_dispatch_thread(struct ust_cmd_queue *cmd_queue,
		int apps_cmd_pipe_write_fd,
		int apps_cmd_notify_write_fd);

#endif /* SESSIOND_UST_DISPATCH_THREAD_H */
