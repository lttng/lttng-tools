/*
 * Copyright (C) 2011 EfficiOS Inc.
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright (C) 2013 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef SESSIOND_UST_DISPATCH_THREAD_H
#define SESSIOND_UST_DISPATCH_THREAD_H

#include "lttng-sessiond.hpp"

#include <stdbool.h>

bool launch_ust_dispatch_thread(struct ust_cmd_queue *cmd_queue,
				int apps_cmd_pipe_write_fd,
				int apps_cmd_notify_write_fd);

#endif /* SESSIOND_UST_DISPATCH_THREAD_H */
