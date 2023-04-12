#ifndef RELAYD_CMD_2_1_H
#define RELAYD_CMD_2_1_H

/*
 * Copyright (C) 2013 Julien Desfossez <jdesfossez@efficios.com>
 * Copyright (C) 2013 David Goulet <dgoulet@efficios.com>
 * Copyright (C) 2015 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "lttng-relayd.hpp"

#include <common/buffer-view.hpp>

int cmd_recv_stream_2_1(const struct lttng_buffer_view *payload,
			char **path_name,
			char **channel_name);

#endif /* RELAYD_CMD_2_1_H */
