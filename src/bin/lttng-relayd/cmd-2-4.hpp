#ifndef RELAYD_CMD_2_4_H
#define RELAYD_CMD_2_4_H

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

int cmd_create_session_2_4(const struct lttng_buffer_view *payload,
			   char *session_name,
			   char *hostname,
			   uint32_t *live_timer,
			   bool *snapshot);

#endif /* RELAYD_CMD_2_4_H */
