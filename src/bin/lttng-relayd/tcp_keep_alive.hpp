/*
 * Copyright (C) 2017 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef RELAYD_TCP_KEEP_ALIVE_H
#define RELAYD_TCP_KEEP_ALIVE_H

#include <common/macros.hpp>

int socket_apply_keep_alive_config(int socket_fd);

#endif /* RELAYD_TCP_KEEP_ALIVE_H */
