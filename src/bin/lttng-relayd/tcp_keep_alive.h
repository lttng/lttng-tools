#ifndef RELAYD_TCP_KEEP_ALIVE_H
#define RELAYD_TCP_KEEP_ALIVE_H

/*
 * Copyright (C) 2017 - Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <common/macros.h>

LTTNG_HIDDEN
int socket_apply_keep_alive_config(int socket_fd);

#endif /* RELAYD_TCP_KEEP_ALIVE_H */
