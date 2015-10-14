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
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define _LGPL_SOURCE
#include <assert.h>

#include <common/common.h>

#include "cmd-generic.h"

int cmd_recv(struct lttcomm_sock *sock, void *buf, size_t len)
{
	int ret;

	assert(sock);
	assert(buf);

	ret = sock->ops->recvmsg(sock, buf, len, 0);
	if (ret < len) {
		if (ret == 0) {
			/* Orderly shutdown. Not necessary to print an error. */
			DBG("Socket %d did an orderly shutdown", sock->fd);
		} else {
			ERR("Relay didn't receive valid add_stream struct size. "
					"Expected %zu, got %d", len, ret);
		}
		ret = -1;
		goto error;
	}

error:
	return ret;
}
