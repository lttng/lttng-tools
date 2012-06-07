/*
 * Copyright (C) 2012 - David Goulet <dgoulet@efficios.com>
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

#ifndef _KERNEL_CONSUMER_H
#define _KERNEL_CONSUMER_H

#include <sys/types.h>

#include "consumer.h"
#include "trace-kernel.h"

int kernel_consumer_send_channel_stream(struct consumer_data *consumer_data,
		int sock, struct ltt_kernel_channel *channel, uid_t uid, gid_t gid);
int kernel_consumer_send_session(struct consumer_data *consumer_data,
		struct ltt_kernel_session *session);

#endif /* _KERNEL_CONSUMER_H */
