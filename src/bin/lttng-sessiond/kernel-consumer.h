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

#include <sys/types.h>

#include <common/sessiond-comm/sessiond-comm.h>

#include "trace-kernel.h"

int kernel_consumer_send_channel_stream(struct consumer_socket *sock,
		struct ltt_kernel_channel *channel, struct ltt_kernel_session *session,
		unsigned int monitor);

int kernel_consumer_send_session(struct consumer_socket *sock,
		struct ltt_kernel_session *session);

int kernel_consumer_add_stream(struct consumer_socket *sock,
		struct ltt_kernel_channel *channel, struct ltt_kernel_stream *stream,
		struct ltt_kernel_session *session, unsigned int monitor);

int kernel_consumer_add_metadata(struct consumer_socket *sock,
		struct ltt_kernel_session *session, unsigned int monitor);

int kernel_consumer_add_channel(struct consumer_socket *sock,
		struct ltt_kernel_channel *channel, struct ltt_kernel_session *session,
		unsigned int monitor);

int kernel_consumer_destroy_channel(struct consumer_socket *socket,
		struct ltt_kernel_channel *channel);

int kernel_consumer_destroy_metadata(struct consumer_socket *socket,
		struct ltt_kernel_metadata *metadata);

int kernel_consumer_streams_sent(struct consumer_socket *sock,
		struct ltt_kernel_session *session, uint64_t channel_key);
