/*
 * Copyright (C) 2012 David Goulet <dgoulet@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "trace-kernel.hpp"

#include <common/sessiond-comm/sessiond-comm.hpp>

#include <sys/types.h>

int kernel_consumer_send_channel_streams(struct consumer_socket *sock,
					 struct ltt_kernel_channel *channel,
					 struct ltt_kernel_session *session,
					 unsigned int monitor);

int kernel_consumer_send_session(struct consumer_socket *sock, struct ltt_kernel_session *session);

int kernel_consumer_add_metadata(struct consumer_socket *sock,
				 struct ltt_kernel_session *session,
				 unsigned int monitor);

int kernel_consumer_destroy_channel(struct consumer_socket *socket,
				    struct ltt_kernel_channel *channel);

int kernel_consumer_destroy_metadata(struct consumer_socket *socket,
				     struct ltt_kernel_metadata *metadata);

int kernel_consumer_streams_sent(struct consumer_socket *sock,
				 struct ltt_kernel_session *session,
				 uint64_t channel_key);
