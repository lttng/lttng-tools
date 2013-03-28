/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
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

#ifndef _UST_CONSUMER_H
#define _UST_CONSUMER_H

#include "consumer.h"
#include "ust-app.h"

int ust_consumer_ask_channel(struct ust_app_session *ua_sess,
		struct ust_app_channel *ua_chan, struct consumer_output *consumer,
		struct consumer_socket *socket, struct ust_registry_session *registry);

int ust_consumer_get_channel(struct consumer_socket *socket,
		struct ust_app_channel *ua_chan);

int ust_consumer_destroy_channel(struct consumer_socket *socket,
		struct ust_app_channel *ua_chan);

int ust_consumer_send_stream_to_ust(struct ust_app *app,
		struct ust_app_channel *channel, struct ust_app_stream *stream);

int ust_consumer_send_channel_to_ust(struct ust_app *app,
		struct ust_app_session *ua_sess, struct ust_app_channel *channel);

#if HAVE_LIBLTTNG_UST_CTL
int ust_consumer_metadata_request(struct consumer_socket *sock);
#else
static inline
int ust_consumer_metadata_request(struct consumer_socket *sock)
{
	return -ENOSYS;
}
#endif /* HAVE_LIBLTTNG_UST_CTL */

#endif /* _UST_CONSUMER_H */
