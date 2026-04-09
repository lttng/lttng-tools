/*
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef _UST_CONSUMER_H
#define _UST_CONSUMER_H

#include "ust-app.hpp"

#include <common/trace-chunk.hpp>

#include <stdint.h>

namespace lttng {
namespace sessiond {
namespace ust {
class trace_class;
} /* namespace ust */
} /* namespace sessiond */
} /* namespace lttng */

int ust_consumer_ask_channel(lttng::sessiond::ust::app_session *ua_sess,
			     struct ust_app_channel *ua_chan,
			     struct consumer_output *consumer,
			     struct consumer_socket *socket,
			     lttng::sessiond::ust::trace_class *registry,
			     struct lttng_trace_chunk *trace_chunk,
			     enum lttng_trace_format trace_format,
			     unsigned int output_traces,
			     unsigned int live_timer_interval);

int ust_consumer_get_channel(struct consumer_socket *socket, struct ust_app_channel *ua_chan);

int ust_consumer_destroy_channel(struct consumer_socket *socket, struct ust_app_channel *ua_chan);

int ust_consumer_send_stream_to_ust(lttng::sessiond::ust::app *app,
				    struct ust_app_channel *channel,
				    lttng::sessiond::ust::app_stream *stream);

int ust_consumer_send_channel_to_ust(lttng::sessiond::ust::app *app,
				     lttng::sessiond::ust::app_session *ua_sess,
				     struct ust_app_channel *channel);

#ifdef HAVE_LIBLTTNG_UST_CTL
int ust_consumer_metadata_request(struct consumer_socket *sock);
#else
static inline int ust_consumer_metadata_request(struct consumer_socket *sock
						__attribute__((unused)))
{
	return -ENOSYS;
}
#endif /* HAVE_LIBLTTNG_UST_CTL */

#endif /* _UST_CONSUMER_H */
