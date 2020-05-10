/*
 * Copyright (C) 2011 Julien Desfossez <julien.desfossez@polymtl.ca>
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright (C) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef _LTTNG_KCONSUMER_H
#define _LTTNG_KCONSUMER_H

#include <stdbool.h>
#include <common/consumer/consumer.h>

int lttng_kconsumer_take_snapshot(struct lttng_consumer_stream *stream);
int lttng_kconsumer_sample_snapshot_positions(
		struct lttng_consumer_stream *stream);
int lttng_kconsumer_get_produced_snapshot(struct lttng_consumer_stream *stream,
        unsigned long *pos);
int lttng_kconsumer_get_consumed_snapshot(struct lttng_consumer_stream *stream,
		unsigned long *pos);
int lttng_kconsumer_recv_cmd(struct lttng_consumer_local_data *ctx,
		int sock, struct pollfd *consumer_sockpoll);
int lttng_kconsumer_on_recv_stream(struct lttng_consumer_stream *stream);
int lttng_kconsumer_data_pending(struct lttng_consumer_stream *stream);
int lttng_kconsumer_sync_metadata(struct lttng_consumer_stream *metadata);

#endif /* _LTTNG_KCONSUMER_H */
