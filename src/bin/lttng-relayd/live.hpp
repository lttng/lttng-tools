#ifndef LTTNG_RELAYD_LIVE_H
#define LTTNG_RELAYD_LIVE_H

/*
 * Copyright (C) 2013 Julien Desfossez <jdesfossez@efficios.com>
 * Copyright (C) 2013 David Goulet <dgoulet@efficios.com>
 * Copyright (C) 2015 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "lttng-relayd.hpp"

#include <common/uri.hpp>

int relayd_live_create(struct lttng_uri *live_uri);
int relayd_live_stop();
int relayd_live_join();

int make_viewer_streams(struct relay_session *relay_session,
			struct relay_viewer_session *viewer_session,
			enum lttng_viewer_seek seek_t,
			unsigned int *nb_total,
			unsigned int *nb_unsent,
			unsigned int *nb_created,
			bool *closed);
#endif /* LTTNG_RELAYD_LIVE_H */
