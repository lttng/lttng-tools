/*
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 * SPDX-FileCopyrightText: 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * SPDX-FileCopyrightText: 2013 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef CLIENT_SESSIOND_H
#define CLIENT_SESSIOND_H

#include "consumer.hpp"
#include "thread.hpp"

#include <sys/types.h>

struct lttng_thread *launch_client_thread();
int start_consumerd(struct consumer_data *consumer_data);

#endif /* CLIENT_SESSIOND_H */
