/*
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 * SPDX-FileCopyrightText: 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * SPDX-FileCopyrightText: 2013 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef SESSIOND_CONSUMER_MANAGEMENT_THREAD_H
#define SESSIOND_CONSUMER_MANAGEMENT_THREAD_H

#include "lttng-sessiond.hpp"

#include <stdbool.h>

bool launch_consumer_management_thread(struct consumer_data *consumer_data);

#endif /* SESSIOND_CONSUMER_MANAGEMENT_THREAD_H */
