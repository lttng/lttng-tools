/*
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 * SPDX-FileCopyrightText: 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * SPDX-FileCopyrightText: 2013 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef SESSIOND_APPLICATION_REGISTRATION_THREAD_H
#define SESSIOND_APPLICATION_REGISTRATION_THREAD_H

#include "lttng-sessiond.hpp"

#include <stdbool.h>

struct lttng_thread *launch_application_registration_thread(struct ust_cmd_queue *cmd_queue);

#endif /* SESSIOND_APPLICATION_REGISTRATION_THREAD_H */
