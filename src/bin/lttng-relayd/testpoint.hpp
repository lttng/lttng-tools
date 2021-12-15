#ifndef RELAYD_TESTPOINT_H
#define RELAYD_TESTPOINT_H

/*
 * Copyright (C) 2012 Christian Babeux <christian.babeux@efficios.com>
 * Copyright (C) 2014 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include <common/testpoint/testpoint.hpp>

/* Testpoints, internal use only */
TESTPOINT_DECL(relayd_thread_dispatcher);
TESTPOINT_DECL(relayd_thread_worker);
TESTPOINT_DECL(relayd_thread_listener);
TESTPOINT_DECL(relayd_thread_live_dispatcher);
TESTPOINT_DECL(relayd_thread_live_worker);
TESTPOINT_DECL(relayd_thread_live_listener);

#endif /* SESSIOND_TESTPOINT_H */
