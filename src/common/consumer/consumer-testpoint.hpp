#ifndef CONSUMERD_TESTPOINT_H
#define CONSUMERD_TESTPOINT_H

/*
 * Copyright (C) 2012 Christian Babeux <christian.babeux@efficios.com>
 * Copyright (C) 2014 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include <common/testpoint/testpoint.hpp>

/* Testpoints, internal use only */
TESTPOINT_DECL(consumerd_thread_channel);
TESTPOINT_DECL(consumerd_thread_metadata);
TESTPOINT_DECL(consumerd_thread_data);
TESTPOINT_DECL(consumerd_thread_data_poll);
TESTPOINT_DECL(consumerd_thread_sessiond);
TESTPOINT_DECL(consumerd_thread_metadata_timer);

#endif /* CONSUMERD_TESTPOINT_H */
