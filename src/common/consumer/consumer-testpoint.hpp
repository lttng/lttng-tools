#ifndef CONSUMERD_TESTPOINT_H
#define CONSUMERD_TESTPOINT_H

/*
 * SPDX-FileCopyrightText: 2012 Christian Babeux <christian.babeux@efficios.com>
 * SPDX-FileCopyrightText: 2014 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

#endif /* CONSUMERD_TESTPOINT_H */
