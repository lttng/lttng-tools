/*
 * SPDX-FileCopyrightText: 2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 *
 */

#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER ust_tests_daemon

#if !defined(_TRACEPOINT_UST_TESTS_DAEMON_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _TRACEPOINT_UST_TESTS_DAEMON_H

#include <lttng/tracepoint.h>

#include <sys/types.h>

TRACEPOINT_EVENT(ust_tests_daemon,
		 before_daemon,
		 TP_ARGS(pid_t, pid),
		 TP_FIELDS(ctf_integer(pid_t, pid, pid)))

TRACEPOINT_EVENT(ust_tests_daemon,
		 after_daemon_child,
		 TP_ARGS(pid_t, pid),
		 TP_FIELDS(ctf_integer(pid_t, pid, pid)))

TRACEPOINT_EVENT(ust_tests_daemon, after_daemon_parent, TP_ARGS(), TP_FIELDS())

#endif /* _TRACEPOINT_UST_TESTS_DAEMON_H */

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "./ust_tests_daemon.h"

/* This part must be outside ifdef protection */
#include <lttng/tracepoint-event.h>
