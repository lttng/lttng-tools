/*
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 *
 */

#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER ust_tests_fork

#if !defined(_TRACEPOINT_UST_TESTS_FORK_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _TRACEPOINT_UST_TESTS_FORK_H

#include <lttng/tracepoint.h>

#include <sys/types.h>

TRACEPOINT_EVENT(ust_tests_fork,
		 before_fork,
		 TP_ARGS(pid_t, pid),
		 TP_FIELDS(ctf_integer(pid_t, pid, pid)))

TRACEPOINT_EVENT(ust_tests_fork,
		 after_fork_child,
		 TP_ARGS(pid_t, pid),
		 TP_FIELDS(ctf_integer(pid_t, pid, pid)))

TRACEPOINT_EVENT(ust_tests_fork,
		 after_fork_parent,
		 TP_ARGS(pid_t, pid),
		 TP_FIELDS(ctf_integer(pid_t, pid, pid)))

TRACEPOINT_EVENT(ust_tests_fork,
		 after_exec,
		 TP_ARGS(pid_t, pid),
		 TP_FIELDS(ctf_integer(pid_t, pid, pid)))

#endif /* _TRACEPOINT_UST_TESTS_FORK_H */

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "./ust_tests_fork.h"

/* This part must be outside ifdef protection */
#include <lttng/tracepoint-event.h>
