#ifndef LTTNG_DAEMONIZE_H
#define LTTNG_DAEMONIZE_H

/*
 * Copyright (C) 2013 David Goulet <dgoulet@efficios.com>
 * Copyright (C) 2014 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include <common/macros.hpp>

#include <unistd.h>

/*
 * Daemonize this process by forking and making the parent wait for the child
 * to signal it indicating readiness. Once received, the parent successfully
 * quits.
 *
 * The child process undergoes the same action that daemon(3) does meaning
 * setsid, chdir, and dup /dev/null into 0, 1 and 2.
 *
 * Return 0 on success else -1 on error.
 */
int lttng_daemonize(pid_t *child_ppid, int *completion_flag, int close_fds);

#endif /* LTTNG_DAEMONIZE_H */
