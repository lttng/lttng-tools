#ifndef RELAYD_UTILS_H
#define RELAYD_UTILS_H

/*
 * SPDX-FileCopyrightText: 2012 Julien Desfossez <jdesfossez@efficios.com>
 * SPDX-FileCopyrightText: 2012 David Goulet <dgoulet@efficios.com>
 * SPDX-FileCopyrightText: 2015 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

char *create_output_path(const char *path_name);
void create_lttng_rundir_with_perm(const char *rundir);

#endif /* RELAYD_UTILS_H */
