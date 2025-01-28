/*
 * SPDX-FileCopyrightText: 2011 David Goulet <dgoulet@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef _MODPROBE_H
#define _MODPROBE_H

void modprobe_remove_lttng_all();
void modprobe_remove_lttng_control();
void modprobe_remove_lttng_data();
int modprobe_lttng_control();
int modprobe_lttng_data();

#endif /* _MODPROBE_H */
