/*
 * Copyright (C) 2011 David Goulet <dgoulet@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef _MODPROBE_H
#define _MODPROBE_H

void modprobe_remove_lttng_all(void);
void modprobe_remove_lttng_control(void);
void modprobe_remove_lttng_data(void);
int modprobe_lttng_control(void);
int modprobe_lttng_data(void);

#endif /* _MODPROBE_H */
