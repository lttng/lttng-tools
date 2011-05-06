/*
 * Copyright (C) 2011 - Julien Desfossez <julien.desfossez@polymtl.ca>
 *                      Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef _LTT_LIBKERNELCTL_H
#define _LTT_LIBKERNELCTL_H

#include <lttng/lttng.h>

int kernctl_create_channel(int, struct lttng_channel*);
int kernctl_create_event(int, struct lttng_event*);
int kernctl_create_session(int);
int kernctl_create_stream(int);
int kernctl_get_max_subbuf_size(int, unsigned long*);
int kernctl_get_mmap_len(int, unsigned long*);
int kernctl_get_mmap_read_offset(int, unsigned long*);
int kernctl_get_next_subbuf(int);
int kernctl_get_padded_subbuf_size(int, unsigned long*);
int kernctl_get_subbuf(int fd, unsigned long*);
int kernctl_get_subbuf_size(int, unsigned long *);
int kernctl_put_next_subbuf(int);
int kernctl_put_subbuf(int fd);
int kernctl_snapshot(int);
int kernctl_snapshot_get_consumed(int, unsigned long*);
int kernctl_snapshot_get_produced(int, unsigned long*);
int kernctl_start_session(int);
int kernctl_stop_session(int);

#endif /* _LTT_LIBKERNELCTL_H */
