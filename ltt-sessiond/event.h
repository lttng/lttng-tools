/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; only version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef _LTT_EVENT_H
#define _LTT_EVENT_H

#include <lttng/lttng.h>

#include "trace-kernel.h"

int event_kernel_disable(struct ltt_kernel_session *ksession,
		struct ltt_kernel_channel *kchan, char *event_name);
int event_kernel_disable_all(struct ltt_kernel_session *ksession,
		struct ltt_kernel_channel *kchan);
int event_kernel_enable(struct ltt_kernel_session *ksession,
		struct ltt_kernel_channel *kchan, struct lttng_event *event);
int event_kernel_enable_all(struct ltt_kernel_session *ksession,
		struct ltt_kernel_channel *kchan, int kernel_tracer_fd);
int event_kernel_enable_syscalls(struct ltt_kernel_session *ksession,
		struct ltt_kernel_channel *kchan, int kernel_tracer_fd);

#endif /* _LTT_EVENT_H */
