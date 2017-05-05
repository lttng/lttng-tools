/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _LTT_CHANNEL_H
#define _LTT_CHANNEL_H

#include <lttng/lttng.h>

#include "trace-kernel.h"
#include "trace-ust.h"

int channel_kernel_disable(struct ltt_kernel_session *ksession,
		char *channel_name);
int channel_kernel_enable(struct ltt_kernel_session *ksession,
		struct ltt_kernel_channel *kchan);
int channel_kernel_create(struct ltt_kernel_session *ksession,
		struct lttng_channel *chan, int kernel_pipe);

struct lttng_channel *channel_new_default_attr(int domain,
		enum lttng_buffer_type type);
void channel_attr_destroy(struct lttng_channel *channel);

int channel_ust_create(struct ltt_ust_session *usess,
		struct lttng_channel *attr, enum lttng_buffer_type type);
int channel_ust_enable(struct ltt_ust_session *usess,
		struct ltt_ust_channel *uchan);
int channel_ust_disable(struct ltt_ust_session *usess,
		struct ltt_ust_channel *uchan);

#endif /* _LTT_CHANNEL_H */
