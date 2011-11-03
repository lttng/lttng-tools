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

int channel_ust_create(struct ltt_ust_session *usession,
		struct lttng_channel *chan);
int channel_ust_copy(struct ltt_ust_channel *dst,
		struct ltt_ust_channel *src);
int channel_ust_disable(struct ltt_ust_session *usession,
		struct ltt_ust_channel *uchan, int sock);
int channel_ust_enable(struct ltt_ust_session *usession,
		struct ltt_ust_channel *uchan, int sock);

struct lttng_channel *channel_new_default_attr(int domain);

#endif /* _LTT_CHANNEL_H */
