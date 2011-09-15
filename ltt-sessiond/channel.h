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

int channel_kernel_disable(struct ltt_kernel_session *ksession,
		char *channel_name);
int channel_kernel_enable(struct ltt_kernel_session *ksession,
		struct ltt_kernel_channel *kchan);
int channel_kernel_create(struct ltt_kernel_session *ksession,
		char *channel_name, struct lttng_channel *chan, int kernel_pipe);

#endif /* _LTT_CHANNEL_H */
