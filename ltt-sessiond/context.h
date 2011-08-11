/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; only version 2
 * of the License.
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

#ifndef _LTT_CONTEXT_H
#define _LTT_CONTEXT_H

#include <limits.h>
#include <urcu/list.h>

#include <lttng/lttng.h>
#include <lttng-sessiond-comm.h>

#include "lttng-kernel.h"
#include "kernel-ctl.h"
#include "trace.h"

int add_kernel_context(struct ltt_kernel_session *ksession,
		struct lttng_kernel_context *kctx, char *event_name,
		char *channel_name);

#endif /* _LTT_CONTEXT_H */
