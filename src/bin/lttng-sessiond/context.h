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

#ifndef _LTT_CONTEXT_H
#define _LTT_CONTEXT_H

#include <lttng/lttng.h>

#include "trace-kernel.h"
#include "trace-ust.h"
#include "ust-ctl.h"

int context_kernel_add(struct ltt_kernel_session *ksession,
		struct lttng_event_context *ctx, char *channel_name);
int context_ust_add(struct ltt_ust_session *usess,
		enum lttng_domain_type domain, struct lttng_event_context *ctx,
		char *channel_name);

#endif /* _LTT_CONTEXT_H */
