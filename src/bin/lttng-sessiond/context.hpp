/*
 * Copyright (C) 2011 EfficiOS Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef _LTT_CONTEXT_H
#define _LTT_CONTEXT_H

#include "lttng-ust-ctl.hpp"
#include "trace-kernel.hpp"
#include "trace-ust.hpp"

#include <lttng/lttng.h>

int context_kernel_add(struct ltt_kernel_session *ksession,
		       const struct lttng_event_context *ctx,
		       const char *channel_name);
int context_ust_add(struct ltt_ust_session *usess,
		    enum lttng_domain_type domain,
		    const struct lttng_event_context *ctx,
		    const char *channel_name);

#endif /* _LTT_CONTEXT_H */
