/*
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef _LTT_CHANNEL_H
#define _LTT_CHANNEL_H

#include "trace-kernel.hpp"
#include "trace-ust.hpp"

#include <common/ctl/memory.hpp>

#include <lttng/lttng.h>

lttng::ctl::lttng_channel_uptr channel_new_default_attr(lttng_domain_type domain,
							enum lttng_buffer_type type);

enum lttng_error_code channel_ust_create(struct ltt_ust_session *usess,
					 struct lttng_channel *attr,
					 enum lttng_buffer_type type);

struct lttng_channel *trace_ust_channel_to_lttng_channel(const struct ltt_ust_channel *uchan);

#endif /* _LTT_CHANNEL_H */
