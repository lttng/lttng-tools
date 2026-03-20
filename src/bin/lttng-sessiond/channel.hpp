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

#endif /* _LTT_CHANNEL_H */
