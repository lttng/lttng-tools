/*
 * Copyright (C) 2011 EfficiOS Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef _LTT_CHANNEL_H
#define _LTT_CHANNEL_H

#include "trace-kernel.hpp"
#include "trace-ust.hpp"

#include <lttng/lttng.h>

int channel_kernel_disable(struct ltt_kernel_session *ksession, char *channel_name);
enum lttng_error_code channel_kernel_enable(struct ltt_kernel_session *ksession,
					    struct ltt_kernel_channel *kchan);
enum lttng_error_code channel_kernel_create(struct ltt_kernel_session *ksession,
					    struct lttng_channel *chan,
					    int kernel_pipe);

struct lttng_channel *channel_new_default_attr(int domain, enum lttng_buffer_type type);
void channel_attr_destroy(struct lttng_channel *channel);

enum lttng_error_code channel_ust_create(struct ltt_ust_session *usess,
					 struct lttng_channel *attr,
					 enum lttng_buffer_type type);
enum lttng_error_code channel_ust_enable(struct ltt_ust_session *usess,
					 struct ltt_ust_channel *uchan);
int channel_ust_disable(struct ltt_ust_session *usess, struct ltt_ust_channel *uchan);

struct lttng_channel *trace_ust_channel_to_lttng_channel(const struct ltt_ust_channel *uchan);

#endif /* _LTT_CHANNEL_H */
