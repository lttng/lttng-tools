/*
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef _LTT_CONTEXT_H
#define _LTT_CONTEXT_H

#include "context-configuration.hpp"
#include "trace-ust.hpp"

/*
 * Add a UST context from a context_configuration to a specific channel
 * or to all channels if channel_name is empty.
 *
 * The context_configuration must outlive the created ltt_ust_context objects.
 */
int context_ust_add(struct ltt_ust_session *usess,
		    const lttng::sessiond::config::context_configuration& context_config,
		    const char *channel_name);

#endif /* _LTT_CONTEXT_H */
