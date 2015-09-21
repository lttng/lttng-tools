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

#ifndef _LTT_EVENT_H
#define _LTT_EVENT_H

#include "trace-kernel.h"

struct agent;

int event_kernel_disable_event(struct ltt_kernel_channel *kchan,
		char *event_name, enum lttng_event_type event_type);

int event_kernel_enable_event(struct ltt_kernel_channel *kchan,
		struct lttng_event *event, char *filter_expression,
		struct lttng_filter_bytecode *filter);

int event_ust_enable_tracepoint(struct ltt_ust_session *usess,
		struct ltt_ust_channel *uchan, struct lttng_event *event,
		char *filter_expression,
		struct lttng_filter_bytecode *filter,
		struct lttng_event_exclusion *exclusion,
		bool internal_event);
int event_ust_disable_tracepoint(struct ltt_ust_session *usess,
		struct ltt_ust_channel *uchan, char *event_name);

int event_ust_disable_all_tracepoints(struct ltt_ust_session *usess,
		struct ltt_ust_channel *uchan);

int event_agent_enable(struct ltt_ust_session *usess, struct agent *agt,
		struct lttng_event *event, struct lttng_filter_bytecode *filter,
		char *filter_expression);
int event_agent_enable_all(struct ltt_ust_session *usess, struct agent *agt,
		struct lttng_event *event, struct lttng_filter_bytecode *filter,
		char *filter_expression);

int event_agent_disable(struct ltt_ust_session *usess, struct agent *agt,
		char *event_name);
int event_agent_disable_all(struct ltt_ust_session *usess, struct agent *agt);

const char *event_get_default_agent_ust_name(enum lttng_domain_type domain);

#endif /* _LTT_EVENT_H */
