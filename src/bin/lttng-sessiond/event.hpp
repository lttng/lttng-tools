/*
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef _LTT_EVENT_H
#define _LTT_EVENT_H

#include "trace-kernel.hpp"

struct agent;

int event_kernel_disable_event(struct ltt_kernel_channel *kchan,
			       const char *event_name,
			       enum lttng_event_type event_type);

int event_kernel_enable_event(struct ltt_kernel_channel *kchan,
			      struct lttng_event *event,
			      char *filter_expression,
			      struct lttng_bytecode *filter);

int event_ust_enable_tracepoint(struct ltt_ust_session *usess,
				struct ltt_ust_channel *uchan,
				struct lttng_event *event,
				char *filter_expression,
				struct lttng_bytecode *filter,
				struct lttng_event_exclusion *exclusion,
				bool internal_event);
int event_ust_disable_tracepoint(struct ltt_ust_session *usess,
				 struct ltt_ust_channel *uchan,
				 const char *event_name);

int event_ust_disable_all_tracepoints(struct ltt_ust_session *usess, struct ltt_ust_channel *uchan);

int event_agent_enable(struct ltt_ust_session *usess,
		       struct agent *agt,
		       struct lttng_event *event,
		       struct lttng_bytecode *filter,
		       char *filter_expression);
int event_agent_enable_all(struct ltt_ust_session *usess,
			   struct agent *agt,
			   struct lttng_event *event,
			   struct lttng_bytecode *filter,
			   char *filter_expression);

int event_agent_disable(struct ltt_ust_session *usess, struct agent *agt, const char *event_name);
int event_agent_disable_all(struct ltt_ust_session *usess, struct agent *agt);

int trigger_agent_enable(const struct lttng_trigger *trigger, struct agent *agt);
int trigger_agent_disable(const struct lttng_trigger *trigger, struct agent *agt);

const char *event_get_default_agent_ust_name(enum lttng_domain_type domain);

#endif /* _LTT_EVENT_H */
