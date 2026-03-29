/*
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef _LTT_EVENT_H
#define _LTT_EVENT_H

#include "event-rule-configuration.hpp"

#include <lttng/lttng.h>

#include <cstdint>

struct agent;

int event_agent_enable(
	std::uint64_t session_id,
	struct agent *agt,
	struct lttng_event *event,
	struct lttng_bytecode *filter,
	char *filter_expression,
	const lttng::sessiond::config::event_rule_configuration *ust_event_rule_config);
int event_agent_enable_all(
	std::uint64_t session_id,
	struct agent *agt,
	struct lttng_event *event,
	struct lttng_bytecode *filter,
	char *filter_expression,
	const lttng::sessiond::config::event_rule_configuration *ust_event_rule_config);

int event_agent_disable(std::uint64_t session_id,
			bool is_active,
			struct agent *agt,
			const char *event_name);
int event_agent_disable_all(std::uint64_t session_id, bool is_active, struct agent *agt);

int trigger_agent_enable(const struct lttng_trigger *trigger, struct agent *agt);
int trigger_agent_disable(const struct lttng_trigger *trigger, struct agent *agt);

const char *event_get_default_agent_ust_name(enum lttng_domain_type domain);

#endif /* _LTT_EVENT_H */
