/*
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include "consumer.hpp"
#include "lttng-sessiond.hpp"
#include "notification-thread-commands.hpp"
#include "trace-kernel.hpp"

#include <common/common.hpp>
#include <common/defaults.hpp>
#include <common/macros.hpp>
#include <common/trace-chunk.hpp>

#include <lttng/event-rule/event-rule-internal.hpp>
#include <lttng/event-rule/event-rule.h>
#include <lttng/event.h>
#include <lttng/lttng-error.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * Allocate and initialize a kernel token event rule.
 *
 * Return pointer to structure or NULL.
 */
enum lttng_error_code
trace_kernel_create_event_notifier_rule(struct lttng_trigger *trigger,
					uint64_t token,
					uint64_t error_counter_index,
					struct ltt_kernel_event_notifier_rule **event_notifier_rule)
{
	enum lttng_error_code ret = LTTNG_OK;
	enum lttng_condition_type condition_type;
	enum lttng_event_rule_type event_rule_type;
	enum lttng_condition_status condition_status;
	struct ltt_kernel_event_notifier_rule *local_kernel_token_event_rule;
	const struct lttng_condition *condition = nullptr;
	const struct lttng_event_rule *event_rule = nullptr;

	LTTNG_ASSERT(event_notifier_rule);

	condition = lttng_trigger_get_const_condition(trigger);
	LTTNG_ASSERT(condition);

	condition_type = lttng_condition_get_type(condition);
	LTTNG_ASSERT(condition_type == LTTNG_CONDITION_TYPE_EVENT_RULE_MATCHES);

	condition_status = lttng_condition_event_rule_matches_get_rule(condition, &event_rule);
	LTTNG_ASSERT(condition_status == LTTNG_CONDITION_STATUS_OK);
	LTTNG_ASSERT(event_rule);

	event_rule_type = lttng_event_rule_get_type(event_rule);
	LTTNG_ASSERT(event_rule_type != LTTNG_EVENT_RULE_TYPE_UNKNOWN);

	local_kernel_token_event_rule = zmalloc<ltt_kernel_event_notifier_rule>();
	if (local_kernel_token_event_rule == nullptr) {
		PERROR("Failed to allocate ltt_kernel_token_event_rule structure");
		ret = LTTNG_ERR_NOMEM;
		goto error;
	}

	local_kernel_token_event_rule->fd = -1;
	local_kernel_token_event_rule->enabled = true;
	local_kernel_token_event_rule->token = token;
	local_kernel_token_event_rule->error_counter_index = error_counter_index;

	/* Get the reference of the event rule. */
	lttng_trigger_get(trigger);

	local_kernel_token_event_rule->trigger = trigger;
	/* The event rule still owns the filter and bytecode. */
	local_kernel_token_event_rule->filter = lttng_event_rule_get_filter_bytecode(event_rule);

	DBG3("Created kernel event notifier rule: token =  %" PRIu64,
	     local_kernel_token_event_rule->token);
error:
	*event_notifier_rule = local_kernel_token_event_rule;
	return ret;
}

/*
 * Cleanup kernel event structure.
 */
namespace {
void free_token_event_rule_rcu(struct rcu_head *rcu_node)
{
	struct ltt_kernel_event_notifier_rule *rule =
		caa_container_of(rcu_node, struct ltt_kernel_event_notifier_rule, rcu_node);

	free(rule);
}
} /* namespace */

void trace_kernel_destroy_event_notifier_rule(struct ltt_kernel_event_notifier_rule *event)
{
	LTTNG_ASSERT(event);

	if (event->fd >= 0) {
		const int ret = close(event->fd);

		DBG("Closing kernel event notifier rule file descriptor: fd = %d", event->fd);
		if (ret) {
			PERROR("Failed to close kernel event notifier file descriptor: fd = %d",
			       event->fd);
		}
	} else {
		DBG("Destroying kernel event notifier rule (no associated file descriptor)");
	}

	lttng_trigger_put(event->trigger);
	call_rcu(&event->rcu_node, free_token_event_rule_rcu);
}
