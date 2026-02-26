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
#include <lttng/event-rule/kernel-kprobe-internal.hpp>
#include <lttng/event-rule/kernel-kprobe.h>
#include <lttng/event-rule/kernel-syscall-internal.hpp>
#include <lttng/event-rule/kernel-syscall.h>
#include <lttng/event-rule/kernel-tracepoint-internal.hpp>
#include <lttng/event-rule/kernel-tracepoint.h>
#include <lttng/event-rule/kernel-uprobe-internal.hpp>
#include <lttng/event-rule/kernel-uprobe.h>
#include <lttng/event.h>
#include <lttng/kernel-probe.h>
#include <lttng/lttng-error.h>
#include <lttng/userspace-probe-internal.hpp>
#include <lttng/userspace-probe.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * Allocate and initialize a kernel session data structure.
 *
 * Return pointer to structure or NULL.
 */
struct ltt_kernel_session *trace_kernel_create_session()
{
	struct ltt_kernel_session *lks = nullptr;

	/* Allocate a new ltt kernel session */
	lks = zmalloc<ltt_kernel_session>();
	if (lks == nullptr) {
		PERROR("create kernel session zmalloc");
		goto alloc_error;
	}

	/* Init data structure */
	lks->fd = -1;
	lks->channel_count = 0;

	return lks;

alloc_error:
	return nullptr;
}

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
 * Initialize a kernel trigger from an event rule.
 */
enum lttng_error_code trace_kernel_init_event_notifier_from_event_rule(
	const struct lttng_event_rule *rule,
	struct lttng_kernel_abi_event_notifier *kernel_event_notifier)
{
	enum lttng_error_code ret_code;
	const char *name;
	int strncpy_ret;

	switch (lttng_event_rule_get_type(rule)) {
	case LTTNG_EVENT_RULE_TYPE_KERNEL_KPROBE:
	{
		uint64_t address = 0, offset = 0;
		const char *symbol_name = nullptr;
		const struct lttng_kernel_probe_location *location = nullptr;
		enum lttng_kernel_probe_location_status k_status;
		enum lttng_event_rule_status status;

		status = lttng_event_rule_kernel_kprobe_get_location(rule, &location);
		if (status != LTTNG_EVENT_RULE_STATUS_OK) {
			ret_code = LTTNG_ERR_PROBE_LOCATION_INVAL;
			goto error;
		}

		switch (lttng_kernel_probe_location_get_type(location)) {
		case LTTNG_KERNEL_PROBE_LOCATION_TYPE_ADDRESS:
		{
			k_status =
				lttng_kernel_probe_location_address_get_address(location, &address);
			LTTNG_ASSERT(k_status == LTTNG_KERNEL_PROBE_LOCATION_STATUS_OK);
			break;
		}
		case LTTNG_KERNEL_PROBE_LOCATION_TYPE_SYMBOL_OFFSET:
		{
			k_status = lttng_kernel_probe_location_symbol_get_offset(location, &offset);
			LTTNG_ASSERT(k_status == LTTNG_KERNEL_PROBE_LOCATION_STATUS_OK);
			symbol_name = lttng_kernel_probe_location_symbol_get_name(location);
			break;
		}
		default:
			abort();
		}

		kernel_event_notifier->event.instrumentation = LTTNG_KERNEL_ABI_KPROBE;
		kernel_event_notifier->event.u.kprobe.addr = address;
		kernel_event_notifier->event.u.kprobe.offset = offset;
		if (symbol_name) {
			strncpy_ret = lttng_strncpy(
				kernel_event_notifier->event.u.kprobe.symbol_name,
				symbol_name,
				sizeof(kernel_event_notifier->event.u.kprobe.symbol_name));

			if (strncpy_ret) {
				ret_code = LTTNG_ERR_INVALID;
				goto error;
			}
		}

		kernel_event_notifier->event.u.kprobe
			.symbol_name[LTTNG_KERNEL_ABI_SYM_NAME_LEN - 1] = '\0';

		status = lttng_event_rule_kernel_kprobe_get_event_name(rule, &name);
		LTTNG_ASSERT(status == LTTNG_EVENT_RULE_STATUS_OK);
		ret_code = LTTNG_OK;
		break;
	}
	case LTTNG_EVENT_RULE_TYPE_KERNEL_UPROBE:
	{
		const struct lttng_userspace_probe_location *location = nullptr;
		const struct lttng_userspace_probe_location_lookup_method *lookup = nullptr;
		enum lttng_event_rule_status status;

		status = lttng_event_rule_kernel_uprobe_get_location(rule, &location);
		if (status != LTTNG_EVENT_RULE_STATUS_OK) {
			ret_code = LTTNG_ERR_PROBE_LOCATION_INVAL;
			goto error;
		}

		kernel_event_notifier->event.instrumentation = LTTNG_KERNEL_ABI_UPROBE;

		lookup = lttng_userspace_probe_location_get_lookup_method(location);
		if (!lookup) {
			ret_code = LTTNG_ERR_PROBE_LOCATION_INVAL;
			goto error;
		}

		/*
		 * From the kernel tracer's perspective, all userspace probe
		 * event types are all the same: a file and an offset.
		 */
		switch (lttng_userspace_probe_location_lookup_method_get_type(lookup)) {
		case LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_FUNCTION_ELF:
			/* Get the file descriptor on the target binary. */
			kernel_event_notifier->event.u.uprobe.fd =
				lttng_userspace_probe_location_function_get_binary_fd(location);

			break;
		case LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_TRACEPOINT_SDT:
			/* Get the file descriptor on the target binary. */
			kernel_event_notifier->event.u.uprobe.fd =
				lttng_userspace_probe_location_tracepoint_get_binary_fd(location);
			break;
		default:
			abort();
		}

		status = lttng_event_rule_kernel_uprobe_get_event_name(rule, &name);
		LTTNG_ASSERT(status == LTTNG_EVENT_RULE_STATUS_OK);
		ret_code = LTTNG_OK;
		break;
	}
	case LTTNG_EVENT_RULE_TYPE_KERNEL_TRACEPOINT:
	{
		const enum lttng_event_rule_status status =
			lttng_event_rule_kernel_tracepoint_get_name_pattern(rule, &name);

		LTTNG_ASSERT(status == LTTNG_EVENT_RULE_STATUS_OK);
		kernel_event_notifier->event.instrumentation = LTTNG_KERNEL_ABI_TRACEPOINT;

		ret_code = LTTNG_OK;
		break;
	}
	case LTTNG_EVENT_RULE_TYPE_KERNEL_SYSCALL:
	{
		const enum lttng_event_rule_status status =
			lttng_event_rule_kernel_syscall_get_name_pattern(rule, &name);
		const enum lttng_event_rule_kernel_syscall_emission_site emission_site =
			lttng_event_rule_kernel_syscall_get_emission_site(rule);
		enum lttng_kernel_abi_syscall_entryexit entryexit;

		LTTNG_ASSERT(status == LTTNG_EVENT_RULE_STATUS_OK);
		LTTNG_ASSERT(emission_site !=
			     LTTNG_EVENT_RULE_KERNEL_SYSCALL_EMISSION_SITE_UNKNOWN);

		switch (emission_site) {
		case LTTNG_EVENT_RULE_KERNEL_SYSCALL_EMISSION_SITE_ENTRY:
			entryexit = LTTNG_KERNEL_ABI_SYSCALL_ENTRY;
			break;
		case LTTNG_EVENT_RULE_KERNEL_SYSCALL_EMISSION_SITE_EXIT:
			entryexit = LTTNG_KERNEL_ABI_SYSCALL_EXIT;
			break;
		case LTTNG_EVENT_RULE_KERNEL_SYSCALL_EMISSION_SITE_ENTRY_EXIT:
			entryexit = LTTNG_KERNEL_ABI_SYSCALL_ENTRYEXIT;
			break;
		default:
			abort();
			break;
		}

		kernel_event_notifier->event.instrumentation = LTTNG_KERNEL_ABI_SYSCALL;
		kernel_event_notifier->event.u.syscall.abi = LTTNG_KERNEL_ABI_SYSCALL_ABI_ALL;
		kernel_event_notifier->event.u.syscall.entryexit = entryexit;
		kernel_event_notifier->event.u.syscall.match = LTTNG_KERNEL_ABI_SYSCALL_MATCH_NAME;
		ret_code = LTTNG_OK;
		break;
	}
	default:
		abort();
		break;
	}

	strncpy_ret = lttng_strncpy(
		kernel_event_notifier->event.name, name, LTTNG_KERNEL_ABI_SYM_NAME_LEN);
	if (strncpy_ret) {
		ret_code = LTTNG_ERR_INVALID;
		goto error;
	}

error:
	return ret_code;
}

/*
 * Cleanup kernel event structure.
 */
static void free_token_event_rule_rcu(struct rcu_head *rcu_node)
{
	struct ltt_kernel_event_notifier_rule *rule =
		caa_container_of(rcu_node, struct ltt_kernel_event_notifier_rule, rcu_node);

	free(rule);
}

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

/*
 * Cleanup kernel session structure
 */
void trace_kernel_destroy_session(struct ltt_kernel_session *session [[maybe_unused]])
{
}

/* Free elements needed by destroy notifiers. */
void trace_kernel_free_session(struct ltt_kernel_session *session)
{
	/* Wipe consumer output object */
	consumer_output_put(session->consumer);
	free(session);
}
