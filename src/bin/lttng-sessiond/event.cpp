/*
 * Copyright (C) 2011 EfficiOS Inc.
 * Copyright (C) 2016 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include "agent.hpp"
#include "channel.hpp"
#include "event.hpp"
#include "kernel.hpp"
#include "lttng-sessiond.hpp"
#include "lttng-ust-ctl.hpp"
#include "lttng-ust-error.hpp"
#include "trace-kernel.hpp"
#include "trace-ust.hpp"
#include "ust-app.hpp"
#include "utils.hpp"

#include <common/bytecode/bytecode.hpp>
#include <common/compat/errno.hpp>
#include <common/context.hpp>
#include <common/error.hpp>
#include <common/filter.hpp>
#include <common/sessiond-comm/sessiond-comm.hpp>
#include <common/urcu.hpp>

#include <lttng/condition/condition.h>
#include <lttng/condition/event-rule-matches.h>
#include <lttng/event-rule/event-rule-internal.hpp>
#include <lttng/event-rule/event-rule.h>
#include <lttng/lttng.h>

#include <string.h>
#include <urcu/list.h>

/*
 * Add unique UST event based on the event name, filter bytecode and loglevel.
 */
static void add_unique_ust_event(struct lttng_ht *ht, struct ltt_ust_event *event)
{
	struct cds_lfht_node *node_ptr;
	struct ltt_ust_ht_key key;

	LTTNG_ASSERT(ht);
	LTTNG_ASSERT(ht->ht);
	LTTNG_ASSERT(event);

	key.name = event->attr.name;
	key.filter = (struct lttng_bytecode *) event->filter;
	key.loglevel_type = (lttng_ust_abi_loglevel_type) event->attr.loglevel_type;
	key.loglevel_value = event->attr.loglevel;
	key.exclusion = event->exclusion;

	node_ptr = cds_lfht_add_unique(ht->ht,
				       ht->hash_fct(event->node.key, lttng_ht_seed),
				       trace_ust_ht_match_event,
				       &key,
				       &event->node.node);
	LTTNG_ASSERT(node_ptr == &event->node.node);
}

/*
 * Disable kernel tracepoint events for a channel from the kernel session of
 * a specified event_name and event type.
 * On type LTTNG_EVENT_ALL all events with event_name are disabled.
 * If event_name is NULL all events of the specified type are disabled.
 */
int event_kernel_disable_event(struct ltt_kernel_channel *kchan,
			       const char *event_name,
			       enum lttng_event_type type)
{
	int ret, error = 0, found = 0;
	struct ltt_kernel_event *kevent;

	LTTNG_ASSERT(kchan);

	/* For each event in the kernel session */
	cds_list_for_each_entry (kevent, &kchan->events_list.head, list) {
		if (type != LTTNG_EVENT_ALL && kevent->type != type)
			continue;
		if (event_name != nullptr && strcmp(event_name, kevent->event->name) != 0) {
			continue;
		}
		found++;
		ret = kernel_disable_event(kevent);
		if (ret < 0) {
			error = 1;
			continue;
		}
	}
	DBG("Disable kernel event: found %d events with name: %s and type: %d",
	    found,
	    event_name ? event_name : "NULL",
	    type);

	if (event_name != nullptr && !found) {
		ret = LTTNG_ERR_NO_EVENT;
	} else {
		ret = error ? LTTNG_ERR_KERN_DISABLE_FAIL : LTTNG_OK;
	}

	return ret;
}

/*
 * Enable kernel tracepoint event for a channel from the kernel session.
 * We own filter_expression and filter.
 */
int event_kernel_enable_event(struct ltt_kernel_channel *kchan,
			      struct lttng_event *event,
			      char *filter_expression,
			      struct lttng_bytecode *filter)
{
	int ret;
	struct ltt_kernel_event *kevent;

	LTTNG_ASSERT(kchan);
	LTTNG_ASSERT(event);

	kevent = trace_kernel_find_event(event->name, kchan, event->type, filter);
	if (kevent == nullptr) {
		ret = kernel_create_event(event, kchan, filter_expression, filter);
		/* We have passed ownership */
		filter_expression = nullptr;
		filter = nullptr;
		if (ret) {
			goto end;
		}
	} else if (!kevent->enabled) {
		ret = kernel_enable_event(kevent);
		if (ret < 0) {
			ret = LTTNG_ERR_KERN_ENABLE_FAIL;
			goto end;
		}
	} else {
		/* At this point, the event is considered enabled */
		ret = LTTNG_ERR_KERN_EVENT_EXIST;
		goto end;
	}

	ret = LTTNG_OK;
end:
	free(filter_expression);
	free(filter);
	return ret;
}

/*
 * ============================
 * UST : The Ultimate Frontier!
 * ============================
 */

/*
 * Enable UST tracepoint event for a channel from a UST session.
 * We own filter_expression, filter, and exclusion.
 */
int event_ust_enable_tracepoint(struct ltt_ust_session *usess,
				struct ltt_ust_channel *uchan,
				struct lttng_event *event,
				char *filter_expression,
				struct lttng_bytecode *filter,
				struct lttng_event_exclusion *exclusion,
				bool internal_event)
{
	int ret = LTTNG_OK, to_create = 0;
	struct ltt_ust_event *uevent;

	LTTNG_ASSERT(usess);
	LTTNG_ASSERT(uchan);
	LTTNG_ASSERT(event);

	lttng::urcu::read_lock_guard read_lock;

	uevent = trace_ust_find_event(uchan->events,
				      event->name,
				      filter,
				      (enum lttng_ust_abi_loglevel_type) event->loglevel_type,
				      event->loglevel,
				      exclusion);
	if (!uevent) {
		ret = trace_ust_create_event(
			event, filter_expression, filter, exclusion, internal_event, &uevent);
		/* We have passed ownership */
		filter_expression = nullptr;
		filter = nullptr;
		exclusion = nullptr;
		if (ret != LTTNG_OK) {
			goto end;
		}

		/* Valid to set it after the goto error since uevent is still NULL */
		to_create = 1;
	}

	if (uevent->enabled) {
		/* It's already enabled so everything is OK */
		LTTNG_ASSERT(!to_create);
		ret = LTTNG_ERR_UST_EVENT_ENABLED;
		goto end;
	}

	uevent->enabled = true;
	if (to_create) {
		/* Add ltt ust event to channel */
		add_unique_ust_event(uchan->events, uevent);
	}

	if (!usess->active) {
		goto end;
	}

	if (to_create) {
		/* Create event on all UST registered apps for session */
		ret = ust_app_create_event_glb(usess, uchan, uevent);
	} else {
		/* Enable event on all UST registered apps for session */
		ret = ust_app_enable_event_glb(usess, uchan, uevent);
	}

	if (ret < 0) {
		if (ret == -LTTNG_UST_ERR_EXIST) {
			ret = LTTNG_ERR_UST_EVENT_EXIST;
		} else {
			ret = LTTNG_ERR_UST_ENABLE_FAIL;
		}
		goto end;
	}

	DBG("Event UST %s %s in channel %s",
	    uevent->attr.name,
	    to_create ? "created" : "enabled",
	    uchan->name);

	ret = LTTNG_OK;

end:
	free(filter_expression);
	free(filter);
	free(exclusion);
	return ret;
}

/*
 * Disable UST tracepoint of a channel from a UST session.
 */
int event_ust_disable_tracepoint(struct ltt_ust_session *usess,
				 struct ltt_ust_channel *uchan,
				 const char *event_name)
{
	int ret;
	struct ltt_ust_event *uevent;
	struct lttng_ht_node_str *node;
	struct lttng_ht_iter iter;
	struct lttng_ht *ht;

	LTTNG_ASSERT(usess);
	LTTNG_ASSERT(uchan);
	LTTNG_ASSERT(event_name);

	ht = uchan->events;

	lttng::urcu::read_lock_guard read_lock;

	/*
	 * We use a custom lookup since we need the iterator for the next_duplicate
	 * call in the do while loop below.
	 */
	cds_lfht_lookup(ht->ht,
			ht->hash_fct((void *) event_name, lttng_ht_seed),
			trace_ust_ht_match_event_by_name,
			event_name,
			&iter.iter);
	node = lttng_ht_iter_get_node_str(&iter);
	if (node == nullptr) {
		DBG2("Trace UST event NOT found by name %s", event_name);
		ret = LTTNG_ERR_UST_EVENT_NOT_FOUND;
		goto error;
	}

	do {
		uevent = lttng::utils::container_of(node, &ltt_ust_event::node);
		LTTNG_ASSERT(uevent);

		if (!uevent->enabled) {
			/* It's already disabled so everything is OK */
			goto next;
		}
		uevent->enabled = false;
		DBG2("Event UST %s disabled in channel %s", uevent->attr.name, uchan->name);

		if (!usess->active) {
			goto next;
		}
		ret = ust_app_disable_event_glb(usess, uchan, uevent);
		if (ret < 0 && ret != -LTTNG_UST_ERR_EXIST) {
			ret = LTTNG_ERR_UST_DISABLE_FAIL;
			goto error;
		}
	next:
		/* Get next duplicate event by name. */
		cds_lfht_next_duplicate(
			ht->ht, trace_ust_ht_match_event_by_name, event_name, &iter.iter);
		node = lttng_ht_iter_get_node_str(&iter);
	} while (node);

	ret = LTTNG_OK;

error:
	return ret;
}

/*
 * Disable all UST tracepoints for a channel from a UST session.
 */
int event_ust_disable_all_tracepoints(struct ltt_ust_session *usess, struct ltt_ust_channel *uchan)
{
	int ret, i, size, error = 0;
	struct lttng_ht_iter iter;
	struct ltt_ust_event *uevent = nullptr;
	struct lttng_event *events = nullptr;

	LTTNG_ASSERT(usess);
	LTTNG_ASSERT(uchan);

	/* Disabling existing events */
	{
		lttng::urcu::read_lock_guard read_lock;

		cds_lfht_for_each_entry (uchan->events->ht, &iter.iter, uevent, node.node) {
			if (uevent->enabled) {
				ret = event_ust_disable_tracepoint(usess, uchan, uevent->attr.name);
				if (ret < 0) {
					error = LTTNG_ERR_UST_DISABLE_FAIL;
					continue;
				}
			}
		}
	}

	/* Get all UST available events */
	size = ust_app_list_events(&events);
	if (size < 0) {
		ret = LTTNG_ERR_UST_LIST_FAIL;
		goto error;
	}

	for (i = 0; i < size; i++) {
		ret = event_ust_disable_tracepoint(usess, uchan, events[i].name);
		if (ret < 0) {
			/* Continue to disable the rest... */
			error = LTTNG_ERR_UST_DISABLE_FAIL;
			continue;
		}
	}

	ret = error ? error : LTTNG_OK;
error:
	free(events);
	return ret;
}

static void agent_enable_all(struct agent *agt)
{
	struct agent_event *aevent;
	struct lttng_ht_iter iter;

	{
		/* Flag every event as enabled. */
		lttng::urcu::read_lock_guard read_lock;

		cds_lfht_for_each_entry (agt->events->ht, &iter.iter, aevent, node.node) {
			aevent->enabled_count++;
		}
	}
}

/*
 * Enable all agent event for a given UST session.
 *
 * Return LTTNG_OK on success or else a LTTNG_ERR* code.
 */
int event_agent_enable_all(struct ltt_ust_session *usess,
			   struct agent *agt,
			   struct lttng_event *event,
			   struct lttng_bytecode *filter,
			   char *filter_expression)
{
	int ret;

	LTTNG_ASSERT(usess);

	DBG("Event agent enabling ALL events for session %" PRIu64, usess->id);

	/* Enable event on agent application through TCP socket. */
	ret = event_agent_enable(usess, agt, event, filter, filter_expression);
	if (ret != LTTNG_OK) {
		goto error;
	}

	agent_enable_all(agt);

	ret = LTTNG_OK;

error:
	return ret;
}

/*
 * Check if this event's filter requires the activation of application contexts
 * and enable them in the agent.
 * TODO: bytecode iterator does not support non-legacy application
 * contexts yet. Not an issue for now, since they are not generated by
 * the lttng-ctl library.
 */
static int add_filter_app_ctx(struct lttng_bytecode *bytecode,
			      const char *filter_expression,
			      struct agent *agt)
{
	int ret = LTTNG_OK;
	char *provider_name = nullptr, *ctx_name = nullptr;
	struct bytecode_symbol_iterator *it = bytecode_symbol_iterator_create(bytecode);

	if (!it) {
		ret = LTTNG_ERR_NOMEM;
		goto end;
	}

	do {
		struct lttng_event_context ctx;
		const char *symbol_name = bytecode_symbol_iterator_get_name(it);

		if (parse_application_context(symbol_name, &provider_name, &ctx_name)) {
			/* Not an application context. */
			continue;
		}

		ctx.ctx = LTTNG_EVENT_CONTEXT_APP_CONTEXT;
		ctx.u.app_ctx.provider_name = provider_name;
		ctx.u.app_ctx.ctx_name = ctx_name;

		/* Recognized an application context. */
		DBG("Enabling event with filter expression \"%s\" requires enabling the %s:%s application context.",
		    filter_expression,
		    provider_name,
		    ctx_name);

		ret = agent_add_context(&ctx, agt);
		if (ret != LTTNG_OK) {
			ERR("Failed to add application context %s:%s.", provider_name, ctx_name);
			goto end;
		}

		ret = agent_enable_context(&ctx, agt->domain);
		if (ret != LTTNG_OK) {
			ERR("Failed to enable application context %s:%s.", provider_name, ctx_name);
			goto end;
		}

		free(provider_name);
		free(ctx_name);
		provider_name = ctx_name = nullptr;
	} while (bytecode_symbol_iterator_next(it) == 0);
end:
	free(provider_name);
	free(ctx_name);
	bytecode_symbol_iterator_destroy(it);
	return ret;
}

static int agent_enable(struct agent *agt,
			struct lttng_event *event,
			struct lttng_bytecode *filter,
			char *filter_expression)
{
	int ret, created = 0;
	struct agent_event *aevent;

	LTTNG_ASSERT(event);
	LTTNG_ASSERT(agt);

	lttng::urcu::read_lock_guard read_lock;
	aevent = agent_find_event(
		event->name, event->loglevel_type, event->loglevel, filter_expression, agt);
	if (!aevent) {
		aevent = agent_create_event(event->name,
					    event->loglevel_type,
					    event->loglevel,
					    filter,
					    filter_expression);
		if (!aevent) {
			ret = LTTNG_ERR_NOMEM;
			goto error;
		}
		filter = nullptr;
		filter_expression = nullptr;
		created = 1;
		LTTNG_ASSERT(!AGENT_EVENT_IS_ENABLED(aevent));
	}

	if (created && aevent->filter) {
		ret = add_filter_app_ctx(aevent->filter, aevent->filter_expression, agt);
		if (ret != LTTNG_OK) {
			goto error;
		}
	}

	/* Already enabled? */
	if (AGENT_EVENT_IS_ENABLED(aevent)) {
		ret = LTTNG_OK;
		goto end;
	}

	ret = agent_enable_event(aevent, agt->domain);
	if (ret != LTTNG_OK) {
		goto error;
	}

	/* If the event was created prior to the enable, add it to the domain. */
	if (created) {
		agent_add_event(aevent, agt);
	}

	ret = LTTNG_OK;
	goto end;

error:
	if (created) {
		agent_destroy_event(aevent);
	}
end:
	free(filter);
	free(filter_expression);
	return ret;
}

/*
 * Enable a single agent event for a given UST session.
 *
 * Return LTTNG_OK on success or else a LTTNG_ERR* code.
 */
int event_agent_enable(struct ltt_ust_session *usess,
		       struct agent *agt,
		       struct lttng_event *event,
		       struct lttng_bytecode *filter,
		       char *filter_expression)
{
	LTTNG_ASSERT(usess);
	LTTNG_ASSERT(event);
	LTTNG_ASSERT(agt);

	DBG("Enabling agent event: event pattern = '%s', session id = %" PRIu64
	    ", loglevel type = %d, loglevel = %d, filter expression = '%s'",
	    event->name,
	    usess->id,
	    event->loglevel_type,
	    event->loglevel,
	    filter_expression ? filter_expression : "(none)");

	return agent_enable(agt, event, filter, filter_expression);
}

/*
 * Enable a single agent event for a trigger.
 *
 * Return LTTNG_OK on success or else a LTTNG_ERR* code.
 */
int trigger_agent_enable(const struct lttng_trigger *trigger, struct agent *agt)
{
	int ret;
	enum lttng_condition_status c_status;
	enum lttng_trigger_status t_status;
	enum lttng_domain_type d_type;
	const struct lttng_condition *condition;
	const struct lttng_event_rule *rule;
	const char *filter_expression;
	char *filter_expression_copy = nullptr;
	const struct lttng_bytecode *filter_bytecode;
	struct lttng_bytecode *filter_bytecode_copy = nullptr;
	struct lttng_event *event = nullptr;
	uid_t trigger_owner_uid = 0;
	const char *trigger_name;

	LTTNG_ASSERT(trigger);
	LTTNG_ASSERT(agt);

	t_status = lttng_trigger_get_name(trigger, &trigger_name);
	if (t_status != LTTNG_TRIGGER_STATUS_OK) {
		trigger_name = "(anonymous)";
	}

	t_status = lttng_trigger_get_owner_uid(trigger, &trigger_owner_uid);
	LTTNG_ASSERT(t_status == LTTNG_TRIGGER_STATUS_OK);

	condition = lttng_trigger_get_const_condition(trigger);

	LTTNG_ASSERT(lttng_condition_get_type(condition) ==
		     LTTNG_CONDITION_TYPE_EVENT_RULE_MATCHES);

	c_status = lttng_condition_event_rule_matches_get_rule(condition, &rule);
	LTTNG_ASSERT(c_status == LTTNG_CONDITION_STATUS_OK);

	switch (lttng_event_rule_get_type(rule)) {
	case LTTNG_EVENT_RULE_TYPE_JUL_LOGGING:
	case LTTNG_EVENT_RULE_TYPE_LOG4J_LOGGING:
	case LTTNG_EVENT_RULE_TYPE_PYTHON_LOGGING:
		break;
	default:
		abort();
		break;
	}

	d_type = lttng_event_rule_get_domain_type(rule);
	LTTNG_ASSERT(d_type == agt->domain);

	event = lttng_event_rule_generate_lttng_event(rule);
	if (!event) {
		ret = LTTNG_ERR_NOMEM;
		goto end;
	}

	/* Get the internal filter expression and bytecode. */
	filter_expression = lttng_event_rule_get_filter(rule);
	if (filter_expression) {
		filter_expression_copy = strdup(filter_expression);
		if (!filter_expression_copy) {
			ret = LTTNG_ERR_NOMEM;
			goto end;
		}

		/* Get the filter bytecode */
		filter_bytecode = lttng_event_rule_get_filter_bytecode(rule);
		if (filter_bytecode) {
			filter_bytecode_copy = lttng_bytecode_copy(filter_bytecode);
			if (!filter_bytecode_copy) {
				ret = LTTNG_ERR_NOMEM;
				goto end;
			}
		}
	}

	DBG("Enabling agent event from trigger: trigger name = '%s', trigger owner uid = %d, token = %" PRIu64,
	    trigger_name,
	    trigger_owner_uid,
	    lttng_trigger_get_tracer_token(trigger));

	ret = agent_enable(agt, event, filter_bytecode_copy, filter_expression_copy);
	/* Ownership was passed even in case of error. */
	filter_expression_copy = nullptr;
	filter_bytecode_copy = nullptr;

end:
	free(filter_expression_copy);
	free(filter_bytecode_copy);
	free(event);
	return ret;
}

/*
 * Return the default event name associated with the provided UST domain. Return
 * NULL on error.
 */
const char *event_get_default_agent_ust_name(enum lttng_domain_type domain)
{
	const char *default_event_name = nullptr;

	switch (domain) {
	case LTTNG_DOMAIN_LOG4J:
		default_event_name = DEFAULT_LOG4J_EVENT_NAME;
		break;
	case LTTNG_DOMAIN_JUL:
		default_event_name = DEFAULT_JUL_EVENT_NAME;
		break;
	case LTTNG_DOMAIN_PYTHON:
		default_event_name = DEFAULT_PYTHON_EVENT_NAME;
		break;
	default:
		abort();
	}

	return default_event_name;
}

static int trigger_agent_disable_one(const struct lttng_trigger *trigger,
				     struct agent *agt,
				     struct agent_event *aevent)

{
	int ret;

	LTTNG_ASSERT(agt);
	LTTNG_ASSERT(trigger);
	LTTNG_ASSERT(aevent);

	/*
	 * Actual ust event un-registration happens on the trigger
	 * un-registration at that point.
	 */

	DBG("Event agent disabling %s (loglevel type %d, loglevel value %d) for trigger %" PRIu64,
	    aevent->name,
	    aevent->loglevel_type,
	    aevent->loglevel_value,
	    lttng_trigger_get_tracer_token(trigger));

	/* Already disabled? */
	if (!AGENT_EVENT_IS_ENABLED(aevent)) {
		goto end;
	}

	ret = agent_disable_event(aevent, agt->domain);
	if (ret != LTTNG_OK) {
		goto error;
	}

end:
	return LTTNG_OK;

error:
	return ret;
}

/*
 * Disable a given agent event for a given UST session.
 *
 * Must be called with the RCU read lock held.
 * Return LTTNG_OK on success or else a LTTNG_ERR* code.
 */
static int event_agent_disable_one(struct ltt_ust_session *usess,
				   struct agent *agt,
				   struct agent_event *aevent)
{
	int ret;
	struct ltt_ust_event *uevent = nullptr;
	struct ltt_ust_channel *uchan = nullptr;
	const char *ust_event_name, *ust_channel_name;

	LTTNG_ASSERT(agt);
	LTTNG_ASSERT(usess);
	LTTNG_ASSERT(aevent);

	DBG("Event agent disabling %s (loglevel type %d, loglevel value %d) for session %" PRIu64,
	    aevent->name,
	    aevent->loglevel_type,
	    aevent->loglevel_value,
	    usess->id);

	/* Already disabled? */
	if (!AGENT_EVENT_IS_ENABLED(aevent)) {
		goto end;
	}

	if (agt->domain == LTTNG_DOMAIN_JUL) {
		ust_channel_name = DEFAULT_JUL_CHANNEL_NAME;
	} else if (agt->domain == LTTNG_DOMAIN_LOG4J) {
		ust_channel_name = DEFAULT_LOG4J_CHANNEL_NAME;
	} else if (agt->domain == LTTNG_DOMAIN_PYTHON) {
		ust_channel_name = DEFAULT_PYTHON_CHANNEL_NAME;
	} else {
		ret = LTTNG_ERR_INVALID;
		goto error;
	}

	/*
	 * Disable it on the UST side. First get the channel reference then find
	 * the event and finally disable it.
	 */
	uchan = trace_ust_find_channel_by_name(usess->domain_global.channels,
					       (char *) ust_channel_name);
	if (!uchan) {
		ret = LTTNG_ERR_UST_CHAN_NOT_FOUND;
		goto error;
	}

	ust_event_name = event_get_default_agent_ust_name(agt->domain);
	if (!ust_event_name) {
		ret = LTTNG_ERR_FATAL;
		goto error;
	}

	/*
	 * Agent UST event has its loglevel type forced to
	 * LTTNG_UST_LOGLEVEL_ALL. The actual loglevel type/value filtering
	 * happens thanks to an UST filter. The following -1 is actually
	 * ignored since the type is LTTNG_UST_LOGLEVEL_ALL.
	 */
	uevent = trace_ust_find_event(uchan->events,
				      (char *) ust_event_name,
				      aevent->filter,
				      LTTNG_UST_ABI_LOGLEVEL_ALL,
				      -1,
				      nullptr);
	/* If the agent event exists, it must be available on the UST side. */
	LTTNG_ASSERT(uevent);

	if (usess->active) {
		ret = ust_app_disable_event_glb(usess, uchan, uevent);
		if (ret < 0 && ret != -LTTNG_UST_ERR_EXIST) {
			ret = LTTNG_ERR_UST_DISABLE_FAIL;
			goto error;
		}
	}

	/*
	 * Flag event that it's disabled so the shadow copy on the ust app side
	 * will disable it if an application shows up.
	 */
	uevent->enabled = false;

	ret = agent_disable_event(aevent, agt->domain);
	if (ret != LTTNG_OK) {
		goto error;
	}

end:
	return LTTNG_OK;

error:
	return ret;
}

/*
 * Disable agent event matching a given trigger.
 *
 * Return LTTNG_OK on success or else a LTTNG_ERR* code.
 */
int trigger_agent_disable(const struct lttng_trigger *trigger, struct agent *agt)
{
	int ret = LTTNG_OK;
	struct agent_event *aevent;

	LTTNG_ASSERT(trigger);
	LTTNG_ASSERT(agt);

	DBG("Event agent disabling for trigger %" PRIu64, lttng_trigger_get_tracer_token(trigger));

	lttng::urcu::read_lock_guard read_lock;
	aevent = agent_find_event_by_trigger(trigger, agt);

	if (aevent == nullptr) {
		DBG2("Event agent NOT found by trigger %" PRIu64,
		     lttng_trigger_get_tracer_token(trigger));
		ret = LTTNG_ERR_UST_EVENT_NOT_FOUND;
		goto end;
	}

	ret = trigger_agent_disable_one(trigger, agt, aevent);

	if (ret != LTTNG_OK) {
		goto end;
	}

end:
	return ret;
}

/*
 * Disable all agent events matching a given name for a given UST session.
 *
 * Return LTTNG_OK on success or else a LTTNG_ERR* code.
 */
int event_agent_disable(struct ltt_ust_session *usess, struct agent *agt, const char *event_name)
{
	int ret = LTTNG_OK;
	struct agent_event *aevent;
	struct lttng_ht_iter iter;
	struct lttng_ht_node_str *node;

	LTTNG_ASSERT(agt);
	LTTNG_ASSERT(usess);
	LTTNG_ASSERT(event_name);

	DBG("Event agent disabling %s (all loglevels) for session %" PRIu64, event_name, usess->id);

	lttng::urcu::read_lock_guard read_lock;
	agent_find_events_by_name(event_name, agt, &iter);
	node = lttng_ht_iter_get_node_str(&iter);

	if (node == nullptr) {
		DBG2("Event agent NOT found by name %s", event_name);
		ret = LTTNG_ERR_UST_EVENT_NOT_FOUND;
		goto end;
	}

	do {
		aevent = lttng::utils::container_of(node, &agent_event::node);
		ret = event_agent_disable_one(usess, agt, aevent);

		if (ret != LTTNG_OK) {
			goto end;
		}

		/* Get next duplicate agent event by name. */
		agent_event_next_duplicate(event_name, agt, &iter);
		node = lttng_ht_iter_get_node_str(&iter);
	} while (node);
end:
	return ret;
}
/*
 * Disable all agent event for a given UST session.
 *
 * Return LTTNG_OK on success or else a LTTNG_ERR* code.
 */
int event_agent_disable_all(struct ltt_ust_session *usess, struct agent *agt)
{
	int ret;
	struct agent_event *aevent;
	struct lttng_ht_iter iter;

	LTTNG_ASSERT(agt);
	LTTNG_ASSERT(usess);

	/*
	 * Disable event on agent application. Continue to disable all other events
	 * if the * event is not found.
	 */
	ret = event_agent_disable(usess, agt, "*");
	if (ret != LTTNG_OK && ret != LTTNG_ERR_UST_EVENT_NOT_FOUND) {
		goto error;
	}

	/* Disable every event. */
	{
		lttng::urcu::read_lock_guard read_lock;

		cds_lfht_for_each_entry (agt->events->ht, &iter.iter, aevent, node.node) {
			if (!AGENT_EVENT_IS_ENABLED(aevent)) {
				continue;
			}

			ret = event_agent_disable(usess, agt, aevent->name);
			if (ret != LTTNG_OK) {
				goto error_unlock;
			}
		}
	}

	ret = LTTNG_OK;

error_unlock:
error:
	return ret;
}
