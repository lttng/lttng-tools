/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 * Copyright (C) 2016 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
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

#define _LGPL_SOURCE
#include <errno.h>
#include <urcu/list.h>
#include <string.h>

#include <lttng/lttng.h>
#include <common/error.h>
#include <common/sessiond-comm/sessiond-comm.h>
#include <common/filter.h>
#include <common/context.h>

#include "channel.h"
#include "event.h"
#include "kernel.h"
#include "lttng-sessiond.h"
#include "ust-ctl.h"
#include "ust-app.h"
#include "trace-kernel.h"
#include "trace-ust.h"
#include "agent.h"

/*
 * Add unique UST event based on the event name, filter bytecode and loglevel.
 */
static void add_unique_ust_event(struct lttng_ht *ht,
		struct ltt_ust_event *event)
{
	struct cds_lfht_node *node_ptr;
	struct ltt_ust_ht_key key;

	assert(ht);
	assert(ht->ht);
	assert(event);

	key.name = event->attr.name;
	key.filter = (struct lttng_filter_bytecode *) event->filter;
	key.loglevel_type = event->attr.loglevel_type;
	key.loglevel_value = event->attr.loglevel;
	key.exclusion = event->exclusion;

	node_ptr = cds_lfht_add_unique(ht->ht,
			ht->hash_fct(event->node.key, lttng_ht_seed),
			trace_ust_ht_match_event, &key, &event->node.node);
	assert(node_ptr == &event->node.node);
}

/*
 * Disable kernel tracepoint events for a channel from the kernel session of
 * a specified event_name and event type.
 * On type LTTNG_EVENT_ALL all events with event_name are disabled.
 * If event_name is NULL all events of the specified type are disabled.
 */
int event_kernel_disable_event(struct ltt_kernel_channel *kchan,
		char *event_name, enum lttng_event_type type)
{
	int ret, error = 0, found = 0;
	struct ltt_kernel_event *kevent;

	assert(kchan);

	/* For each event in the kernel session */
	cds_list_for_each_entry(kevent, &kchan->events_list.head, list) {
		if (type != LTTNG_EVENT_ALL && kevent->type != type)
			continue;
		if (event_name != NULL && strcmp(event_name, kevent->event->name)) {
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
			found, event_name ? event_name : "NULL", type);

	if (event_name != NULL && !found) {
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
		struct lttng_event *event, char *filter_expression,
		struct lttng_filter_bytecode *filter)
{
	int ret;
	struct ltt_kernel_event *kevent;

	assert(kchan);
	assert(event);

	kevent = trace_kernel_find_event(event->name, kchan,
			event->type, filter);
	if (kevent == NULL) {
		ret = kernel_create_event(event, kchan,
			filter_expression, filter);
		/* We have passed ownership */
		filter_expression = NULL;
		filter = NULL;
		if (ret < 0) {
			switch (-ret) {
			case EEXIST:
				ret = LTTNG_ERR_KERN_EVENT_EXIST;
				break;
			case ENOSYS:
				ret = LTTNG_ERR_KERN_EVENT_ENOSYS;
				break;
			default:
				ret = LTTNG_ERR_KERN_ENABLE_FAIL;
				break;
			}
			goto end;
		}
	} else if (kevent->enabled == 0) {
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
		struct ltt_ust_channel *uchan, struct lttng_event *event,
		char *filter_expression,
		struct lttng_filter_bytecode *filter,
		struct lttng_event_exclusion *exclusion,
		bool internal_event)
{
	int ret = LTTNG_OK, to_create = 0;
	struct ltt_ust_event *uevent;

	assert(usess);
	assert(uchan);
	assert(event);

	rcu_read_lock();

	uevent = trace_ust_find_event(uchan->events, event->name, filter,
			event->loglevel_type, event->loglevel, exclusion);
	if (!uevent) {
		uevent = trace_ust_create_event(event, filter_expression,
				filter, exclusion, internal_event);
		/* We have passed ownership */
		filter_expression = NULL;
		filter = NULL;
		exclusion = NULL;
		if (uevent == NULL) {
			ret = LTTNG_ERR_UST_ENABLE_FAIL;
			goto error;
		}

		/* Valid to set it after the goto error since uevent is still NULL */
		to_create = 1;
	}

	if (uevent->enabled) {
		/* It's already enabled so everything is OK */
		ret = LTTNG_ERR_UST_EVENT_ENABLED;
		goto end;
	}

	uevent->enabled = 1;

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
			goto end;
		} else {
			ret = LTTNG_ERR_UST_ENABLE_FAIL;
			goto error;
		}
	}

	if (to_create) {
		/* Add ltt ust event to channel */
		add_unique_ust_event(uchan->events, uevent);
	}

	DBG("Event UST %s %s in channel %s", uevent->attr.name,
			to_create ? "created" : "enabled", uchan->name);

	ret = LTTNG_OK;

end:
	rcu_read_unlock();
	free(filter_expression);
	free(filter);
	free(exclusion);
	return ret;

error:
	/*
	 * Only destroy event on creation time (not enabling time) because if the
	 * event is found in the channel (to_create == 0), it means that at some
	 * point the enable_event worked and it's thus valid to keep it alive.
	 * Destroying it also implies that we also destroy it's shadow copy to sync
	 * everyone up.
	 */
	if (to_create) {
		/* In this code path, the uevent was not added to the hash table */
		trace_ust_destroy_event(uevent);
	}
	rcu_read_unlock();
	free(filter_expression);
	free(filter);
	free(exclusion);
	return ret;
}

/*
 * Disable UST tracepoint of a channel from a UST session.
 */
int event_ust_disable_tracepoint(struct ltt_ust_session *usess,
		struct ltt_ust_channel *uchan, char *event_name)
{
	int ret;
	struct ltt_ust_event *uevent;
	struct lttng_ht_node_str *node;
	struct lttng_ht_iter iter;
	struct lttng_ht *ht;

	assert(usess);
	assert(uchan);
	assert(event_name);

	ht = uchan->events;

	rcu_read_lock();

	/*
	 * We use a custom lookup since we need the iterator for the next_duplicate
	 * call in the do while loop below.
	 */
	cds_lfht_lookup(ht->ht, ht->hash_fct((void *) event_name, lttng_ht_seed),
			trace_ust_ht_match_event_by_name, event_name, &iter.iter);
	node = lttng_ht_iter_get_node_str(&iter);
	if (node == NULL) {
		DBG2("Trace UST event NOT found by name %s", event_name);
		ret = LTTNG_ERR_UST_EVENT_NOT_FOUND;
		goto error;
	}

	do {
		uevent = caa_container_of(node, struct ltt_ust_event, node);
		assert(uevent);

		if (uevent->enabled == 0) {
			/* It's already disabled so everything is OK */
			goto next;
		}

		ret = ust_app_disable_event_glb(usess, uchan, uevent);
		if (ret < 0 && ret != -LTTNG_UST_ERR_EXIST) {
			ret = LTTNG_ERR_UST_DISABLE_FAIL;
			goto error;
		}
		uevent->enabled = 0;

		DBG2("Event UST %s disabled in channel %s", uevent->attr.name,
				uchan->name);

next:
		/* Get next duplicate event by name. */
		cds_lfht_next_duplicate(ht->ht, trace_ust_ht_match_event_by_name,
				event_name, &iter.iter);
		node = lttng_ht_iter_get_node_str(&iter);
	} while (node);

	ret = LTTNG_OK;

error:
	rcu_read_unlock();
	return ret;
}

/*
 * Disable all UST tracepoints for a channel from a UST session.
 */
int event_ust_disable_all_tracepoints(struct ltt_ust_session *usess,
		struct ltt_ust_channel *uchan)
{
	int ret, i, size, error = 0;
	struct lttng_ht_iter iter;
	struct ltt_ust_event *uevent = NULL;
	struct lttng_event *events = NULL;

	assert(usess);
	assert(uchan);

	rcu_read_lock();

	/* Disabling existing events */
	cds_lfht_for_each_entry(uchan->events->ht, &iter.iter, uevent,
			node.node) {
		if (uevent->enabled == 1) {
			ret = event_ust_disable_tracepoint(usess, uchan,
					uevent->attr.name);
			if (ret < 0) {
				error = LTTNG_ERR_UST_DISABLE_FAIL;
				continue;
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
		ret = event_ust_disable_tracepoint(usess, uchan,
				events[i].name);
		if (ret < 0) {
			/* Continue to disable the rest... */
			error = LTTNG_ERR_UST_DISABLE_FAIL;
			continue;
		}
	}

	ret = error ? error : LTTNG_OK;
error:
	rcu_read_unlock();
	free(events);
	return ret;
}

/*
 * Enable all agent event for a given UST session.
 *
 * Return LTTNG_OK on success or else a LTTNG_ERR* code.
 */
int event_agent_enable_all(struct ltt_ust_session *usess,
		struct agent *agt, struct lttng_event *event,
		struct lttng_filter_bytecode *filter ,char *filter_expression)
{
	int ret;
	struct agent_event *aevent;
	struct lttng_ht_iter iter;

	assert(usess);

	DBG("Event agent enabling ALL events for session %" PRIu64, usess->id);

	/* Enable event on agent application through TCP socket. */
	ret = event_agent_enable(usess, agt, event, filter, filter_expression);
	if (ret != LTTNG_OK) {
		goto error;
	}

	/* Flag every event that they are now enabled. */
	rcu_read_lock();
	cds_lfht_for_each_entry(agt->events->ht, &iter.iter, aevent,
			node.node) {
		aevent->enabled = 1;
	}
	rcu_read_unlock();

	ret = LTTNG_OK;

error:
	return ret;
}

/*
 * Check if this event's filter requires the activation of application contexts
 * and enable them in the agent.
 */
static int add_filter_app_ctx(struct lttng_filter_bytecode *bytecode,
		const char *filter_expression, struct agent *agt)
{
	int ret = LTTNG_OK;
	char *provider_name = NULL, *ctx_name = NULL;
	struct bytecode_symbol_iterator *it =
			bytecode_symbol_iterator_create(bytecode);

	if (!it) {
		ret = LTTNG_ERR_NOMEM;
		goto end;
	}

	do {
		struct lttng_event_context ctx;
		const char *symbol_name =
				bytecode_symbol_iterator_get_name(it);

		if (parse_application_context(symbol_name, &provider_name,
				&ctx_name)) {
			/* Not an application context. */
			continue;
		}

		ctx.ctx = LTTNG_EVENT_CONTEXT_APP_CONTEXT;
		ctx.u.app_ctx.provider_name = provider_name;
		ctx.u.app_ctx.ctx_name = ctx_name;

		/* Recognized an application context. */
		DBG("Enabling event with filter expression \"%s\" requires enabling the %s:%s application context.",
				filter_expression, provider_name, ctx_name);

		ret = agent_add_context(&ctx, agt);
		if (ret != LTTNG_OK) {
			ERR("Failed to add application context %s:%s.",
					provider_name, ctx_name);
			goto end;
		}

		ret = agent_enable_context(&ctx, agt->domain);
		if (ret != LTTNG_OK) {
			ERR("Failed to enable application context %s:%s.",
					provider_name, ctx_name);
			goto end;
		}

		free(provider_name);
		free(ctx_name);
		provider_name = ctx_name = NULL;
	} while (bytecode_symbol_iterator_next(it) == 0);
end:
	free(provider_name);
	free(ctx_name);
	bytecode_symbol_iterator_destroy(it);
	return ret;
}

/*
 * Enable a single agent event for a given UST session.
 *
 * Return LTTNG_OK on success or else a LTTNG_ERR* code.
 */
int event_agent_enable(struct ltt_ust_session *usess,
		struct agent *agt, struct lttng_event *event,
		struct lttng_filter_bytecode *filter,
		char *filter_expression)
{
	int ret, created = 0;
	struct agent_event *aevent;

	assert(usess);
	assert(event);
	assert(agt);

	DBG("Event agent enabling %s for session %" PRIu64 " with loglevel type %d "
			", loglevel %d and filter \"%s\"", event->name,
			usess->id, event->loglevel_type, event->loglevel,
			filter_expression ? filter_expression : "NULL");

	aevent = agent_find_event(event->name, event->loglevel_type,
			event->loglevel, filter_expression, agt);
	if (!aevent) {
		aevent = agent_create_event(event->name, event->loglevel_type,
				event->loglevel, filter,
				filter_expression);
		if (!aevent) {
			ret = LTTNG_ERR_NOMEM;
			goto error;
		}

		created = 1;
	}

	/* Already enabled? */
	if (aevent->enabled) {
		goto end;
	}

	if (created && filter) {
		ret = add_filter_app_ctx(filter, filter_expression, agt);
		if (ret != LTTNG_OK) {
			goto error;
		}
	}

	ret = agent_enable_event(aevent, agt->domain);
	if (ret != LTTNG_OK) {
		goto error;
	}

	/* If the event was created prior to the enable, add it to the domain. */
	if (created) {
		agent_add_event(aevent, agt);
	}

end:
	return LTTNG_OK;

error:
	if (created) {
		agent_destroy_event(aevent);
	}
	return ret;
}

/*
 * Return the default event name associated with the provided UST domain. Return
 * NULL on error.
 */
const char *event_get_default_agent_ust_name(enum lttng_domain_type domain)
{
	const char *default_event_name = NULL;

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
		assert(0);
	}

	return default_event_name;
}

/*
 * Disable a given agent event for a given UST session.
 *
 * Must be called with the RCU read lock held.
 * Return LTTNG_OK on success or else a LTTNG_ERR* code.
 */
static int event_agent_disable_one(struct ltt_ust_session *usess,
		struct agent *agt, struct agent_event *aevent)
{
	int ret;
	struct ltt_ust_event *uevent = NULL;
	struct ltt_ust_channel *uchan = NULL;
	const char *ust_event_name, *ust_channel_name;

	assert(agt);
	assert(usess);
	assert(aevent);

	DBG("Event agent disabling %s (loglevel type %d, loglevel value %d) for session %" PRIu64,
		aevent->name, aevent->loglevel_type, aevent->loglevel_value,
		usess->id);

	/* Already disabled? */
	if (!aevent->enabled) {
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
	uevent = trace_ust_find_event(uchan->events, (char *) ust_event_name,
			aevent->filter, LTTNG_UST_LOGLEVEL_ALL, -1, NULL);
	/* If the agent event exists, it must be available on the UST side. */
	assert(uevent);

	ret = ust_app_disable_event_glb(usess, uchan, uevent);
	if (ret < 0 && ret != -LTTNG_UST_ERR_EXIST) {
		ret = LTTNG_ERR_UST_DISABLE_FAIL;
		goto error;
	}

	/*
	 * Flag event that it's disabled so the shadow copy on the ust app side
	 * will disable it if an application shows up.
	 */
	uevent->enabled = 0;

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
 * Disable all agent events matching a given name for a given UST session.
 *
 * Return LTTNG_OK on success or else a LTTNG_ERR* code.
 */
int event_agent_disable(struct ltt_ust_session *usess, struct agent *agt,
		char *event_name)
{
	int ret = LTTNG_OK;
	struct agent_event *aevent;
	struct lttng_ht_iter iter;
	struct lttng_ht_node_str *node;

	assert(agt);
	assert(usess);
	assert(event_name);

	DBG("Event agent disabling %s (all loglevels) for session %" PRIu64, event_name, usess->id);

	rcu_read_lock();
	agent_find_events_by_name(event_name, agt, &iter);
	node = lttng_ht_iter_get_node_str(&iter);

	if (node == NULL) {
		DBG2("Event agent NOT found by name %s", event_name);
		ret = LTTNG_ERR_UST_EVENT_NOT_FOUND;
		goto end;
	}

	do {
		aevent = caa_container_of(node, struct agent_event, node);
		ret = event_agent_disable_one(usess, agt, aevent);

		if (ret != LTTNG_OK) {
			goto end;
		}

		/* Get next duplicate agent event by name. */
		agent_event_next_duplicate(event_name, agt, &iter);
		node = lttng_ht_iter_get_node_str(&iter);
	} while (node);
end:
	rcu_read_unlock();
	return ret;
}
/*
 * Disable all agent event for a given UST session.
 *
 * Return LTTNG_OK on success or else a LTTNG_ERR* code.
 */
int event_agent_disable_all(struct ltt_ust_session *usess,
		struct agent *agt)
{
	int ret;
	struct agent_event *aevent;
	struct lttng_ht_iter iter;

	assert(agt);
	assert(usess);

	/*
	 * Disable event on agent application. Continue to disable all other events
	 * if the * event is not found.
	 */
	ret = event_agent_disable(usess, agt, "*");
	if (ret != LTTNG_OK && ret != LTTNG_ERR_UST_EVENT_NOT_FOUND) {
		goto error;
	}

	/* Disable every event. */
	rcu_read_lock();
	cds_lfht_for_each_entry(agt->events->ht, &iter.iter, aevent,
			node.node) {
		if (!aevent->enabled) {
			continue;
		}

		ret = event_agent_disable(usess, agt, aevent->name);
		if (ret != LTTNG_OK) {
			goto error_unlock;
		}
	}
	ret = LTTNG_OK;

error_unlock:
	rcu_read_unlock();
error:
	return ret;
}
