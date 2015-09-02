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

#define _GNU_SOURCE
#define _LGPL_SOURCE
#include <errno.h>
#include <urcu/list.h>
#include <string.h>

#include <lttng/lttng.h>
#include <common/error.h>
#include <common/sessiond-comm/sessiond-comm.h>

#include "channel.h"
#include "event.h"
#include "kernel.h"
#include "lttng-sessiond.h"
#include "ust-ctl.h"
#include "ust-app.h"
#include "trace-kernel.h"
#include "trace-ust.h"

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
 * Disable kernel tracepoint event for a channel from the kernel session.
 */
int event_kernel_disable_event(struct ltt_kernel_channel *kchan,
		char *event_name)
{
	int ret;
	struct ltt_kernel_event *kevent;

	assert(kchan);

	kevent = trace_kernel_get_event_by_name(event_name, kchan,
			LTTNG_EVENT_ALL);
	if (kevent == NULL) {
		ret = LTTNG_ERR_NO_EVENT;
		goto error;
	}

	ret = kernel_disable_event(kevent);
	if (ret < 0) {
		ret = LTTNG_ERR_KERN_DISABLE_FAIL;
		goto error;
	}

	DBG("Kernel event %s disable for channel %s.",
			kevent->event->name, kchan->channel->name);

	ret = LTTNG_OK;

error:
	return ret;
}

/*
 * Disable kernel tracepoint events for a channel from the kernel session.
 */
int event_kernel_disable_event_type(struct ltt_kernel_channel *kchan,
		enum lttng_event_type type)
{
	int ret;
	struct ltt_kernel_event *kevent;

	assert(kchan);

	/* For each event in the kernel session */
	cds_list_for_each_entry(kevent, &kchan->events_list.head, list) {
		if (type != LTTNG_EVENT_ALL && kevent->type != type)
			continue;
		ret = kernel_disable_event(kevent);
		if (ret < 0) {
			/* We continue disabling the rest */
			continue;
		}
	}
	ret = LTTNG_OK;
	return ret;
}

/*
 * Disable all kernel event for a channel from the kernel session.
 */
int event_kernel_disable_event_all(struct ltt_kernel_channel *kchan)
{
	return event_kernel_disable_event_type(kchan, LTTNG_EVENT_ALL);
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

	aevent = agent_find_event(event->name, event->loglevel, agt);
	if (!aevent) {
		aevent = agent_create_event(event->name, event->loglevel,
				event->loglevel_type, filter,
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
 * Return the agent default event name to use by testing if the process is root
 * or not. Return NULL on error.
 */
const char *event_get_default_agent_ust_name(enum lttng_domain_type domain)
{
	const char *default_event_name = NULL;

	switch (domain) {
	case LTTNG_DOMAIN_LOG4J:
		if (is_root) {
			default_event_name = DEFAULT_SYS_LOG4J_EVENT_NAME;
		} else {
			default_event_name = DEFAULT_USER_LOG4J_EVENT_NAME;
		}
		break;
	case LTTNG_DOMAIN_JUL:
		if (is_root) {
			default_event_name = DEFAULT_SYS_JUL_EVENT_NAME;
		} else {
			default_event_name = DEFAULT_USER_JUL_EVENT_NAME;
		}
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
 * Disable a single agent event for a given UST session.
 *
 * Return LTTNG_OK on success or else a LTTNG_ERR* code.
 */
int event_agent_disable(struct ltt_ust_session *usess, struct agent *agt,
		char *event_name)
{
	int ret;
	struct agent_event *aevent;
	struct ltt_ust_event *uevent = NULL;
	struct ltt_ust_channel *uchan = NULL;
	const char *ust_event_name, *ust_channel_name;

	assert(agt);
	assert(usess);
	assert(event_name);

	DBG("Event agent disabling %s for session %" PRIu64, event_name, usess->id);

	aevent = agent_find_event_by_name(event_name, agt);
	if (!aevent) {
		ret = LTTNG_ERR_UST_EVENT_NOT_FOUND;
		goto error;
	}

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

	/* Flag every event that they are now enabled. */
	rcu_read_lock();
	cds_lfht_for_each_entry(agt->events->ht, &iter.iter, aevent,
			node.node) {
		if (!aevent->enabled) {
			continue;
		}

		ret = event_agent_disable(usess, agt, aevent->name);
		if (ret != LTTNG_OK) {
			rcu_read_unlock();
			goto error;
		}
	}
	rcu_read_unlock();

	ret = LTTNG_OK;

error:
	return ret;
}
