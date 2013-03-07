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
#include <errno.h>
#include <urcu/list.h>
#include <string.h>

#include <lttng/lttng.h>
#include <common/error.h>
#include <common/sessiond-comm/sessiond-comm.h>

#include "channel.h"
#include "event.h"
#include "kernel.h"
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
	key.loglevel = event->attr.loglevel;

	node_ptr = cds_lfht_add_unique(ht->ht,
			ht->hash_fct(event->node.key, lttng_ht_seed),
			trace_ust_ht_match_event, &key, &event->node.node);
	assert(node_ptr == &event->node.node);
}

/*
 * Setup a lttng_event used to enable *all* syscall tracing.
 */
static void init_syscalls_kernel_event(struct lttng_event *event)
{
	assert(event);

	event->name[0] = '\0';
	/*
	 * We use LTTNG_EVENT* here since the trace kernel creation will make the
	 * right changes for the kernel.
	 */
	event->type = LTTNG_EVENT_SYSCALL;
}

/*
 * Disable kernel tracepoint event for a channel from the kernel session.
 */
int event_kernel_disable_tracepoint(struct ltt_kernel_channel *kchan,
		char *event_name)
{
	int ret;
	struct ltt_kernel_event *kevent;

	assert(kchan);

	kevent = trace_kernel_get_event_by_name(event_name, kchan);
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
int event_kernel_disable_all_tracepoints(struct ltt_kernel_channel *kchan)
{
	int ret;
	struct ltt_kernel_event *kevent;

	assert(kchan);

	/* For each event in the kernel session */
	cds_list_for_each_entry(kevent, &kchan->events_list.head, list) {
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
 * Disable kernel syscall events for a channel from the kernel session.
 */
int event_kernel_disable_all_syscalls(struct ltt_kernel_channel *kchan)
{
	ERR("Cannot disable syscall tracing for existing session. Please destroy session instead.");
	return LTTNG_OK;	/* Return OK so disable all succeeds */
}

/*
 * Disable all kernel event for a channel from the kernel session.
 */
int event_kernel_disable_all(struct ltt_kernel_channel *kchan)
{
	int ret;

	assert(kchan);

	ret = event_kernel_disable_all_tracepoints(kchan);
	if (ret != LTTNG_OK)
		return ret;
	ret = event_kernel_disable_all_syscalls(kchan);
	return ret;
}

/*
 * Enable kernel tracepoint event for a channel from the kernel session.
 */
int event_kernel_enable_tracepoint(struct ltt_kernel_channel *kchan,
		struct lttng_event *event)
{
	int ret;
	struct ltt_kernel_event *kevent;

	assert(kchan);
	assert(event);

	kevent = trace_kernel_get_event_by_name(event->name, kchan);
	if (kevent == NULL) {
		ret = kernel_create_event(event, kchan);
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
	return ret;
}

/*
 * Enable all kernel tracepoint events of a channel of the kernel session.
 */
int event_kernel_enable_all_tracepoints(struct ltt_kernel_channel *kchan,
		int kernel_tracer_fd)
{
	int size, i, ret;
	struct ltt_kernel_event *kevent;
	struct lttng_event *event_list = NULL;

	assert(kchan);

	/* For each event in the kernel session */
	cds_list_for_each_entry(kevent, &kchan->events_list.head, list) {
		if (kevent->enabled == 0) {
			ret = kernel_enable_event(kevent);
			if (ret < 0) {
				/* Enable failed but still continue */
				continue;
			}
		}
	}

	size = kernel_list_events(kernel_tracer_fd, &event_list);
	if (size < 0) {
		ret = LTTNG_ERR_KERN_LIST_FAIL;
		goto end;
	}

	for (i = 0; i < size; i++) {
		kevent = trace_kernel_get_event_by_name(event_list[i].name, kchan);
		if (kevent == NULL) {
			/* Default event type for enable all */
			event_list[i].type = LTTNG_EVENT_TRACEPOINT;
			/* Enable each single tracepoint event */
			ret = kernel_create_event(&event_list[i], kchan);
			if (ret < 0) {
				/* Ignore error here and continue */
			}
		}
	}
	free(event_list);

	ret = LTTNG_OK;
end:
	return ret;
}

/*
 * Enable all kernel tracepoint events of a channel of the kernel session.
 */
int event_kernel_enable_all_syscalls(struct ltt_kernel_channel *kchan,
		int kernel_tracer_fd)
{
	int ret;
	struct lttng_event event;

	assert(kchan);

	init_syscalls_kernel_event(&event);

	DBG("Enabling all syscall tracing");

	ret = kernel_create_event(&event, kchan);
	if (ret < 0) {
		if (ret == -EEXIST) {
			ret = LTTNG_ERR_KERN_EVENT_EXIST;
		} else {
			ret = LTTNG_ERR_KERN_ENABLE_FAIL;
		}
		goto end;
	}

	ret = LTTNG_OK;
end:
	return ret;
}

/*
 * Enable all kernel events of a channel of the kernel session.
 */
int event_kernel_enable_all(struct ltt_kernel_channel *kchan,
		int kernel_tracer_fd)
{
	int tp_ret;

	assert(kchan);

	tp_ret = event_kernel_enable_all_tracepoints(kchan, kernel_tracer_fd);
	if (tp_ret != LTTNG_OK) {
		goto end;
	}

	/*
	 * Reaching this code path means that all tracepoints were enabled without
	 * errors so we ignore the error value of syscalls.
	 *
	 * At the moment, failing to enable syscalls on "lttng enable-event -a -k"
	 * is not considered an error that need to be returned to the client since
	 * tracepoints did not fail. Future work will allow us to send back
	 * multiple errors to the client in one API call.
	 */
	(void) event_kernel_enable_all_syscalls(kchan, kernel_tracer_fd);

end:
	return tp_ret;
}

/*
 * ============================
 * UST : The Ultimate Frontier!
 * ============================
 */

/*
 * Enable all UST tracepoints for a channel from a UST session.
 */
int event_ust_enable_all_tracepoints(struct ltt_ust_session *usess,
		struct ltt_ust_channel *uchan, struct lttng_filter_bytecode *filter)
{
	int ret, i, size;
	struct lttng_ht_iter iter;
	struct ltt_ust_event *uevent = NULL;
	struct lttng_event *events = NULL;

	assert(usess);
	assert(uchan);

	rcu_read_lock();

	/* Enable existing events */
	cds_lfht_for_each_entry(uchan->events->ht, &iter.iter, uevent,
			node.node) {
		if (uevent->enabled == 0) {
			ret = ust_app_enable_event_glb(usess, uchan, uevent);
			if (ret < 0) {
				continue;
			}
			uevent->enabled = 1;
		}
	}

	/* Get all UST available events */
	size = ust_app_list_events(&events);
	if (size < 0) {
		ret = LTTNG_ERR_UST_LIST_FAIL;
		goto error;
	}

	for (i = 0; i < size; i++) {
		/*
		 * Check if event exist and if so, continue since it was enable
		 * previously.
		 */
		uevent = trace_ust_find_event(uchan->events, events[i].name, filter,
				events[i].loglevel);
		if (uevent != NULL) {
			ret = ust_app_enable_event_pid(usess, uchan, uevent,
					events[i].pid);
			if (ret < 0) {
				if (ret != -LTTNG_UST_ERR_EXIST) {
					ret = LTTNG_ERR_UST_ENABLE_FAIL;
					goto error;
				}
			}
			continue;
		}

		/* Create ust event */
		uevent = trace_ust_create_event(&events[i], filter);
		if (uevent == NULL) {
			ret = LTTNG_ERR_FATAL;
			goto error_destroy;
		}

		/* Create event for the specific PID */
		ret = ust_app_enable_event_pid(usess, uchan, uevent,
				events[i].pid);
		if (ret < 0) {
			if (ret == -LTTNG_UST_ERR_EXIST) {
				ret = LTTNG_ERR_UST_EVENT_EXIST;
				goto error;
			} else {
				ret = LTTNG_ERR_UST_ENABLE_FAIL;
				goto error_destroy;
			}
		}

		uevent->enabled = 1;
		/* Add ltt ust event to channel */
		rcu_read_lock();
		add_unique_ust_event(uchan->events, uevent);
		rcu_read_unlock();
	}
	free(events);

	rcu_read_unlock();
	return LTTNG_OK;

error_destroy:
	trace_ust_destroy_event(uevent);

error:
	free(events);
	rcu_read_unlock();
	return ret;
}

/*
 * Enable UST tracepoint event for a channel from a UST session.
 */
int event_ust_enable_tracepoint(struct ltt_ust_session *usess,
		struct ltt_ust_channel *uchan, struct lttng_event *event,
		struct lttng_filter_bytecode *filter)
{
	int ret = LTTNG_OK, to_create = 0;
	struct ltt_ust_event *uevent;

	assert(usess);
	assert(uchan);
	assert(event);

	rcu_read_lock();

	uevent = trace_ust_find_event(uchan->events, event->name, filter,
			event->loglevel);
	if (uevent == NULL) {
		uevent = trace_ust_create_event(event, filter);
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
			ret = LTTNG_OK;
			continue;
		}

		ret = ust_app_disable_event_glb(usess, uchan, uevent);
		if (ret < 0 && ret != -LTTNG_UST_ERR_EXIST) {
			ret = LTTNG_ERR_UST_DISABLE_FAIL;
			goto error;
		}
		uevent->enabled = 0;

		DBG2("Event UST %s disabled in channel %s", uevent->attr.name,
				uchan->name);

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
	int ret, i, size;
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
		if (ret != LTTNG_OK) {
			/* Continue to disable the rest... */
			continue;
		}
	}
	free(events);

	rcu_read_unlock();
	return LTTNG_OK;

error:
	free(events);
	rcu_read_unlock();
	return ret;
}
