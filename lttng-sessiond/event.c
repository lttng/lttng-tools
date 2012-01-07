/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; only version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <urcu/list.h>
#include <string.h>

#include <lttng/lttng.h>
#include <lttng-sessiond-comm.h>
#include <lttngerr.h>

#include "channel.h"
#include "event.h"
#include "../common/hashtable.h"
#include "kernel.h"
#include "ust-ctl.h"
#include "ust-app.h"
#include "trace-kernel.h"
#include "trace-ust.h"

/*
 * Setup a lttng_event used to enable *all* syscall tracing.
 */
static void init_syscalls_kernel_event(struct lttng_event *event)
{
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
int event_kernel_disable_tracepoint(struct ltt_kernel_session *ksession,
		struct ltt_kernel_channel *kchan, char *event_name)
{
	int ret;
	struct ltt_kernel_event *kevent;

	kevent = trace_kernel_get_event_by_name(event_name, kchan);
	if (kevent == NULL) {
		ret = LTTCOMM_NO_EVENT;
		goto error;
	}

	ret = kernel_disable_event(kevent);
	if (ret < 0) {
		ret = LTTCOMM_KERN_DISABLE_FAIL;
		goto error;
	}

	DBG("Kernel event %s disable for channel %s.",
			kevent->event->name, kchan->channel->name);

	ret = LTTCOMM_OK;

error:
	return ret;
}

/*
 * Disable kernel tracepoint events for a channel from the kernel session.
 */
int event_kernel_disable_all_tracepoints(struct ltt_kernel_session *ksession,
		struct ltt_kernel_channel *kchan)
{
	int ret;
	struct ltt_kernel_event *kevent;

	/* For each event in the kernel session */
	cds_list_for_each_entry(kevent, &kchan->events_list.head, list) {
		ret = kernel_disable_event(kevent);
		if (ret < 0) {
			/* We continue disabling the rest */
			continue;
		}
	}
	ret = LTTCOMM_OK;
	return ret;
}

/*
 * Disable kernel syscall events for a channel from the kernel session.
 */
int event_kernel_disable_all_syscalls(struct ltt_kernel_session *ksession,
		struct ltt_kernel_channel *kchan)
{
	ERR("Cannot disable syscall tracing for existing session. Please destroy session instead.");
	return LTTCOMM_OK;	/* Return OK so disable all succeeds */
}

/*
 * Disable all kernel event for a channel from the kernel session.
 */
int event_kernel_disable_all(struct ltt_kernel_session *ksession,
		struct ltt_kernel_channel *kchan)
{
	int ret;

	ret = event_kernel_disable_all_tracepoints(ksession, kchan);
	if (ret != LTTCOMM_OK)
		return ret;
	ret = event_kernel_disable_all_syscalls(ksession, kchan);
	return ret;
}

/*
 * Enable kernel tracepoint event for a channel from the kernel session.
 */
int event_kernel_enable_tracepoint(struct ltt_kernel_session *ksession,
		struct ltt_kernel_channel *kchan, struct lttng_event *event)
{
	int ret;
	struct ltt_kernel_event *kevent;

	kevent = trace_kernel_get_event_by_name(event->name, kchan);
	if (kevent == NULL) {
		ret = kernel_create_event(event, kchan);
		if (ret < 0) {
			if (ret == -EEXIST) {
				ret = LTTCOMM_KERN_EVENT_EXIST;
			} else {
				ret = LTTCOMM_KERN_ENABLE_FAIL;
			}
			goto end;
		}
	} else if (kevent->enabled == 0) {
		ret = kernel_enable_event(kevent);
		if (ret < 0) {
			ret = LTTCOMM_KERN_ENABLE_FAIL;
			goto end;
		}
	}
	ret = LTTCOMM_OK;
end:
	return ret;
}

/*
 * Enable all kernel tracepoint events of a channel of the kernel session.
 */
int event_kernel_enable_all_tracepoints(struct ltt_kernel_session *ksession,
		struct ltt_kernel_channel *kchan, int kernel_tracer_fd)
{
	int size, i, ret;
	struct ltt_kernel_event *kevent;
	struct lttng_event *event_list = NULL;

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
		ret = LTTCOMM_KERN_LIST_FAIL;
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

	ret = LTTCOMM_OK;
end:
	return ret;

}

/*
 * Enable all kernel tracepoint events of a channel of the kernel session.
 */
int event_kernel_enable_all_syscalls(struct ltt_kernel_session *ksession,
		struct ltt_kernel_channel *kchan, int kernel_tracer_fd)
{
	int ret;
	struct lttng_event event;

	init_syscalls_kernel_event(&event);

	DBG("Enabling all syscall tracing");

	ret = kernel_create_event(&event, kchan);
	if (ret < 0) {
		if (ret == -EEXIST) {
			ret = LTTCOMM_KERN_EVENT_EXIST;
		} else {
			ret = LTTCOMM_KERN_ENABLE_FAIL;
		}
		goto end;
	}

	ret = LTTCOMM_OK;
end:
	return ret;
}

/*
 * Enable all kernel events of a channel of the kernel session.
 */
int event_kernel_enable_all(struct ltt_kernel_session *ksession,
		struct ltt_kernel_channel *kchan, int kernel_tracer_fd)
{
	int ret;

	ret = event_kernel_enable_all_tracepoints(ksession, kchan, kernel_tracer_fd);
	if (ret != LTTCOMM_OK) {
		goto end;
	}
	ret = event_kernel_enable_all_syscalls(ksession, kchan, kernel_tracer_fd);
end:
	return ret;
}

/*
 * ============================
 * UST : The Ultimate Frontier!
 * ============================
 */

/*
 * Enable all UST tracepoints for a channel from a UST session.
 */
int event_ust_enable_all_tracepoints(struct ltt_ust_session *usess, int domain,
		struct ltt_ust_channel *uchan)
{
	int ret, i;
	size_t size;
	struct cds_lfht_iter iter;
	struct ltt_ust_event *uevent = NULL;
	struct lttng_event *events = NULL;

	switch (domain) {
	case LTTNG_DOMAIN_UST:
	{
		/* Enable existing events */
		cds_lfht_for_each_entry(uchan->events, &iter, uevent, node) {
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
			ret = LTTCOMM_UST_LIST_FAIL;
			goto error;
		}

		for (i = 0; i < size; i++) {
			/*
			 * Check if event exist and if so, continue since it was enable
			 * previously.
			 */
			uevent = trace_ust_find_event_by_name(uchan->events,
					events[i].name);
			if (uevent != NULL) {
				ret = ust_app_enable_event_pid(usess, uchan, uevent,
						events[i].pid);
				if (ret < 0) {
					if (ret != -EEXIST) {
						ret = LTTCOMM_UST_ENABLE_FAIL;
						goto error;
					}
				}
				continue;
			}

			/* Create ust event */
			uevent = trace_ust_create_event(&events[i]);
			if (uevent == NULL) {
				ret = LTTCOMM_FATAL;
				goto error_destroy;
			}

			/* Create event for the specific PID */
			ret = ust_app_enable_event_pid(usess, uchan, uevent,
					events[i].pid);
			if (ret < 0) {
				if (ret == -EEXIST) {
					ret = LTTCOMM_UST_EVENT_EXIST;
					goto error;
				} else {
					ret = LTTCOMM_UST_ENABLE_FAIL;
					goto error_destroy;
				}
			}

			uevent->enabled = 1;
			/* Add ltt ust event to channel */
			rcu_read_lock();
			hashtable_add_unique(uchan->events, &uevent->node);
			rcu_read_unlock();
		}

		free(events);
		break;
	}
	case LTTNG_DOMAIN_UST_EXEC_NAME:
	case LTTNG_DOMAIN_UST_PID:
	case LTTNG_DOMAIN_UST_PID_FOLLOW_CHILDREN:
	default:
		ret = LTTCOMM_NOT_IMPLEMENTED;
		goto error;
	}

	return LTTCOMM_OK;

error_destroy:
	trace_ust_destroy_event(uevent);

error:
	free(events);
	return ret;
}

/*
 * Enable UST tracepoint event for a channel from a UST session.
 */
int event_ust_enable_tracepoint(struct ltt_ust_session *usess, int domain,
		struct ltt_ust_channel *uchan, struct lttng_event *event)
{
	int ret, to_create = 0;
	struct ltt_ust_event *uevent;

	uevent = trace_ust_find_event_by_name(uchan->events, event->name);
	if (uevent == NULL) {
		uevent = trace_ust_create_event(event);
		if (uevent == NULL) {
			ret = LTTCOMM_FATAL;
			goto error;
		}
		to_create = 1;
	}

	if (uevent->enabled) {
		/* It's already enabled so everything is OK */
		goto end;
	}

	switch (domain) {
	case LTTNG_DOMAIN_UST:
	{
		if (to_create) {
			/* Create event on all UST registered apps for session */
			ret = ust_app_create_event_glb(usess, uchan, uevent);
		} else {
			/* Enable event on all UST registered apps for session */
			ret = ust_app_enable_event_glb(usess, uchan, uevent);
		}

		if (ret < 0) {
			if (ret == -EEXIST) {
				ret = LTTCOMM_UST_EVENT_EXIST;
				goto end;
			} else {
				ret = LTTCOMM_UST_ENABLE_FAIL;
				goto error;
			}
		}
		break;
	}
	case LTTNG_DOMAIN_UST_EXEC_NAME:
	case LTTNG_DOMAIN_UST_PID:
	case LTTNG_DOMAIN_UST_PID_FOLLOW_CHILDREN:
	default:
		ret = LTTCOMM_NOT_IMPLEMENTED;
		goto end;
	}

	uevent->enabled = 1;
	/* Add ltt ust event to channel */
	if (to_create) {
		rcu_read_lock();
		hashtable_add_unique(uchan->events, &uevent->node);
		rcu_read_unlock();
	}

	DBG("Event UST %s %s in channel %s", uevent->attr.name,
			to_create ? "created" : "enabled", uchan->name);

end:
	return LTTCOMM_OK;

error:
	trace_ust_destroy_event(uevent);
	return ret;
}

/*
 * Disable UST tracepoint of a channel from a UST session.
 */
int event_ust_disable_tracepoint(struct ltt_ust_session *usess, int domain,
		struct ltt_ust_channel *uchan, char *event_name)
{
	int ret;
	struct ltt_ust_event *uevent;

	uevent = trace_ust_find_event_by_name(uchan->events, event_name);
	if (uevent == NULL) {
		ret = LTTCOMM_UST_EVENT_NOT_FOUND;
		goto error;
	}

	if (uevent->enabled == 0) {
		/* It's already enabled so everything is OK */
		ret = LTTCOMM_OK;
		goto end;
	}

	switch (domain) {
	case LTTNG_DOMAIN_UST:
		ret = ust_app_disable_event_glb(usess, uchan, uevent);
		if (ret < 0 && ret != -EEXIST) {
			ret = LTTCOMM_UST_DISABLE_FAIL;
			goto error;
		}
		break;
	case LTTNG_DOMAIN_UST_EXEC_NAME:
	case LTTNG_DOMAIN_UST_PID:
	case LTTNG_DOMAIN_UST_PID_FOLLOW_CHILDREN:
	default:
		ret = LTTCOMM_NOT_IMPLEMENTED;
		goto error;
	}

	uevent->enabled = 0;
	ret = LTTCOMM_OK;

end:
	DBG2("Event UST %s disabled in channel %s", uevent->attr.name,
			uchan->name);

error:
	return ret;
}

/*
 * Disable all UST tracepoints for a channel from a UST session.
 */
int event_ust_disable_all_tracepoints(struct ltt_ust_session *usess, int domain,
		struct ltt_ust_channel *uchan)
{
	int ret, i;
	size_t size;
	struct cds_lfht_iter iter;
	struct ltt_ust_event *uevent = NULL;
	struct lttng_event *events = NULL;

	switch (domain) {
	case LTTNG_DOMAIN_UST:
	{
		/* Disabling existing events */
		cds_lfht_for_each_entry(uchan->events, &iter, uevent, node) {
			if (uevent->enabled == 1) {
				ret = ust_app_disable_event_glb(usess, uchan, uevent);
				if (ret < 0) {
					continue;
				}
				uevent->enabled = 0;
			}
		}

		/* Get all UST available events */
		size = ust_app_list_events(&events);
		if (size < 0) {
			ret = LTTCOMM_UST_LIST_FAIL;
			goto error;
		}

		for (i = 0; i < size; i++) {
			uevent = trace_ust_find_event_by_name(uchan->events,
					events[i].name);
			if (uevent != NULL && uevent->enabled == 1) {
				ret = ust_app_disable_event_pid(usess, uchan, uevent,
						events[i].pid);
				if (ret < 0 && ret != -EEXIST) {
					ret = LTTCOMM_UST_DISABLE_FAIL;
					goto error;
				}
				uevent->enabled = 0;
				continue;
			}
		}

		free(events);
		break;
	}
	case LTTNG_DOMAIN_UST_EXEC_NAME:
	case LTTNG_DOMAIN_UST_PID:
	case LTTNG_DOMAIN_UST_PID_FOLLOW_CHILDREN:
	default:
		ret = LTTCOMM_NOT_IMPLEMENTED;
		goto error;
	}

	return LTTCOMM_OK;

error:
	free(events);
	return ret;
}
