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

#include <errno.h>
#include <urcu/list.h>
#include <string.h>

#include <lttng/lttng.h>
#include <lttng-sessiond-comm.h>
#include <lttngerr.h>

#include "channel.h"
#include "event.h"
#include "hashtable.h"
#include "kernel.h"
#include "ust-ctl.h"

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
	struct lttng_event *event_list;

	/* For each event in the kernel session */
	cds_list_for_each_entry(kevent, &kchan->events_list.head, list) {
		ret = kernel_enable_event(kevent);
		if (ret < 0) {
			/* Enable failed but still continue */
			continue;
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
 * Enable UST tracepoint event for a channel from a UST session.
 */
#ifdef DISABLE
int event_ust_enable_tracepoint(struct ltt_ust_session *usess,
		struct ltt_ust_channel *uchan, struct ltt_ust_event *uevent)
{
	int ret;
	struct lttng_ust_event ltt_uevent;
	struct object_data *obj_event;

	strncpy(ltt_uevent.name, uevent->attr.name, sizeof(ltt_uevent.name));
	ltt_uevent.name[sizeof(ltt_uevent.name) - 1] = '\0';
	/* TODO: adjust to other instrumentation types */
	ltt_uevent.instrumentation = LTTNG_UST_TRACEPOINT;

	ret = ustctl_create_event(app->key.sock, &ltt_uevent,
			uchan->obj, &obj_event);
	if (ret < 0) {
		DBG("Error ustctl create event %s for app pid: %d, sock: %d ret %d",
				uevent->attr.name, app->key.pid, app->key.sock, ret);
		goto next;
	}

	uevent->obj = obj_event;
	uevent->handle = obj_event->handle;
	uevent->enabled = 1;
	ret = LTTCOMM_OK;
end:
	return ret;
}
#endif

#ifdef DISABLE
int event_ust_disable_tracepoint(struct ltt_ust_session *ustsession,
		struct ltt_ust_channel *ustchan, char *event_name)
{
	int ret;
	struct ltt_ust_event *ustevent;

	ustevent = trace_ust_find_event_by_name(ustchan->events, event_name);
	if (ustevent == NULL) {
		ret = LTTCOMM_NO_EVENT;
		goto end;
	}
	//ret = ustctl_disable(ustsession->sock, ustevent->obj);
	if (ret < 0) {
		ret = LTTCOMM_UST_ENABLE_FAIL;
		goto end;
	}
	ustevent->enabled = 0;
	ret = LTTCOMM_OK;
end:
	return ret;
}
#endif
