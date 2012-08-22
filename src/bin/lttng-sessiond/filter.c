/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 * Copyright (C) 2012 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <urcu/list.h>

#include <common/error.h>
#include <common/sessiond-comm/sessiond-comm.h>

#include "filter.h"
#include "kernel.h"
#include "ust-app.h"
#include "trace-ust.h"

/*
 * Add UST context to event.
 */
static int add_ufilter_to_event(struct ltt_ust_session *usess, int domain,
		struct ltt_ust_channel *uchan, struct ltt_ust_event *uevent,
		struct lttng_filter_bytecode *bytecode)
{
	int ret;

	if (uevent->filter) {
		ret = -EEXIST;
		goto error;
	}
	/* Same layout. */
	uevent->filter = (struct lttng_ust_filter_bytecode *) bytecode;

	switch (domain) {
	case LTTNG_DOMAIN_UST:
		ret = ust_app_set_filter_event_glb(usess, uchan, uevent,
						bytecode);
		if (ret < 0) {
			goto error;
		}
		break;
	default:
		ret = -ENOSYS;
		goto error;
	}

	DBG("Filter UST added to event %s",uevent->attr.name);

	return 0;

error:
	free(bytecode);
	return ret;
}

/*
 * Add UST context to tracer.
 */
int filter_ust_set(struct ltt_ust_session *usess, int domain,
		struct lttng_filter_bytecode *bytecode, char *event_name,
		char *channel_name)
{
	int ret = LTTNG_OK, have_event = 0;
	struct lttng_ht_iter iter;
	struct lttng_ht *chan_ht;
	struct ltt_ust_channel *uchan = NULL;
	struct ltt_ust_event *uevent = NULL;

	/*
	 * Define which channel's hashtable to use from the domain or quit if
	 * unknown domain.
	 */
	switch (domain) {
	case LTTNG_DOMAIN_UST:
		chan_ht = usess->domain_global.channels;
		break;
#if 0
	case LTTNG_DOMAIN_UST_EXEC_NAME:
	case LTTNG_DOMAIN_UST_PID:
	case LTTNG_DOMAIN_UST_PID_FOLLOW_CHILDREN:
#endif
	default:
		ret = LTTNG_ERR_UND;
		goto error;
	}

	/* Do we have an event name */
	if (strlen(event_name) != 0) {
		have_event = 1;
	}

	/* Get UST channel if defined */
	if (strlen(channel_name) != 0) {
		uchan = trace_ust_find_channel_by_name(chan_ht, channel_name);
		if (uchan == NULL) {
			ret = LTTNG_ERR_UST_CHAN_NOT_FOUND;
			goto error;
		}
	}

	/* If UST channel specified and event name, get UST event ref */
	if (uchan && have_event) {
		uevent = trace_ust_find_event_by_name(uchan->events, event_name);
		if (uevent == NULL) {
			ret = LTTNG_ERR_UST_EVENT_NOT_FOUND;
			goto error;
		}
	}

	/* At this point, we have 4 possibilities */

	if (uchan && uevent) {				/* Add filter to event in channel */
		ret = add_ufilter_to_event(usess, domain, uchan, uevent,
					bytecode);
	} else if (uchan && !have_event) {	/* Add filter to channel */
		ERR("Cannot add filter to channel");
		ret = LTTNG_ERR_FATAL;	/* not supported. */
		goto error;
	} else if (!uchan && have_event) {	/* Add filter to event */
		/* Add context to event without having the channel name */
		cds_lfht_for_each_entry(chan_ht->ht, &iter.iter, uchan, node.node) {
			uevent = trace_ust_find_event_by_name(uchan->events, event_name);
			if (uevent != NULL) {
				ret = add_ufilter_to_event(usess, domain, uchan, uevent, bytecode);
				/*
				 * LTTng UST does not allowed the same event to be registered
				 * multiple time in different or the same channel. So, if we
				 * found our event, we stop.
				 */
				goto end;
			}
		}
		ret = LTTNG_ERR_UST_EVENT_NOT_FOUND;
		goto error;
	} else if (!uchan && !have_event) {	/* Add filter all events, all channels */
		ERR("Cannot add filter to channel");
		ret = LTTNG_ERR_FATAL;	/* not supported. */
		goto error;
	}

end:
	switch (ret) {
	case -EEXIST:
		ret = LTTNG_ERR_FILTER_EXIST;
		break;
	case -ENOMEM:
		ret = LTTNG_ERR_FATAL;
		break;
	case -EINVAL:
		ret = LTTNG_ERR_FILTER_INVAL;
		break;
	case -ENOSYS:
		ret = LTTNG_ERR_UNKNOWN_DOMAIN;
		break;
	default:
		ret = LTTNG_OK;
		break;
	}

error:
	return ret;
}
