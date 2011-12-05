/*
 * Copyright (C)  2011 - David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; only version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <urcu/list.h>

#include <lttng-sessiond-comm.h>
#include <lttngerr.h>

#include "context.h"
#include "hashtable.h"
#include "kernel.h"
#include "ust-app.h"
#include "trace-ust.h"

/*
 * Add kernel context to an event of a specific channel.
 */
static int add_kctx_to_event(struct lttng_kernel_context *kctx,
		struct ltt_kernel_channel *kchan, char *event_name)
{
	int ret, found = 0;
	struct ltt_kernel_event *kevent;

	DBG("Add kernel context to event %s", event_name);

	kevent = trace_kernel_get_event_by_name(event_name, kchan);
	if (kevent != NULL) {
		ret = kernel_add_event_context(kevent, kctx);
		if (ret < 0) {
			goto error;
		}
		found = 1;
	}

	ret = found;

error:
	return ret;
}

/*
 * Add kernel context to all channel.
 *
 * If event_name is specified, add context to event instead.
 */
static int add_kctx_all_channels(struct ltt_kernel_session *ksession,
		struct lttng_kernel_context *kctx, char *event_name)
{
	int ret, no_event = 0, found = 0;
	struct ltt_kernel_channel *kchan;

	if (strlen(event_name) == 0) {
		no_event = 1;
	}

	DBG("Adding kernel context to all channels (event: %s)", event_name);

	/* Go over all channels */
	cds_list_for_each_entry(kchan, &ksession->channel_list.head, list) {
		if (no_event) {
			ret = kernel_add_channel_context(kchan, kctx);
			if (ret < 0) {
				ret = LTTCOMM_KERN_CONTEXT_FAIL;
				goto error;
			}
		} else {
			ret = add_kctx_to_event(kctx, kchan, event_name);
			if (ret < 0) {
				ret = LTTCOMM_KERN_CONTEXT_FAIL;
				goto error;
			} else if (ret == 1) {
				/* Event found and context added */
				found = 1;
				break;
			}
		}
	}

	if (!found && !no_event) {
		ret = LTTCOMM_NO_EVENT;
		goto error;
	}

	ret = LTTCOMM_OK;

error:
	return ret;
}

/*
 * Add kernel context to a specific channel.
 *
 * If event_name is specified, add context to that event.
 */
static int add_kctx_to_channel(struct lttng_kernel_context *kctx,
		struct ltt_kernel_channel *kchan, char *event_name)
{
	int ret, no_event = 0, found = 0;

	if (strlen(event_name) == 0) {
		no_event = 1;
	}

	DBG("Add kernel context to channel '%s', event '%s'",
			kchan->channel->name, event_name);

	if (no_event) {
		ret = kernel_add_channel_context(kchan, kctx);
		if (ret < 0) {
			ret = LTTCOMM_KERN_CONTEXT_FAIL;
			goto error;
		}
	} else {
		ret = add_kctx_to_event(kctx, kchan, event_name);
		if (ret < 0) {
			ret = LTTCOMM_KERN_CONTEXT_FAIL;
			goto error;
		} else if (ret == 1) {
			/* Event found and context added */
			found = 1;
		}
	}

	if (!found && !no_event) {
		ret = LTTCOMM_NO_EVENT;
		goto error;
	}

	ret = LTTCOMM_OK;

error:
	return ret;
}

/*
 * Add kernel context to tracer.
 */
int context_kernel_add(struct ltt_kernel_session *ksession,
		struct lttng_event_context *ctx, char *event_name,
		char *channel_name)
{
	int ret;
	struct ltt_kernel_channel *kchan;
	struct lttng_kernel_context kctx;

	/* Setup kernel context structure */
	kctx.ctx = ctx->ctx;
	kctx.u.perf_counter.type = ctx->u.perf_counter.type;
	kctx.u.perf_counter.config = ctx->u.perf_counter.config;
	strncpy(kctx.u.perf_counter.name, ctx->u.perf_counter.name,
			LTTNG_SYMBOL_NAME_LEN);
	kctx.u.perf_counter.name[LTTNG_SYMBOL_NAME_LEN - 1] = '\0';

	if (strlen(channel_name) == 0) {
		ret = add_kctx_all_channels(ksession, &kctx, event_name);
		if (ret != LTTCOMM_OK) {
			goto error;
		}
	} else {
		/* Get kernel channel */
		kchan = trace_kernel_get_channel_by_name(channel_name, ksession);
		if (kchan == NULL) {
			ret = LTTCOMM_KERN_CHAN_NOT_FOUND;
			goto error;
		}

		ret = add_kctx_to_channel(&kctx, kchan, event_name);
		if (ret != LTTCOMM_OK) {
			goto error;
		}
	}

	ret = LTTCOMM_OK;

error:
	return ret;
}

/*
 * Add UST context to tracer.
 */
int context_ust_add(struct ltt_ust_session *usess, int domain,
		struct lttng_event_context *ctx, char *event_name,
		char *channel_name)
{
	int ret = LTTCOMM_OK, have_event = 0;
	struct cds_lfht_iter iter, uiter;
	struct cds_lfht *chan_ht;
	struct ltt_ust_channel *uchan = NULL;
	struct ltt_ust_event *uevent = NULL;
	struct ltt_ust_context *uctx;

	switch (domain) {
	case LTTNG_DOMAIN_UST:
		chan_ht = usess->domain_global.channels;
		break;
	case LTTNG_DOMAIN_UST_EXEC_NAME:
	case LTTNG_DOMAIN_UST_PID:
	case LTTNG_DOMAIN_UST_PID_FOLLOW_CHILDREN:
	default:
		ret = LTTCOMM_NOT_IMPLEMENTED;
		goto error;
	}

	if (strlen(event_name) != 0) {
		have_event = 1;
	}

	/* Get UST channel if defined */
	if (strlen(channel_name) != 0) {
		uchan = trace_ust_find_channel_by_name(chan_ht, channel_name);
		if (uchan == NULL) {
			ret = LTTCOMM_UST_CHAN_NOT_FOUND;
			goto error;
		}
	}

	/* If UST channel specified and event name, get UST event ref */
	if (uchan && have_event) {
		uevent = trace_ust_find_event_by_name(uchan->events, event_name);
		if (uevent == NULL) {
			ret = LTTCOMM_UST_EVENT_NOT_FOUND;
			goto error;
		}
	}

	/* Create ltt UST context */
	uctx = trace_ust_create_context(ctx);
	if (uctx == NULL) {
		ret = LTTCOMM_FATAL;
		goto error;
	}

	/* At this point, we have 4 possibilities */

	if (uchan && uevent) {			/* Add ctx to event in channel */
		ret = ust_app_add_ctx_event_glb(usess, uchan, uevent, uctx);
	} else if (uchan && !have_event) {	/* Add ctx to channel */
		ret = ust_app_add_ctx_channel_glb(usess, uchan, uctx);
	} else if (!uchan && have_event) {	/* Add ctx to event */
		cds_lfht_for_each_entry(chan_ht, &iter, uchan, node) {
			uevent = trace_ust_find_event_by_name(uchan->events, event_name);
			if (uevent != NULL) {
				ret = ust_app_add_ctx_event_glb(usess, uchan, uevent, uctx);
				/*
				 * LTTng UST does not allowed the same event to be registered
				 * multiple time in different or the same channel. So, if we
				 * found our event in the first place, no need to continue.
				 */
				goto end;
			}
		}
		ret = LTTCOMM_UST_EVENT_NOT_FOUND;
		goto error_free_ctx;
	} else if (!uchan && !have_event) {	/* Add ctx to all events, all channels */
		cds_lfht_for_each_entry(chan_ht, &iter, uchan, node) {
			ret = ust_app_add_ctx_channel_glb(usess, uchan, uctx);
			if (ret < 0) {
				/* Add failed so uctx was not added. We can keep it. */
				continue;
			}
			cds_lfht_for_each_entry(uchan->events, &uiter, uevent, node) {
				ret = ust_app_add_ctx_event_glb(usess, uchan, uevent, uctx);
				if (ret < 0) {
					/* Add failed so uctx was not added. We can keep it. */
					continue;
				}
				/* Create ltt UST context */
				uctx = trace_ust_create_context(ctx);
				if (uctx == NULL) {
					ret = LTTCOMM_FATAL;
					goto error;
				}
			}
			/* Create ltt UST context */
			uctx = trace_ust_create_context(ctx);
			if (uctx == NULL) {
				ret = LTTCOMM_FATAL;
				goto error;
			}
		}
	}

end:
	switch (ret) {
	case -EEXIST:
		ret = LTTCOMM_UST_CONTEXT_EXIST;
		goto error_free_ctx;
	case -ENOMEM:
		ret = LTTCOMM_FATAL;
		goto error_free_ctx;
	}

	return LTTCOMM_OK;

error_free_ctx:
	free(uctx);
error:
	return ret;
}
