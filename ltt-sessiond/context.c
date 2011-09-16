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
#include "kernel-ctl.h"

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
