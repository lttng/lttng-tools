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

#ifdef CONFIG_LTTNG_TOOLS_HAVE_UST
#include <ust/lttng-ust-ctl.h>
#include <ust/lttng-ust-abi.h>
#else
#include "lttng-ust-ctl.h"
#include "lttng-ust-abi.h"
#endif

#include "context.h"
#include "hashtable.h"
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

/*
 * UST support.
 */

/*
 * Add UST context to an event of a specific channel.
 */
#ifdef DISABLE
static int add_ustctx_to_event(struct ltt_ust_session *ustsession,
		struct lttng_ust_context *ustctx,
		struct ltt_ust_channel *ustchan, char *event_name)
{
	int ret, found = 0;
	struct ltt_ust_event *ustevent;
	struct object_data *context_data;	/* FIXME: currently a memleak */

	DBG("Add UST context to event %s", event_name);

	ustevent = trace_ust_find_event_by_name(ustchan->events, event_name);
	if (ustevent != NULL) {
		ret = ustctl_add_context(ustsession->sock, ustctx,
			ustevent->obj, &context_data);
		if (ret < 0) {
			goto error;
		}
		found = 1;
	}

	ret = found;

error:
	return ret;
}
#endif

/*
 * Add UST context to all channel.
 *
 * If event_name is specified, add context to event instead.
 */
static int add_ustctx_all_channels(struct ltt_ust_session *ustsession,
		struct lttng_ust_context *ustctx, char *event_name,
		struct cds_lfht *channels)
{
#ifdef DISABLE
	int ret, no_event = 0, found = 0;
	struct ltt_ust_channel *ustchan;
	struct object_data *context_data;	/* FIXME: currently a memleak */

	if (strlen(event_name) == 0) {
		no_event = 1;
	}

	DBG("Adding ust context to all channels (event: %s)", event_name);

	struct cds_lfht_node *node;
	struct cds_lfht_iter iter;

	rcu_read_lock();
	hashtable_get_first(channels, &iter);
	while ((node = hashtable_iter_get_node(&iter)) != NULL) {
		ustchan = caa_container_of(node, struct ltt_ust_channel, node);
		if (no_event) {
			//ret = ustctl_add_context(ustsession->sock,
			//		ustctx, ustchan->obj, &context_data);
			if (ret < 0) {
				ret = LTTCOMM_UST_CONTEXT_FAIL;
				goto error;
			}
		} else {
			ret = add_ustctx_to_event(ustsession, ustctx, ustchan, event_name);
			if (ret < 0) {
				ret = LTTCOMM_UST_CONTEXT_FAIL;
				goto error;
			} else if (ret == 1) {
				/* Event found and context added */
				found = 1;
				break;
			}
		}
		hashtable_get_next(channels, &iter);
	}
	rcu_read_unlock();

	if (!found && !no_event) {
		ret = LTTCOMM_NO_EVENT;
		goto error;
	}

	ret = LTTCOMM_OK;

error:
	return ret;
#endif
	return 0;
}

/*
 * Add UST context to a specific channel.
 *
 * If event_name is specified, add context to that event.
 */
static int add_ustctx_to_channel(struct ltt_ust_session *ustsession,
		struct lttng_ust_context *ustctx,
		struct ltt_ust_channel *ustchan, char *event_name)
{
#ifdef DISABLE
	int ret, no_event = 0, found = 0;
	struct object_data *context_data;	/* FIXME: currently a memleak */

	if (strlen(event_name) == 0) {
		no_event = 1;
	}

	DBG("Add UST context to channel '%s', event '%s'",
			ustchan->name, event_name);

	if (no_event) {
		//ret = ustctl_add_context(ustsession->sock, ustctx,
		//	ustchan->obj, &context_data);
		if (ret < 0) {
			ret = LTTCOMM_UST_CONTEXT_FAIL;
			goto error;
		}
	} else {
		ret = add_ustctx_to_event(ustsession, ustctx, ustchan, event_name);
		if (ret < 0) {
			ret = LTTCOMM_UST_CONTEXT_FAIL;
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
#endif
	return 0;
}

/*
 * Add UST context to tracer.
 */
int context_ust_add(struct ltt_ust_session *ustsession,
		struct lttng_event_context *ctx, char *event_name,
		char *channel_name, int domain)
{
	int ret;
	struct cds_lfht *chan_ht = NULL;
	struct ltt_ust_channel *ustchan;
	struct lttng_ust_context ustctx;

	/* Setup UST context structure */
	ustctx.ctx = ctx->ctx;

	switch (domain) {
		case LTTNG_DOMAIN_UST:
			chan_ht = ustsession->domain_global.channels;
			break;
	}

	if (strlen(channel_name) == 0) {
		ret = add_ustctx_all_channels(ustsession, &ustctx, event_name, chan_ht);
		if (ret != LTTCOMM_OK) {
			goto error;
		}
	} else {
		/* Get UST channel */
		ustchan = trace_ust_find_channel_by_name(chan_ht, channel_name);
		if (ustchan == NULL) {
			ret = LTTCOMM_UST_CHAN_NOT_FOUND;
			goto error;
		}

		ret = add_ustctx_to_channel(ustsession, &ustctx, ustchan, event_name);
		if (ret != LTTCOMM_OK) {
			goto error;
		}
	}

	ret = LTTCOMM_OK;

error:
	return ret;
}
