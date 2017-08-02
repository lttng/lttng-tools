/*
 * Copyright (C)  2011 - David Goulet <david.goulet@polymtl.ca>
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <common/common.h>
#include <common/defaults.h>

#include "consumer.h"
#include "trace-kernel.h"
#include "lttng-sessiond.h"
#include "notification-thread-commands.h"

/*
 * Find the channel name for the given kernel session.
 */
struct ltt_kernel_channel *trace_kernel_get_channel_by_name(
		char *name, struct ltt_kernel_session *session)
{
	struct ltt_kernel_channel *chan;

	assert(session);
	assert(name);

	/*
	 * If we receive an empty string for channel name, it means the
	 * default channel name is requested.
	 */
	if (name[0] == '\0')
		name = DEFAULT_CHANNEL_NAME;

	DBG("Trying to find channel %s", name);

	cds_list_for_each_entry(chan, &session->channel_list.head, list) {
		if (strcmp(name, chan->channel->name) == 0) {
			DBG("Found channel by name %s", name);
			return chan;
		}
	}

	return NULL;
}

/*
 * Find the event for the given channel.
 */
struct ltt_kernel_event *trace_kernel_find_event(
		char *name, struct ltt_kernel_channel *channel,
		enum lttng_event_type type,
		struct lttng_filter_bytecode *filter)
{
	struct ltt_kernel_event *ev;
	int found = 0;

	assert(name);
	assert(channel);

	cds_list_for_each_entry(ev, &channel->events_list.head, list) {
		if (type != LTTNG_EVENT_ALL && ev->type != type) {
			continue;
		}
		if (strcmp(name, ev->event->name)) {
			continue;
		}
		if ((ev->filter && !filter) || (!ev->filter && filter)) {
			continue;
		}
		if (ev->filter && filter) {
			if (ev->filter->len != filter->len ||
					memcmp(ev->filter->data, filter->data,
						filter->len) != 0) {
				continue;
			}
		}
		found = 1;
		break;
	}
	if (found) {
		DBG("Found event %s for channel %s", name,
			channel->channel->name);
		return ev;
	} else {
		return NULL;
	}
}

/*
 * Find the event name for the given channel.
 */
struct ltt_kernel_event *trace_kernel_get_event_by_name(
		char *name, struct ltt_kernel_channel *channel,
		enum lttng_event_type type)
{
	struct ltt_kernel_event *ev;
	int found = 0;

	assert(name);
	assert(channel);

	cds_list_for_each_entry(ev, &channel->events_list.head, list) {
		if (type != LTTNG_EVENT_ALL && ev->type != type) {
			continue;
		}
		if (strcmp(name, ev->event->name)) {
			continue;
		}
		found = 1;
		break;
	}
	if (found) {
		DBG("Found event %s for channel %s", name,
			channel->channel->name);
		return ev;
	} else {
		return NULL;
	}
}

/*
 * Allocate and initialize a kernel session data structure.
 *
 * Return pointer to structure or NULL.
 */
struct ltt_kernel_session *trace_kernel_create_session(void)
{
	struct ltt_kernel_session *lks = NULL;

	/* Allocate a new ltt kernel session */
	lks = zmalloc(sizeof(struct ltt_kernel_session));
	if (lks == NULL) {
		PERROR("create kernel session zmalloc");
		goto alloc_error;
	}

	/* Init data structure */
	lks->fd = -1;
	lks->metadata_stream_fd = -1;
	lks->channel_count = 0;
	lks->stream_count_global = 0;
	lks->metadata = NULL;
	CDS_INIT_LIST_HEAD(&lks->channel_list.head);

	lks->consumer = consumer_create_output(CONSUMER_DST_LOCAL);
	if (lks->consumer == NULL) {
		goto error;
	}

	return lks;

error:
	free(lks);

alloc_error:
	return NULL;
}

/*
 * Allocate and initialize a kernel channel data structure.
 *
 * Return pointer to structure or NULL.
 */
struct ltt_kernel_channel *trace_kernel_create_channel(
		struct lttng_channel *chan)
{
	struct ltt_kernel_channel *lkc;
	struct lttng_channel_extended *extended = NULL;

	assert(chan);

	lkc = zmalloc(sizeof(struct ltt_kernel_channel));
	if (lkc == NULL) {
		PERROR("ltt_kernel_channel zmalloc");
		goto error;
	}

	lkc->channel = zmalloc(sizeof(struct lttng_channel));
	if (lkc->channel == NULL) {
		PERROR("lttng_channel zmalloc");
		goto error;
	}

	extended = zmalloc(sizeof(struct lttng_channel_extended));
	if (!extended) {
		PERROR("lttng_channel_channel zmalloc");
		goto error;
	}
	memcpy(lkc->channel, chan, sizeof(struct lttng_channel));
	memcpy(extended, chan->attr.extended.ptr, sizeof(struct lttng_channel_extended));
	lkc->channel->attr.extended.ptr = extended;
	extended = NULL;

	/*
	 * If we receive an empty string for channel name, it means the
	 * default channel name is requested.
	 */
	if (chan->name[0] == '\0') {
		strncpy(lkc->channel->name, DEFAULT_CHANNEL_NAME,
			sizeof(lkc->channel->name));
	}
	lkc->channel->name[LTTNG_KERNEL_SYM_NAME_LEN - 1] = '\0';

	lkc->fd = -1;
	lkc->stream_count = 0;
	lkc->event_count = 0;
	lkc->enabled = 1;
	lkc->published_to_notification_thread = false;
	/* Init linked list */
	CDS_INIT_LIST_HEAD(&lkc->events_list.head);
	CDS_INIT_LIST_HEAD(&lkc->stream_list.head);
	CDS_INIT_LIST_HEAD(&lkc->ctx_list);

	return lkc;

error:
	if (lkc) {
		free(lkc->channel);
	}
	free(extended);
	free(lkc);
	return NULL;
}

/*
 * Allocate and init a kernel context object.
 *
 * Return the allocated object or NULL on error.
 */
struct ltt_kernel_context *trace_kernel_create_context(
		struct lttng_kernel_context *ctx)
{
	struct ltt_kernel_context *kctx;

	kctx = zmalloc(sizeof(*kctx));
	if (!kctx) {
		PERROR("zmalloc kernel context");
		goto error;
	}

	if (ctx) {
		memcpy(&kctx->ctx, ctx, sizeof(kctx->ctx));
	}
error:
	return kctx;
}

/*
 * Allocate and init a kernel context object from an existing kernel context
 * object.
 *
 * Return the allocated object or NULL on error.
 */
struct ltt_kernel_context *trace_kernel_copy_context(
		struct ltt_kernel_context *kctx)
{
	struct ltt_kernel_context *kctx_copy;

	assert(kctx);
	kctx_copy = zmalloc(sizeof(*kctx_copy));
	if (!kctx_copy) {
		PERROR("zmalloc ltt_kernel_context");
		goto error;
	}

	memcpy(kctx_copy, kctx, sizeof(*kctx_copy));
	memset(&kctx_copy->list, 0, sizeof(kctx_copy->list));

error:
	return kctx_copy;
}

/*
 * Allocate and initialize a kernel event. Set name and event type.
 * We own filter_expression, and filter.
 *
 * Return pointer to structure or NULL.
 */
struct ltt_kernel_event *trace_kernel_create_event(struct lttng_event *ev,
		char *filter_expression, struct lttng_filter_bytecode *filter)
{
	struct ltt_kernel_event *lke;
	struct lttng_kernel_event *attr;

	assert(ev);

	lke = zmalloc(sizeof(struct ltt_kernel_event));
	attr = zmalloc(sizeof(struct lttng_kernel_event));
	if (lke == NULL || attr == NULL) {
		PERROR("kernel event zmalloc");
		goto error;
	}

	switch (ev->type) {
	case LTTNG_EVENT_PROBE:
		attr->instrumentation = LTTNG_KERNEL_KPROBE;
		attr->u.kprobe.addr = ev->attr.probe.addr;
		attr->u.kprobe.offset = ev->attr.probe.offset;
		strncpy(attr->u.kprobe.symbol_name,
				ev->attr.probe.symbol_name, LTTNG_KERNEL_SYM_NAME_LEN);
		attr->u.kprobe.symbol_name[LTTNG_KERNEL_SYM_NAME_LEN - 1] = '\0';
		break;
	case LTTNG_EVENT_FUNCTION:
		attr->instrumentation = LTTNG_KERNEL_KRETPROBE;
		attr->u.kretprobe.addr = ev->attr.probe.addr;
		attr->u.kretprobe.offset = ev->attr.probe.offset;
		strncpy(attr->u.kretprobe.symbol_name,
				ev->attr.probe.symbol_name, LTTNG_KERNEL_SYM_NAME_LEN);
		attr->u.kretprobe.symbol_name[LTTNG_KERNEL_SYM_NAME_LEN - 1] = '\0';
		break;
	case LTTNG_EVENT_FUNCTION_ENTRY:
		attr->instrumentation = LTTNG_KERNEL_FUNCTION;
		strncpy(attr->u.ftrace.symbol_name,
				ev->attr.ftrace.symbol_name, LTTNG_KERNEL_SYM_NAME_LEN);
		attr->u.ftrace.symbol_name[LTTNG_KERNEL_SYM_NAME_LEN - 1] = '\0';
		break;
	case LTTNG_EVENT_TRACEPOINT:
		attr->instrumentation = LTTNG_KERNEL_TRACEPOINT;
		break;
	case LTTNG_EVENT_SYSCALL:
		attr->instrumentation = LTTNG_KERNEL_SYSCALL;
		break;
	case LTTNG_EVENT_ALL:
		attr->instrumentation = LTTNG_KERNEL_ALL;
		break;
	default:
		ERR("Unknown kernel instrumentation type (%d)", ev->type);
		goto error;
	}

	/* Copy event name */
	strncpy(attr->name, ev->name, LTTNG_KERNEL_SYM_NAME_LEN);
	attr->name[LTTNG_KERNEL_SYM_NAME_LEN - 1] = '\0';

	/* Setting up a kernel event */
	lke->fd = -1;
	lke->event = attr;
	lke->enabled = 1;
	lke->filter_expression = filter_expression;
	lke->filter = filter;

	return lke;

error:
	free(filter_expression);
	free(filter);
	free(lke);
	free(attr);
	return NULL;
}

/*
 * Allocate and initialize a kernel metadata.
 *
 * Return pointer to structure or NULL.
 */
struct ltt_kernel_metadata *trace_kernel_create_metadata(void)
{
	struct ltt_kernel_metadata *lkm;
	struct lttng_channel *chan;

	lkm = zmalloc(sizeof(struct ltt_kernel_metadata));
	chan = zmalloc(sizeof(struct lttng_channel));
	if (lkm == NULL || chan == NULL) {
		PERROR("kernel metadata zmalloc");
		goto error;
	}

	/* Set default attributes */
	chan->attr.overwrite = DEFAULT_CHANNEL_OVERWRITE;
	chan->attr.subbuf_size = default_get_metadata_subbuf_size();
	chan->attr.num_subbuf = DEFAULT_METADATA_SUBBUF_NUM;
	chan->attr.switch_timer_interval = DEFAULT_KERNEL_CHANNEL_SWITCH_TIMER;
	chan->attr.read_timer_interval = DEFAULT_KERNEL_CHANNEL_READ_TIMER;
	chan->attr.output = DEFAULT_KERNEL_CHANNEL_OUTPUT;

	/* Init metadata */
	lkm->fd = -1;
	lkm->conf = chan;

	return lkm;

error:
	free(lkm);
	free(chan);
	return NULL;
}

/*
 * Allocate and initialize a kernel stream. The stream is set to ACTIVE_FD by
 * default.
 *
 * Return pointer to structure or NULL.
 */
struct ltt_kernel_stream *trace_kernel_create_stream(const char *name,
		unsigned int count)
{
	int ret;
	struct ltt_kernel_stream *lks;

	assert(name);

	lks = zmalloc(sizeof(struct ltt_kernel_stream));
	if (lks == NULL) {
		PERROR("kernel stream zmalloc");
		goto error;
	}

	/* Set name */
	ret = snprintf(lks->name, sizeof(lks->name), "%s_%u", name, count);
	if (ret < 0) {
		PERROR("snprintf stream name");
		goto error;
	}
	lks->name[sizeof(lks->name) - 1] = '\0';

	/* Init stream */
	lks->fd = -1;
	lks->state = 0;
	lks->cpu = count;

	return lks;

error:
	return NULL;
}

/*
 * Cleanup kernel stream structure.
 */
void trace_kernel_destroy_stream(struct ltt_kernel_stream *stream)
{
	assert(stream);

	DBG("[trace] Closing stream fd %d", stream->fd);
	/* Close kernel fd */
	if (stream->fd >= 0) {
		int ret;

		ret = close(stream->fd);
		if (ret) {
			PERROR("close");
		}
	}
	/* Remove from stream list */
	cds_list_del(&stream->list);

	free(stream);
}

/*
 * Cleanup kernel event structure.
 */
void trace_kernel_destroy_event(struct ltt_kernel_event *event)
{
	assert(event);

	if (event->fd >= 0) {
		int ret;

		DBG("[trace] Closing event fd %d", event->fd);
		/* Close kernel fd */
		ret = close(event->fd);
		if (ret) {
			PERROR("close");
		}
	} else {
		DBG("[trace] Tearing down event (no associated fd)");
	}

	/* Remove from event list */
	cds_list_del(&event->list);

	free(event->filter_expression);
	free(event->filter);

	free(event->event);
	free(event);
}

/*
 * Cleanup kernel context structure.
 */
void trace_kernel_destroy_context(struct ltt_kernel_context *ctx)
{
	assert(ctx);

	if (ctx->in_list) {
		cds_list_del(&ctx->list);
	}
	free(ctx);
}

/*
 * Cleanup kernel channel structure.
 */
void trace_kernel_destroy_channel(struct ltt_kernel_channel *channel)
{
	struct ltt_kernel_stream *stream, *stmp;
	struct ltt_kernel_event *event, *etmp;
	struct ltt_kernel_context *ctx, *ctmp;
	int ret;
	enum lttng_error_code status;

	assert(channel);

	DBG("[trace] Closing channel fd %d", channel->fd);
	/* Close kernel fd */
	if (channel->fd >= 0) {
		ret = close(channel->fd);
		if (ret) {
			PERROR("close");
		}
	}

	/* For each stream in the channel list */
	cds_list_for_each_entry_safe(stream, stmp, &channel->stream_list.head, list) {
		trace_kernel_destroy_stream(stream);
	}

	/* For each event in the channel list */
	cds_list_for_each_entry_safe(event, etmp, &channel->events_list.head, list) {
		trace_kernel_destroy_event(event);
	}

	/* For each context in the channel list */
	cds_list_for_each_entry_safe(ctx, ctmp, &channel->ctx_list, list) {
		trace_kernel_destroy_context(ctx);
	}

	/* Remove from channel list */
	cds_list_del(&channel->list);

	if (notification_thread_handle
			&& channel->published_to_notification_thread) {
		status = notification_thread_command_remove_channel(
				notification_thread_handle,
				channel->fd, LTTNG_DOMAIN_KERNEL);
		assert(status == LTTNG_OK);
	}
	free(channel->channel->attr.extended.ptr);
	free(channel->channel);
	free(channel);
}

/*
 * Cleanup kernel metadata structure.
 */
void trace_kernel_destroy_metadata(struct ltt_kernel_metadata *metadata)
{
	assert(metadata);

	DBG("[trace] Closing metadata fd %d", metadata->fd);
	/* Close kernel fd */
	if (metadata->fd >= 0) {
		int ret;

		ret = close(metadata->fd);
		if (ret) {
			PERROR("close");
		}
	}

	free(metadata->conf);
	free(metadata);
}

/*
 * Cleanup kernel session structure
 *
 * Should *NOT* be called with RCU read-side lock held.
 */
void trace_kernel_destroy_session(struct ltt_kernel_session *session)
{
	struct ltt_kernel_channel *channel, *ctmp;
	int ret;

	assert(session);

	DBG("[trace] Closing session fd %d", session->fd);
	/* Close kernel fds */
	if (session->fd >= 0) {
		ret = close(session->fd);
		if (ret) {
			PERROR("close");
		}
	}

	if (session->metadata_stream_fd >= 0) {
		DBG("[trace] Closing metadata stream fd %d", session->metadata_stream_fd);
		ret = close(session->metadata_stream_fd);
		if (ret) {
			PERROR("close");
		}
	}

	if (session->metadata != NULL) {
		trace_kernel_destroy_metadata(session->metadata);
	}

	cds_list_for_each_entry_safe(channel, ctmp, &session->channel_list.head, list) {
		trace_kernel_destroy_channel(channel);
	}

	/* Wipe consumer output object */
	consumer_output_put(session->consumer);

	free(session);
}
