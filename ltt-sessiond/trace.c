/*
 * Copyright (C)  2011 - David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <urcu/list.h>

#include "lttngerr.h"
#include "trace.h"

/*
 *  get_kernel_channel_by_name
 *
 *  Find the channel name for the given kernel session.
 */
struct ltt_kernel_channel *get_kernel_channel_by_name(
		char *name, struct ltt_kernel_session *session)
{
	struct ltt_kernel_channel *chan;

	if (session == NULL) {
		ERR("Undefine session");
		goto error;
	}

	cds_list_for_each_entry(chan, &session->channel_list.head, list) {
		if (strcmp(name, chan->channel->name) == 0) {
			DBG("Found channel by name %s", name);
			return chan;
		}
	}

error:
	return NULL;
}

/*
 *  get_kernel_event_by_name
 *
 *  Find the event name for the given channel.
 */
struct ltt_kernel_event *get_kernel_event_by_name(
		char *name, struct ltt_kernel_channel *channel)
{
	struct ltt_kernel_event *ev;

	if (channel == NULL) {
		ERR("Undefine channel");
		goto error;
	}

	cds_list_for_each_entry(ev, &channel->events_list.head, list) {
		if (strcmp(name, ev->event->name) == 0) {
			DBG("Found event by name %s for channel %s", name,
					channel->channel->name);
			return ev;
		}
	}

error:
	return NULL;
}

/*
 *  trace_create_kernel_session
 *
 *  Allocate and initialize a kernel session data structure.
 *
 *  Return pointer to structure or NULL.
 */
struct ltt_kernel_session *trace_create_kernel_session(void)
{
	struct ltt_kernel_session *lks;

	/* Allocate a new ltt kernel session */
	lks = malloc(sizeof(struct ltt_kernel_session));
	if (lks == NULL) {
		perror("create kernel session malloc");
		goto error;
	}

	/* Init data structure */
	lks->fd = 0;
	lks->metadata_stream_fd = 0;
	lks->channel_count = 0;
	lks->stream_count_global = 0;
	lks->metadata = NULL;
	CDS_INIT_LIST_HEAD(&lks->channel_list.head);

	return lks;

error:
	return NULL;
}

/*
 *  trace_create_kernel_channel
 *
 *  Allocate and initialize a kernel channel data structure.
 *
 *  Return pointer to structure or NULL.
 */
struct ltt_kernel_channel *trace_create_kernel_channel(struct lttng_channel *chan, char *path)
{
	int ret;
	struct ltt_kernel_channel *lkc;

	lkc = malloc(sizeof(struct ltt_kernel_channel));
	if (lkc == NULL) {
		perror("ltt_kernel_channel malloc");
		goto error;
	}

	lkc->channel = malloc(sizeof(struct lttng_channel));
	if (lkc->channel == NULL) {
		perror("lttng_channel malloc");
		goto error;
	}
	memcpy(lkc->channel, chan, sizeof(struct lttng_channel));

	lkc->fd = 0;
	lkc->stream_count = 0;
	lkc->enabled = 1;
	/* Init linked list */
	CDS_INIT_LIST_HEAD(&lkc->events_list.head);
	CDS_INIT_LIST_HEAD(&lkc->stream_list.head);
	/* Set default trace output path */
	ret = asprintf(&lkc->pathname, "%s", path);
	if (ret < 0) {
		perror("asprintf kernel create channel");
		goto error;
	}

	return lkc;

error:
	return NULL;
}

/*
 *  trace_create_kernel_event
 *
 *  Allocate and initialize a kernel event. Set name and event type.
 *
 *  Return pointer to structure or NULL.
 */
struct ltt_kernel_event *trace_create_kernel_event(struct lttng_event *ev)
{
	struct ltt_kernel_event *lke;
	struct lttng_kernel_event *attr;

	lke = malloc(sizeof(struct ltt_kernel_event));
	attr = malloc(sizeof(struct lttng_kernel_event));
	if (lke == NULL || attr == NULL) {
		perror("kernel event malloc");
		goto error;
	}

	switch (ev->type) {
	case LTTNG_EVENT_PROBE:
		attr->instrumentation = LTTNG_KERNEL_KPROBE;
		attr->u.kprobe.addr = ev->attr.probe.addr;
		attr->u.kprobe.offset = ev->attr.probe.offset;
		strncpy(attr->u.kprobe.symbol_name,
				ev->attr.probe.symbol_name, LTTNG_SYM_NAME_LEN);
		break;
	case LTTNG_EVENT_FUNCTION:
		attr->instrumentation = LTTNG_KERNEL_FUNCTION;
		strncpy(attr->u.ftrace.symbol_name,
				ev->attr.ftrace.symbol_name, LTTNG_SYM_NAME_LEN);
		break;
	case LTTNG_EVENT_TRACEPOINT:
		attr->instrumentation = LTTNG_KERNEL_TRACEPOINT;
		break;
	default:
		ERR("Unknown kernel instrumentation type (%d)", ev->type);
		goto error;
	}

	/* Copy event name */
	strncpy(attr->name, ev->name, LTTNG_SYM_NAME_LEN);

	/* Setting up a kernel event */
	lke->fd = 0;
	lke->event = attr;
	lke->enabled = 1;

	return lke;

error:
	return NULL;
}

/*
 *  trace_create_kernel_metadata
 *
 *  Allocate and initialize a kernel metadata.
 *
 *  Return pointer to structure or NULL.
 */
struct ltt_kernel_metadata *trace_create_kernel_metadata(char *path)
{
	int ret;
	struct ltt_kernel_metadata *lkm;
	struct lttng_channel *chan;

	lkm = malloc(sizeof(struct ltt_kernel_metadata));
	chan = malloc(sizeof(struct lttng_channel));
	if (lkm == NULL || chan == NULL) {
		perror("kernel metadata malloc");
		goto error;
	}

	/* Set default attributes */
	chan->attr.overwrite = DEFAULT_CHANNEL_OVERWRITE;
	chan->attr.subbuf_size = DEFAULT_CHANNEL_SUBBUF_SIZE;
	chan->attr.num_subbuf = DEFAULT_CHANNEL_SUBBUF_NUM;
	chan->attr.switch_timer_interval = DEFAULT_CHANNEL_SWITCH_TIMER;
	chan->attr.read_timer_interval = DEFAULT_CHANNEL_READ_TIMER;
	chan->attr.output = DEFAULT_KERNEL_CHANNEL_OUTPUT;

	/* Init metadata */
	lkm->fd = 0;
	lkm->conf = chan;
	/* Set default metadata path */
	ret = asprintf(&lkm->pathname, "%s/metadata", path);
	if (ret < 0) {
		perror("asprintf kernel metadata");
		goto error;
	}

	return lkm;

error:
	return NULL;
}

/*
 *  trace_create_kernel_stream
 *
 *  Allocate and initialize a kernel stream. The stream is set to ACTIVE_FD by
 *  default.
 *
 *  Return pointer to structure or NULL.
 */
struct ltt_kernel_stream *trace_create_kernel_stream(void)
{
	struct ltt_kernel_stream *lks;

	lks = malloc(sizeof(struct ltt_kernel_stream));
	if (lks == NULL) {
		perror("kernel stream malloc");
		goto error;
	}

	/* Init stream */
	lks->fd = 0;
	lks->pathname = NULL;
	lks->state = 0;

	return lks;

error:
	return NULL;
}

void trace_destroy_kernel_stream(struct ltt_kernel_stream *stream)
{
	DBG("[trace] Closing stream fd %d", stream->fd);
	/* Close kernel fd */
	close(stream->fd);
	free(stream->pathname);

	/* Remove from stream list */
	cds_list_del(&stream->list);
	free(stream);
}

void trace_destroy_kernel_event(struct ltt_kernel_event *event)
{
	DBG("[trace] Closing event fd %d", event->fd);
	/* Close kernel fd */
	close(event->fd);
	/* Free attributes */
	free(event->event);

	/* Remove from event list */
	cds_list_del(&event->list);
	free(event);
}

void trace_destroy_kernel_channel(struct ltt_kernel_channel *channel)
{
	struct ltt_kernel_stream *stream;
	struct ltt_kernel_event *event;

	DBG("[trace] Closing channel fd %d", channel->fd);
	/* Close kernel fd */
	close(channel->fd);
	free(channel->pathname);
	/* Free attributes structure */
	free(channel->channel);

	/* For each stream in the channel list */
	cds_list_for_each_entry(stream, &channel->stream_list.head, list) {
		trace_destroy_kernel_stream(stream);
	}

	/* For each event in the channel list */
	cds_list_for_each_entry(event, &channel->events_list.head, list) {
		trace_destroy_kernel_event(event);
	}

	/* Remove from channel list */
	cds_list_del(&channel->list);
	free(channel);
}

void trace_destroy_kernel_metadata(struct ltt_kernel_metadata *metadata)
{
	DBG("[trace] Closing metadata fd %d", metadata->fd);
	/* Close kernel fd */
	close(metadata->fd);
	/* Free attributes */
	free(metadata->conf);

	free(metadata);
}

void trace_destroy_kernel_session(struct ltt_kernel_session *session)
{
	struct ltt_kernel_channel *channel;

	DBG("[trace] Closing session fd %d", session->fd);
	/* Close kernel fds */
	close(session->fd);
	if (session->metadata_stream_fd != 0) {
		DBG("[trace] Closing metadata stream fd %d", session->metadata_stream_fd);
		close(session->metadata_stream_fd);
	}

	if (session->metadata != NULL) {
		trace_destroy_kernel_metadata(session->metadata);
	}

	cds_list_for_each_entry(channel, &session->channel_list.head, list) {
		trace_destroy_kernel_channel(channel);
	}

	free(session);
}
