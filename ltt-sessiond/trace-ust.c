/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
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

#include <lttngerr.h>
#include <lttng-share.h>

#include "trace-ust.h"

/*
 * Return an UST session by traceable app PID.
 */
struct ltt_ust_session *trace_ust_get_session_by_pid(pid_t pid,
		struct ltt_ust_session_list *session_list)
{
	struct ltt_ust_session *lus;

	cds_list_for_each_entry(lus, &session_list->head, list) {
		if (lus->app->pid == pid) {
			DBG("Found UST session by pid %d", pid);
			return lus;
		}
	}

	return NULL;
}

/*
 * Find the channel name for the given ust session.
 */
struct ltt_ust_channel *trace_ust_get_channel_by_name(
		char *name, struct ltt_ust_session *session)
{
	struct ltt_ust_channel *chan;

	if (session == NULL) {
		ERR("Undefine session");
		goto error;
	}

	cds_list_for_each_entry(chan, &session->channels.head, list) {
		if (strcmp(name, chan->name) == 0) {
			DBG("Found UST channel by name %s", name);
			return chan;
		}
	}

error:
	return NULL;
}

/*
 * Find the event name for the given channel.
 */
struct ltt_ust_event *trace_ust_get_event_by_name(
		char *name, struct ltt_ust_channel *channel)
{
	struct ltt_ust_event *ev;

	if (channel == NULL) {
		ERR("Undefine channel");
		goto error;
	}

	cds_list_for_each_entry(ev, &channel->events.head, list) {
		if (strcmp(name, ev->event->name) == 0) {
			DBG("Found UST event by name %s for channel %s", name,
					channel->name);
			return ev;
		}
	}

error:
	return NULL;
}

/*
 * Allocate and initialize a ust session data structure.
 *
 * Return pointer to structure or NULL.
 */
struct ltt_ust_session *trace_ust_create_session(char *path, pid_t pid)
{
	int ret;
	struct ltt_ust_session *lus;

	/* Allocate a new ltt ust session */
	lus = malloc(sizeof(struct ltt_ust_session));
	if (lus == NULL) {
		perror("create ust session malloc");
		goto error;
	}

	/* Init data structure */
	lus->handle = -1;
	lus->enabled = 1;
	lus->uconsumer_fds_sent = 0;
	lus->path = NULL;
	lus->metadata = NULL;
	lus->app = NULL;	/* TODO: Search app by PID */
	lus->channels.count = 0;
	CDS_INIT_LIST_HEAD(&lus->channels.head);

	/* Set session path */
	ret = asprintf(&lus->path, "%s/ust_%d", path, pid);
	if (ret < 0) {
		perror("asprintf kernel traces path");
		goto error;
	}

	return lus;

error:
	return NULL;
}

/*
 * Allocate and initialize a ust channel data structure.
 *
 * Return pointer to structure or NULL.
 */
struct ltt_ust_channel *trace_ust_create_channel(char *name, char *path,
		struct lttng_ust_channel *chan)
{
	int ret;
	struct ltt_ust_channel *luc;

	luc = malloc(sizeof(struct ltt_ust_channel));
	if (luc == NULL) {
		perror("ltt_ust_channel malloc");
		goto error;
	}

	luc->attr = malloc(sizeof(struct lttng_ust_channel));
	if (luc->attr == NULL) {
		perror("lttng_ust_channel malloc");
		goto error;
	}
	memcpy(luc->attr, chan, sizeof(struct lttng_ust_channel));

	luc->handle = -1;
	luc->enabled = 1;
	luc->ctx = NULL;
	luc->events.count = 0;
	CDS_INIT_LIST_HEAD(&luc->events.head);

	/* Copy channel name */
	strncpy(luc->name, name, LTTNG_UST_SYM_NAME_LEN);
	luc->name[LTTNG_UST_SYM_NAME_LEN - 1] = '\0';

	/* Set trace output path */
	ret = asprintf(&luc->trace_path, "%s", path);
	if (ret < 0) {
		perror("asprintf ust create channel");
		goto error;
	}

	return luc;

error:
	return NULL;
}

/*
 * Allocate and initialize a ust event. Set name and event type.
 *
 * Return pointer to structure or NULL.
 */
struct ltt_ust_event *trace_ust_create_event(struct lttng_event *ev)
{
	struct ltt_ust_event *lue;
	struct lttng_ust_event *event;

	lue = malloc(sizeof(struct ltt_ust_event));
	event = malloc(sizeof(struct lttng_ust_event));
	if (lue == NULL || event == NULL) {
		perror("ust event malloc");
		goto error;
	}

	switch (ev->type) {
	case LTTNG_EVENT_PROBE:
		event->instrumentation = LTTNG_UST_PROBE;
		break;
	case LTTNG_EVENT_FUNCTION:
		event->instrumentation = LTTNG_UST_FUNCTION;
		break;
	case LTTNG_EVENT_FUNCTION_ENTRY:
		event->instrumentation = LTTNG_UST_FUNCTION;
		break;
	case LTTNG_EVENT_TRACEPOINT:
		event->instrumentation = LTTNG_UST_TRACEPOINT;
		break;
	default:
		ERR("Unknown ust instrumentation type (%d)", ev->type);
		goto error;
	}

	/* Copy event name */
	strncpy(event->name, ev->name, LTTNG_UST_SYM_NAME_LEN);
	event->name[LTTNG_UST_SYM_NAME_LEN - 1] = '\0';

	/* Setting up a ust event */
	lue->handle = -1;
	lue->event = event;
	lue->enabled = 1;
	lue->ctx = NULL;

	return lue;

error:
	return NULL;
}

/*
 * Allocate and initialize a ust metadata.
 *
 * Return pointer to structure or NULL.
 */
struct ltt_ust_metadata *trace_ust_create_metadata(char *path)
{
	int ret;
	struct ltt_ust_metadata *lum;
	struct lttng_ust_channel *attr;

	lum = malloc(sizeof(struct ltt_ust_metadata));
	attr = malloc(sizeof(struct lttng_ust_channel));
	if (lum == NULL || attr == NULL) {
		perror("ust metadata malloc");
		goto error;
	}

	/* Set default attributes */
	attr->overwrite = DEFAULT_CHANNEL_OVERWRITE;
	attr->subbuf_size = DEFAULT_METADATA_SUBBUF_SIZE;
	attr->num_subbuf = DEFAULT_METADATA_SUBBUF_NUM;
	attr->switch_timer_interval = DEFAULT_CHANNEL_SWITCH_TIMER;
	attr->read_timer_interval = DEFAULT_CHANNEL_READ_TIMER;
	attr->output = DEFAULT_UST_CHANNEL_OUTPUT;

	lum->attr = attr;
	lum->handle = -1;
	/* Set metadata trace path */
	ret = asprintf(&lum->trace_path, "%s/metadata", path);
	if (ret < 0) {
		perror("asprintf ust metadata");
		goto error;
	}

	return lum;

error:
	return NULL;
}

/*
 * Cleanup ust event structure.
 */
void trace_ust_destroy_event(struct ltt_ust_event *event)
{
	DBG("[trace] Destroy ust event %s", event->event->name);

	/* Free attributes */
	free(event->event);
	free(event->ctx);

	/* Remove from event list */
	cds_list_del(&event->list);
	free(event);
}

/*
 * Cleanup ust channel structure.
 */
void trace_ust_destroy_channel(struct ltt_ust_channel *channel)
{
	struct ltt_ust_event *event, *etmp;

	DBG("[trace] Destroy ust channel %d", channel->handle);

	free(channel->trace_path);
	/* Free attributes structure */
	free(channel->attr);
	free(channel->ctx);

	/* For each event in the channel list */
	cds_list_for_each_entry_safe(event, etmp, &channel->events.head, list) {
		trace_ust_destroy_event(event);
	}

	/* Remove from channel list */
	cds_list_del(&channel->list);
	free(channel);
}

/*
 * Cleanup ust metadata structure.
 */
void trace_ust_destroy_metadata(struct ltt_ust_metadata *metadata)
{
	DBG("[trace] Destroy ust metadata %d", metadata->handle);

	/* Free attributes */
	free(metadata->attr);
	free(metadata->trace_path);

	free(metadata);
}

/*
 * Cleanup ust session structure
 */
void trace_ust_destroy_session(struct ltt_ust_session *session)
{
	struct ltt_ust_channel *channel, *ctmp;

	DBG("[trace] Destroy ust session %d", session->handle);

	/* Extra safety */
	if (session == NULL) {
		return;
	}

	if (session->metadata != NULL) {
		trace_ust_destroy_metadata(session->metadata);
	}

	cds_list_for_each_entry_safe(channel, ctmp, &session->channels.head, list) {
		trace_ust_destroy_channel(channel);
	}

	free(session->path);
	free(session);
}
