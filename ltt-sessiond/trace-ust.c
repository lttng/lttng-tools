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
 * Using a ust session list, it will return the session corresponding to the
 * pid. Must be a session of domain LTTNG_DOMAIN_UST_PID.
 */
struct ltt_ust_session *trace_ust_get_session_by_pid(
		struct ltt_ust_session_list *session_list, pid_t pid)
{
	struct ltt_ust_session *sess;

	if (session_list == NULL) {
		ERR("Session list is NULL");
		goto error;
	}

	cds_list_for_each_entry(sess, &session_list->head, list) {
		if (sess->domain.type == LTTNG_DOMAIN_UST_PID &&
				sess->domain.attr.pid == pid) {
			DBG2("Trace UST session found by pid %d", pid);
			return sess;
		}
	}

error:
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
			DBG2("Found UST channel by name %s", name);
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
		if (strcmp(name, ev->attr.name) == 0) {
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
struct ltt_ust_session *trace_ust_create_session(char *path, pid_t pid,
		struct lttng_domain *domain)
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
	lus->consumer_fds_sent = 0;
	lus->metadata = NULL;
	lus->channels.count = 0;
	CDS_INIT_LIST_HEAD(&lus->channels.head);

	/* Copy lttng_domain */
	memcpy(&lus->domain, domain, sizeof(struct lttng_domain));

	/* Set session path */
	ret = snprintf(lus->path, PATH_MAX, "%s/ust_%d", path, pid);
	if (ret < 0) {
		PERROR("snprintf kernel traces path");
		goto error;
	}

	DBG2("UST trace session create successful");

	return lus;

error:
	return NULL;
}

/*
 * Allocate and initialize a ust channel data structure.
 *
 * Return pointer to structure or NULL.
 */
struct ltt_ust_channel *trace_ust_create_channel(struct lttng_channel *chan,
		char *path)
{
	int ret;
	struct ltt_ust_channel *luc;

	luc = malloc(sizeof(struct ltt_ust_channel));
	if (luc == NULL) {
		perror("ltt_ust_channel malloc");
		goto error;
	}

	/* Copy UST channel attributes */
	memcpy(&luc->attr, &chan->attr, sizeof(struct lttng_ust_channel));

	/* Translate to UST output enum */
	switch (luc->attr.output) {
	default:
		luc->attr.output = LTTNG_UST_MMAP;
		break;
	}

	luc->handle = -1;
	luc->enabled = 1;
	luc->events.count = 0;
	CDS_INIT_LIST_HEAD(&luc->events.head);

	memset(&luc->ctx, 0, sizeof(struct lttng_ust_context));

	/* Copy channel name */
	strncpy(luc->name, chan->name, sizeof(&luc->name));
	luc->name[LTTNG_UST_SYM_NAME_LEN - 1] = '\0';

	/* Set trace output path */
	ret = snprintf(luc->trace_path, PATH_MAX, "%s", path);
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

	lue = malloc(sizeof(struct ltt_ust_event));
	if (lue == NULL) {
		PERROR("ust event malloc");
		goto error;
	}

	switch (ev->type) {
	case LTTNG_EVENT_PROBE:
		lue->attr.instrumentation = LTTNG_UST_PROBE;
		break;
	case LTTNG_EVENT_FUNCTION:
		lue->attr.instrumentation = LTTNG_UST_FUNCTION;
		break;
	case LTTNG_EVENT_FUNCTION_ENTRY:
		lue->attr.instrumentation = LTTNG_UST_FUNCTION;
		break;
	case LTTNG_EVENT_TRACEPOINT:
		lue->attr.instrumentation = LTTNG_UST_TRACEPOINT;
		break;
	default:
		ERR("Unknown ust instrumentation type (%d)", ev->type);
		goto error;
	}

	/* Copy event name */
	strncpy(lue->attr.name, ev->name, LTTNG_UST_SYM_NAME_LEN);
	lue->attr.name[LTTNG_UST_SYM_NAME_LEN - 1] = '\0';

	/* Setting up a ust event */
	lue->handle = -1;
	lue->enabled = 1;
	memset(&lue->ctx, 0, sizeof(struct lttng_ust_context));

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

	lum = malloc(sizeof(struct ltt_ust_metadata));
	if (lum == NULL) {
		perror("ust metadata malloc");
		goto error;
	}

	/* Set default attributes */
	lum->attr.overwrite = DEFAULT_CHANNEL_OVERWRITE;
	lum->attr.subbuf_size = DEFAULT_METADATA_SUBBUF_SIZE;
	lum->attr.num_subbuf = DEFAULT_METADATA_SUBBUF_NUM;
	lum->attr.switch_timer_interval = DEFAULT_CHANNEL_SWITCH_TIMER;
	lum->attr.read_timer_interval = DEFAULT_CHANNEL_READ_TIMER;
	lum->attr.output = DEFAULT_UST_CHANNEL_OUTPUT;

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
	DBG("[trace] Destroy ust event %s", event->attr.name);

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

	if (session->path) {
		free(session->path);
	}

	free(session);
}
