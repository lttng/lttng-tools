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
#include <urcu/list.h>

#include "ltt-sessiond.h"
#include "trace.h"

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
struct ltt_kernel_channel *trace_create_kernel_channel(void)
{
	int ret;
	struct ltt_kernel_channel *lkc;
	struct lttng_kernel_channel *chan;

	lkc = malloc(sizeof(struct ltt_kernel_channel));
	chan = malloc(sizeof(struct lttng_kernel_channel));
	if (lkc == NULL || chan == NULL) {
		perror("kernel channel malloc");
		goto error;
	}

	/* Default value to channel */
	chan->overwrite = DEFAULT_KERNEL_OVERWRITE;
	chan->subbuf_size = DEFAULT_KERNEL_SUBBUF_SIZE;
	chan->num_subbuf = DEFAULT_KERNEL_SUBBUF_NUM;
	chan->switch_timer_interval = DEFAULT_KERNEL_SWITCH_TIMER;
	chan->read_timer_interval = DEFAULT_KERNEL_READ_TIMER;

	lkc->fd = 0;
	lkc->stream_count = 0;
	lkc->channel = chan;
	/* Init linked list */
	CDS_INIT_LIST_HEAD(&lkc->events_list.head);
	CDS_INIT_LIST_HEAD(&lkc->stream_list.head);
	/* Set default trace output path */
	ret = asprintf(&lkc->pathname, "%s", DEFAULT_TRACE_OUTPUT);
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
struct ltt_kernel_event *trace_create_kernel_event(char *name,
		enum lttng_kernel_instrumentation type)
{
	struct ltt_kernel_event *lke;
	struct lttng_kernel_event *attr;

	lke = malloc(sizeof(struct ltt_kernel_event));
	attr = malloc(sizeof(struct lttng_kernel_event));
	if (lke == NULL || attr == NULL) {
		perror("kernel event malloc");
		goto error;
	}

	/* Init event attribute */
	attr->instrumentation = type;
	strncpy(attr->name, name, LTTNG_SYM_NAME_LEN);
	/* Setting up a kernel event */
	lke->fd = 0;
	lke->event = attr;

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
struct ltt_kernel_metadata *trace_create_kernel_metadata(void)
{
	int ret;
	struct ltt_kernel_metadata *lkm;
	struct lttng_kernel_channel *attr;

	lkm = malloc(sizeof(struct ltt_kernel_metadata));
	attr = malloc(sizeof(struct lttng_kernel_channel));
	if (lkm == NULL || attr == NULL) {
		perror("kernel metadata malloc");
		goto error;
	}

	/* Set default attributes */
	attr->overwrite = DEFAULT_KERNEL_OVERWRITE;
	attr->subbuf_size = DEFAULT_KERNEL_SUBBUF_SIZE;
	attr->num_subbuf = DEFAULT_KERNEL_SUBBUF_NUM;
	attr->switch_timer_interval = DEFAULT_KERNEL_SWITCH_TIMER;
	attr->read_timer_interval = DEFAULT_KERNEL_READ_TIMER;

	/* Init metadata */
	lkm->fd = 0;
	lkm->conf = attr;
	/* Set default metadata path */
	ret = asprintf(&lkm->pathname, "%s/metadata", DEFAULT_TRACE_OUTPUT);
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
