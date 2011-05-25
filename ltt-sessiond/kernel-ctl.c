/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
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
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "lttngerr.h"
#include "ltt-sessiond.h"
#include "libkernelctl.h"
#include "kernel-ctl.h"
#include "trace.h"

/*
 *  kernel_create_session
 *
 *  Create a new kernel session using the command context session.
 */
int kernel_create_session(struct ltt_session *session, int tracer_fd)
{
	int ret;
	struct ltt_kernel_session *lks;

	/* Allocate a new kernel session */
	lks = malloc(sizeof(struct ltt_kernel_session));
	if (lks == NULL) {
		perror("kernel session malloc");
		ret = -errno;
		goto error;
	}

	ret = kernctl_create_session(tracer_fd);
	if (ret < 0) {
		goto error;
	}

	/* Assigning session fd and to the command context */
	lks->fd = ret;
	lks->channel_count = 0;
	lks->stream_count_global = 0;
	session->kernel_session = lks;
	session->kern_session_count++;
	CDS_INIT_LIST_HEAD(&lks->channel_list.head);

	DBG("Kernel session created (fd: %d)", lks->fd);

	return 0;

error:
	return ret;
}

/*
 *  kernel_create_channel
 *
 *  Create a kernel channel within the kernel session.
 */
int kernel_create_channel(struct ltt_kernel_session *session)
{
	int ret;
	struct ltt_kernel_channel *lkc;
	struct lttng_kernel_channel *chan;

	lkc = malloc(sizeof(struct ltt_kernel_channel));
	chan = malloc(sizeof(struct lttng_kernel_channel));

	if (lkc == NULL || chan == NULL) {
		perror("kernel channel malloc");
		ret = -errno;
		goto error;
	}

	chan->overwrite = DEFAULT_KERNEL_OVERWRITE;
	chan->subbuf_size = DEFAULT_KERNEL_SUBBUF_SIZE;
	chan->num_subbuf = DEFAULT_KERNEL_SUBBUF_NUM;
	chan->switch_timer_interval = DEFAULT_KERNEL_SWITCH_TIMER;
	chan->read_timer_interval = DEFAULT_KERNEL_READ_TIMER;

	ret = kernctl_create_channel(session->fd, chan);
	if (ret < 0) {
		perror("ioctl create channel");
		goto error;
	}

	/* Setup the channel */
	lkc->fd = ret;
	lkc->channel = chan;
	lkc->stream_count = 0;
	ret = asprintf(&lkc->pathname, "%s", DEFAULT_TRACE_OUTPUT);
	if (ret < 0) {
		perror("asprintf kernel create channel");
		goto error;
	}

	DBG("Channel path set to %s", lkc->pathname);

	CDS_INIT_LIST_HEAD(&lkc->events_list.head);
	CDS_INIT_LIST_HEAD(&lkc->stream_list.head);
	cds_list_add(&lkc->list, &session->channel_list.head);
	session->channel_count++;

	DBG("Kernel channel created (fd: %d)", lkc->fd);

	return 0;

error:
	return ret;
}

/*
 *  kernel_enable_event
 *
 *  Enable kernel event.
 */
int kernel_enable_event(struct ltt_kernel_session *session, char *name)
{
	int ret;
	struct ltt_kernel_channel *chan;
	struct ltt_kernel_event *event;
	struct lttng_kernel_event *lke;

	event = malloc(sizeof(struct ltt_kernel_event));
	lke = malloc(sizeof(struct lttng_kernel_event));

	if (event == NULL || lke == NULL) {
		perror("kernel enable event malloc");
		ret = -errno;
		goto error;
	}

	/* Setting up a kernel event */
	strncpy(lke->name, name, LTTNG_SYM_NAME_LEN);
	lke->instrumentation = LTTNG_KERNEL_TRACEPOINTS;
	event->event = lke;

	cds_list_for_each_entry(chan, &session->channel_list.head, list) {
		ret = kernctl_create_event(chan->fd, lke);
		if (ret < 0) {
			goto error;
		}

		event->fd = ret;
		/* Add event to event list */
		cds_list_add(&event->list, &chan->events_list.head);
		DBG("Event %s enabled (fd: %d)", name, event->fd);
	}

	return 0;

error:
	return ret;
}

/*
 *  kernel_open_metadata
 *
 *  Open metadata stream.
 */
int kernel_open_metadata(struct ltt_kernel_session *session)
{
	int ret;
	struct ltt_kernel_metadata *lkm;
	struct lttng_kernel_channel *conf;

	lkm = malloc(sizeof(struct ltt_kernel_metadata));
	conf = malloc(sizeof(struct lttng_kernel_channel));

	if (lkm == NULL || conf == NULL) {
		perror("kernel open metadata malloc");
		ret = -errno;
		goto error;
	}

	conf->overwrite = DEFAULT_KERNEL_OVERWRITE;
	conf->subbuf_size = DEFAULT_KERNEL_SUBBUF_SIZE;
	conf->num_subbuf = DEFAULT_KERNEL_SUBBUF_NUM;
	conf->switch_timer_interval = DEFAULT_KERNEL_SWITCH_TIMER;
	conf->read_timer_interval = DEFAULT_KERNEL_READ_TIMER;

	ret = kernctl_open_metadata(session->fd, conf);
	if (ret < 0) {
		goto error;
	}

	lkm->fd = ret;
	lkm->conf = conf;
	ret = asprintf(&lkm->pathname, "%s/metadata", DEFAULT_TRACE_OUTPUT);
	if (ret < 0) {
		perror("asprintf kernel metadata");
		goto error;
	}
	session->metadata = lkm;

	DBG("Kernel metadata opened (fd: %d)", lkm->fd);

	return 0;

error:
	return ret;
}

/*
 *  kernel_start_session
 *
 *  Start tracing session.
 */
int kernel_start_session(struct ltt_kernel_session *session)
{
	int ret;

	ret = kernctl_start_session(session->fd);
	if (ret < 0) {
		goto error;
	}

	DBG("Kernel session started");

	return 0;

error:
	return ret;
}

/*
 *  kernel_stop_session
 *
 *  Stop tracing session.
 */
int kernel_stop_session(struct ltt_kernel_session *session)
{
	int ret;

	ret = kernctl_stop_session(session->fd);
	if (ret < 0) {
		goto error;
	}

	DBG("Kernel session stopped");

	return 0;

error:
	return ret;
}

/*
 *  kernel_create_channel_stream
 *
 *  Create a stream for a channel.
 *
 *  Return the number of created stream. Else, a negative value.
 */
int kernel_create_channel_stream(struct ltt_kernel_channel *channel)
{
	int ret;
	struct ltt_kernel_stream *lks;

	while ((ret = kernctl_create_stream(channel->fd)) > 0) {
		lks = malloc(sizeof(struct ltt_kernel_stream));
		if (lks == NULL) {
			perror("kernel create stream malloc");
			ret = -errno;
			goto error;
		}

		lks->fd = ret;
		ret = asprintf(&lks->pathname, "%s/trace_%d",
				channel->pathname, channel->stream_count);
		if (ret < 0) {
			perror("asprintf kernel create stream");
			goto error;
		}
		lks->state = 0;

		cds_list_add(&lks->list, &channel->stream_list.head);
		channel->stream_count++;
	}

	DBG("Kernel channel stream created (num: %d)", channel->stream_count);

	return channel->stream_count;

error:
	return ret;
}

/*
 *  kernel_create_metadata_stream
 *
 *  Create the metadata stream.
 */
int kernel_create_metadata_stream(struct ltt_kernel_session *session)
{
	int ret;

	ret = kernctl_create_stream(session->metadata->fd);
	if (ret < 0) {
		perror("kernel create metadata stream");
		ret = -errno;
		goto error;
	}

	DBG("Kernel metadata stream created (fd: %d)", ret);
	session->metadata_stream_fd = ret;

	return 0;

error:
	return ret;
}
