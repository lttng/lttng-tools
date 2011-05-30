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

/*
 *  kernel_create_session
 *
 *  Create a new kernel session, register it to the kernel tracer and add it to
 *  the session daemon session.
 */
int kernel_create_session(struct ltt_session *session, int tracer_fd)
{
	int ret;
	struct ltt_kernel_session *lks;

	/* Allocate data structure */
	lks = trace_create_kernel_session();
	if (lks == NULL) {
		ret = -1;
		goto error;
	}

	/* Kernel tracer session creation */
	ret = kernctl_create_session(tracer_fd);
	if (ret < 0) {
		perror("ioctl kernel create session");
		goto error;
	}

	lks->fd = ret;
	session->kernel_session = lks;
	session->kern_session_count++;

	DBG("Kernel session created (fd: %d)", lks->fd);

	return 0;

error:
	return ret;
}

/*
 *  kernel_create_channel
 *
 *  Create a kernel channel, register it to the kernel tracer and add it to the
 *  kernel session.
 */
int kernel_create_channel(struct ltt_kernel_session *session)
{
	int ret;
	struct ltt_kernel_channel *lkc;

	/* Allocate kernel channel */
	lkc = trace_create_kernel_channel();
	if (lkc == NULL) {
		goto error;
	}

	/* Kernel tracer channel creation */
	ret = kernctl_create_channel(session->fd, lkc->channel);
	if (ret < 0) {
		perror("ioctl kernel create channel");
		goto error;
	}

	/* Setup the channel fd */
	lkc->fd = ret;
	/* Add channel to session */
	cds_list_add(&lkc->list, &session->channel_list.head);
	session->channel_count++;

	DBG("Kernel channel created (fd: %d and path: %s)", lkc->fd, lkc->pathname);

	return 0;

error:
	return -1;
}

/*
 *  kernel_enable_event
 *
 *  Create a kernel event, enable it to the kernel tracer and add it to the
 *  channel event list of the kernel session.
 */
int kernel_enable_event(struct ltt_kernel_session *session, char *name)
{
	int ret;
	struct ltt_kernel_channel *chan;
	struct ltt_kernel_event *event;

	event = trace_create_kernel_event(name, LTTNG_KERNEL_TRACEPOINTS);
	if (event == NULL) {
		goto error;
	}

	cds_list_for_each_entry(chan, &session->channel_list.head, list) {
		ret = kernctl_create_event(chan->fd, event->event);
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
	return -1;
}

/*
 *  kernel_open_metadata
 *
 *  Create kernel metadata, open from the kernel tracer and add it to the
 *  kernel session.
 */
int kernel_open_metadata(struct ltt_kernel_session *session)
{
	int ret;
	struct ltt_kernel_metadata *lkm;

	/* Allocate kernel metadata */
	lkm = trace_create_kernel_metadata();
	if (lkm == NULL) {
		goto error;
	}

	/* Kernel tracer metadata creation */
	ret = kernctl_open_metadata(session->fd, lkm->conf);
	if (ret < 0) {
		goto error;
	}

	lkm->fd = ret;
	session->metadata = lkm;

	DBG("Kernel metadata opened (fd: %d and path: %s)", lkm->fd, lkm->pathname);

	return 0;

error:
	return -1;
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
 *  Create a stream for a channel, register it to the kernel tracer and add it
 *  to the stream list of the channel.
 *
 *  Return the number of created stream. Else, a negative value.
 */
int kernel_create_channel_stream(struct ltt_kernel_channel *channel)
{
	int ret;
	struct ltt_kernel_stream *lks;

	while ((ret = kernctl_create_stream(channel->fd)) > 0) {
		lks = trace_create_kernel_stream();
		if (lks == NULL) {
			close(ret);
			goto error;
		}

		lks->fd = ret;
		ret = asprintf(&lks->pathname, "%s/trace_%d",
				channel->pathname, channel->stream_count);
		if (ret < 0) {
			perror("asprintf kernel create stream");
			goto error;
		}

		/* Add stream to channe stream list */
		cds_list_add(&lks->list, &channel->stream_list.head);
		channel->stream_count++;

		DBG("Kernel stream %d created (fd: %d, state: %d, path: %s)",
				channel->stream_count, lks->fd, lks->state, lks->pathname);
	}

	return channel->stream_count;

error:
	return -1;
}

/*
 *  kernel_create_metadata_stream
 *
 *  Create the metadata stream and set it to the kernel session.
 */
int kernel_create_metadata_stream(struct ltt_kernel_session *session)
{
	int ret;

	ret = kernctl_create_stream(session->metadata->fd);
	if (ret < 0) {
		perror("kernel create metadata stream");
		goto error;
	}

	DBG("Kernel metadata stream created (fd: %d)", ret);
	session->metadata_stream_fd = ret;

	return 0;

error:
	return -1;
}

/*
 *  kernel_list_events
 *
 *  Get the event list from the kernel tracer and return that list in the CTF
 *  format.
 */
ssize_t kernel_list_events(int tracer_fd, char **list)
{
	int fd;
	char *buf, *line = NULL;
	size_t nb, nbmem, total = 0;
	ssize_t size;
	FILE *fp;

	fd = kernctl_tracepoint_list(tracer_fd);
	if (fd < 0) {
		perror("kernel tracepoint list");
		goto error;
	}

	fp = fdopen(fd, "r");
	if (fp == NULL) {
		perror("kernel tracepoint list fdopen");
		goto error;
	}

	/*
	 * Init memory size counter
	 * See kernel-ctl.h for explanation of this value
	 */
	nbmem = KERNEL_EVENT_LIST_SIZE;
	buf = malloc(nbmem);

	while ((size = getline(&line, &nb, fp)) != -1) {
		if (total + size > nbmem) {
			DBG("Reallocating event list from %ld to %ld bytes", nbmem,
					total + size + KERNEL_EVENT_LIST_SIZE);
			/* Adding the default size again */
			nbmem = total + size + KERNEL_EVENT_LIST_SIZE;
			buf = realloc(buf, nbmem);
			if (buf == NULL) {
				perror("realloc list events");
				goto error;
			}
		}
		memcpy(buf + total, line, size);
		total += size;
	}

	*list = buf;

	DBG("Kernel list events done");

	return total;

error:
	return -1;
}

