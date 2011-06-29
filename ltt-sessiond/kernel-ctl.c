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
#include <fcntl.h>
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
	/* Prevent fd duplication after execlp() */
	ret = fcntl(lks->fd, F_SETFD, FD_CLOEXEC);
	if (ret < 0) {
		perror("fcntl session fd");
	}

	lks->kconsumer_fds_sent = 0;
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
int kernel_create_channel(struct ltt_kernel_session *session, struct lttng_channel *chan)
{
	int ret;
	struct ltt_kernel_channel *lkc;

	/* Allocate kernel channel */
	lkc = trace_create_kernel_channel(chan);
	if (lkc == NULL) {
		goto error;
	}

	/* Kernel tracer channel creation */
	ret = kernctl_create_channel(session->fd, &lkc->channel->attr);
	if (ret < 0) {
		perror("ioctl kernel create channel");
		goto error;
	}

	/* Setup the channel fd */
	lkc->fd = ret;
	/* Prevent fd duplication after execlp() */
	ret = fcntl(lkc->fd, F_SETFD, FD_CLOEXEC);
	if (ret < 0) {
		perror("fcntl session fd");
	}

	/* Add channel to session */
	cds_list_add(&lkc->list, &session->channel_list.head);
	session->channel_count++;

	DBG("Kernel channel %s created (fd: %d and path: %s)",
			lkc->channel->name, lkc->fd, lkc->pathname);

	return 0;

error:
	return -1;
}

/*
 *  kernel_create_event
 *
 *  Create a kernel event, enable it to the kernel tracer and add it to the
 *  channel event list of the kernel session.
 */
int kernel_create_event(struct lttng_event *ev, struct ltt_kernel_channel *channel)
{
	int ret;
	struct ltt_kernel_event *event;

	event = trace_create_kernel_event(ev);
	if (event == NULL) {
		goto error;
	}

	ret = kernctl_create_event(channel->fd, event->event);
	if (ret < 0) {
		perror("create event ioctl");
		goto free_event;
	}

	event->fd = ret;
	/* Prevent fd duplication after execlp() */
	ret = fcntl(event->fd, F_SETFD, FD_CLOEXEC);
	if (ret < 0) {
		perror("fcntl session fd");
	}

	/* Add event to event list */
	cds_list_add(&event->list, &channel->events_list.head);
	DBG("Event %s created (fd: %d)", ev->name, event->fd);

	return 0;

free_event:
	free(event);
error:
	return -1;
}

/*
 *  kernel_enable_channel
 *
 *  Enable a kernel channel.
 */
int kernel_enable_channel(struct ltt_kernel_channel *chan)
{
	int ret;

	ret = kernctl_enable(chan->fd);
	if (ret < 0) {
		perror("enable chan ioctl");
		ret = errno;
		goto error;
	}

	chan->enabled = 1;
	DBG("Kernel channel %s enabled (fd: %d)", chan->channel->name, chan->fd);

	return 0;

error:
	return ret;
}

/*
 *  kernel_enable_event
 *
 *  Enable a kernel event.
 */
int kernel_enable_event(struct ltt_kernel_event *event)
{
	int ret;

	ret = kernctl_enable(event->fd);
	if (ret < 0) {
		perror("enable event ioctl");
		goto error;
	}

	event->enabled = 1;
	DBG("Kernel event %s enabled (fd: %d)", event->event->name, event->fd);

	return 0;

error:
	return ret;
}

/*
 *  kernel_disable_event
 *
 *  Disable a kernel event.
 */
int kernel_disable_event(struct ltt_kernel_event *event)
{
	int ret;

	ret = kernctl_disable(event->fd);
	if (ret < 0) {
		perror("disable event ioctl");
		goto error;
	}

	event->enabled = 0;
	DBG("Kernel event %s disabled (fd: %d)", event->event->name, event->fd);

	return 0;

error:
	return ret;
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
	ret = kernctl_open_metadata(session->fd, &lkm->conf->attr);
	if (ret < 0) {
		goto error;
	}

	lkm->fd = ret;
	/* Prevent fd duplication after execlp() */
	ret = fcntl(lkm->fd, F_SETFD, FD_CLOEXEC);
	if (ret < 0) {
		perror("fcntl session fd");
	}

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
		perror("ioctl start session");
		goto error;
	}

	DBG("Kernel session started");

	return 0;

error:
	return ret;
}

/*
 *  kernel_wait_quiescent
 *
 *  Make a kernel wait to make sure in-flight probe have completed.
 */
void kernel_wait_quiescent(int fd)
{
	int ret;

	DBG("Kernel quiescent wait on %d", fd);

	ret = kernctl_wait_quiescent(fd);
	if (ret < 0) {
		perror("wait quiescent ioctl");
		ERR("Kernel quiescent wait failed");
	}
}

/*
 *  kernel_metadata_flush_buffer
 *
 *  Force flush buffer of metadata.
 */
int kernel_metadata_flush_buffer(int fd)
{
	int ret;

	ret = kernctl_buffer_flush(fd);
	if (ret < 0) {
		ERR("Fail to flush metadata buffers %d (ret: %d", fd, ret);
	}

	return 0;
}

/*
 *  kernel_flush_buffer
 *
 *  Force flush buffer for channel.
 */
int kernel_flush_buffer(struct ltt_kernel_channel *channel)
{
	int ret;
	struct ltt_kernel_stream *stream;

	DBG("Flush buffer for channel %s", channel->channel->name);

	cds_list_for_each_entry(stream, &channel->stream_list.head, list) {
		DBG("Flushing channel stream %d", stream->fd);
		ret = kernctl_buffer_flush(stream->fd);
		if (ret < 0) {
			perror("ioctl");
			ERR("Fail to flush buffer for stream %d (ret: %d)",
					stream->fd, ret);
		}
	}

	return 0;
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
 *  kernel_open_channel_stream
 *
 *  Open stream of channel, register it to the kernel tracer and add it
 *  to the stream list of the channel.
 *
 *  Return the number of created stream. Else, a negative value.
 */
int kernel_open_channel_stream(struct ltt_kernel_channel *channel)
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
		/* Prevent fd duplication after execlp() */
		ret = fcntl(lks->fd, F_SETFD, FD_CLOEXEC);
		if (ret < 0) {
			perror("fcntl session fd");
		}

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
 *  kernel_open_metadata_stream
 *
 *  Open the metadata stream and set it to the kernel session.
 */
int kernel_open_metadata_stream(struct ltt_kernel_session *session)
{
	int ret;

	ret = kernctl_create_stream(session->metadata->fd);
	if (ret < 0) {
		perror("kernel create metadata stream");
		goto error;
	}

	DBG("Kernel metadata stream created (fd: %d)", ret);
	session->metadata_stream_fd = ret;
	/* Prevent fd duplication after execlp() */
	ret = fcntl(session->metadata_stream_fd, F_SETFD, FD_CLOEXEC);
	if (ret < 0) {
		perror("fcntl session fd");
	}

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
			DBG("Reallocating event list from %zd to %zd bytes", nbmem,
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
