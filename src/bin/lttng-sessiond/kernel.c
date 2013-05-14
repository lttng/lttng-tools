/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
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

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>

#include <common/common.h>
#include <common/kernel-ctl/kernel-ctl.h>
#include <common/sessiond-comm/sessiond-comm.h>

#include "consumer.h"
#include "kernel.h"
#include "kern-modules.h"

/*
 * Add context on a kernel channel.
 */
int kernel_add_channel_context(struct ltt_kernel_channel *chan,
		struct lttng_kernel_context *ctx)
{
	int ret;

	assert(chan);
	assert(ctx);

	DBG("Adding context to channel %s", chan->channel->name);
	ret = kernctl_add_context(chan->fd, ctx);
	if (ret < 0) {
		if (errno != EEXIST) {
			PERROR("add context ioctl");
		} else {
			/* If EEXIST, we just ignore the error */
			ret = 0;
		}
		goto error;
	}

	chan->ctx = zmalloc(sizeof(struct lttng_kernel_context));
	if (chan->ctx == NULL) {
		PERROR("zmalloc event context");
		goto error;
	}

	memcpy(chan->ctx, ctx, sizeof(struct lttng_kernel_context));

	return 0;

error:
	return ret;
}

/*
 * Create a new kernel session, register it to the kernel tracer and add it to
 * the session daemon session.
 */
int kernel_create_session(struct ltt_session *session, int tracer_fd)
{
	int ret;
	struct ltt_kernel_session *lks;

	assert(session);

	/* Allocate data structure */
	lks = trace_kernel_create_session();
	if (lks == NULL) {
		ret = -1;
		goto error;
	}

	/* Kernel tracer session creation */
	ret = kernctl_create_session(tracer_fd);
	if (ret < 0) {
		PERROR("ioctl kernel create session");
		goto error;
	}

	lks->fd = ret;
	/* Prevent fd duplication after execlp() */
	ret = fcntl(lks->fd, F_SETFD, FD_CLOEXEC);
	if (ret < 0) {
		PERROR("fcntl session fd");
	}

	lks->id = session->id;
	lks->consumer_fds_sent = 0;
	session->kernel_session = lks;

	DBG("Kernel session created (fd: %d)", lks->fd);

	return 0;

error:
	return ret;
}

/*
 * Create a kernel channel, register it to the kernel tracer and add it to the
 * kernel session.
 */
int kernel_create_channel(struct ltt_kernel_session *session,
		struct lttng_channel *chan)
{
	int ret;
	struct ltt_kernel_channel *lkc;

	assert(session);
	assert(chan);

	/* Allocate kernel channel */
	lkc = trace_kernel_create_channel(chan);
	if (lkc == NULL) {
		goto error;
	}

	DBG3("Kernel create channel %s with attr: %d, %" PRIu64 ", %" PRIu64 ", %u, %u, %d",
			chan->name, lkc->channel->attr.overwrite,
			lkc->channel->attr.subbuf_size, lkc->channel->attr.num_subbuf,
			lkc->channel->attr.switch_timer_interval, lkc->channel->attr.read_timer_interval,
			lkc->channel->attr.output);

	/* Kernel tracer channel creation */
	ret = kernctl_create_channel(session->fd, &lkc->channel->attr);
	if (ret < 0) {
		PERROR("ioctl kernel create channel");
		goto error;
	}

	/* Setup the channel fd */
	lkc->fd = ret;
	/* Prevent fd duplication after execlp() */
	ret = fcntl(lkc->fd, F_SETFD, FD_CLOEXEC);
	if (ret < 0) {
		PERROR("fcntl session fd");
	}

	/* Add channel to session */
	cds_list_add(&lkc->list, &session->channel_list.head);
	session->channel_count++;
	lkc->session = session;

	DBG("Kernel channel %s created (fd: %d)", lkc->channel->name, lkc->fd);

	return 0;

error:
	return -1;
}

/*
 * Create a kernel event, enable it to the kernel tracer and add it to the
 * channel event list of the kernel session.
 */
int kernel_create_event(struct lttng_event *ev,
		struct ltt_kernel_channel *channel)
{
	int ret;
	struct ltt_kernel_event *event;

	assert(ev);
	assert(channel);

	event = trace_kernel_create_event(ev);
	if (event == NULL) {
		ret = -1;
		goto error;
	}

	ret = kernctl_create_event(channel->fd, event->event);
	if (ret < 0) {
		switch (errno) {
		case EEXIST:
			break;
		case ENOSYS:
			WARN("Event type not implemented");
			break;
		default:
			PERROR("create event ioctl");
		}
		ret = -errno;
		goto free_event;
	}

	/*
	 * LTTNG_KERNEL_SYSCALL event creation will return 0 on success.
	 */
	if (ret == 0 && event->event->instrumentation == LTTNG_KERNEL_SYSCALL) {
		DBG2("Kernel event syscall creation success");
		/*
		 * We use fd == -1 to ensure that we never trigger a close of fd
		 * 0.
		 */
		event->fd = -1;
		goto add_list;
	}

	event->fd = ret;
	/* Prevent fd duplication after execlp() */
	ret = fcntl(event->fd, F_SETFD, FD_CLOEXEC);
	if (ret < 0) {
		PERROR("fcntl session fd");
	}

add_list:
	/* Add event to event list */
	cds_list_add(&event->list, &channel->events_list.head);
	channel->event_count++;

	DBG("Event %s created (fd: %d)", ev->name, event->fd);

	return 0;

free_event:
	free(event);
error:
	return ret;
}

/*
 * Disable a kernel channel.
 */
int kernel_disable_channel(struct ltt_kernel_channel *chan)
{
	int ret;

	assert(chan);

	ret = kernctl_disable(chan->fd);
	if (ret < 0) {
		PERROR("disable chan ioctl");
		ret = errno;
		goto error;
	}

	chan->enabled = 0;
	DBG("Kernel channel %s disabled (fd: %d)", chan->channel->name, chan->fd);

	return 0;

error:
	return ret;
}

/*
 * Enable a kernel channel.
 */
int kernel_enable_channel(struct ltt_kernel_channel *chan)
{
	int ret;

	assert(chan);

	ret = kernctl_enable(chan->fd);
	if (ret < 0 && errno != EEXIST) {
		PERROR("Enable kernel chan");
		goto error;
	}

	chan->enabled = 1;
	DBG("Kernel channel %s enabled (fd: %d)", chan->channel->name, chan->fd);

	return 0;

error:
	return ret;
}

/*
 * Enable a kernel event.
 */
int kernel_enable_event(struct ltt_kernel_event *event)
{
	int ret;

	assert(event);

	ret = kernctl_enable(event->fd);
	if (ret < 0) {
		switch (errno) {
		case EEXIST:
			ret = LTTNG_ERR_KERN_EVENT_EXIST;
			break;
		default:
			PERROR("enable kernel event");
			break;
		}
		goto error;
	}

	event->enabled = 1;
	DBG("Kernel event %s enabled (fd: %d)", event->event->name, event->fd);

	return 0;

error:
	return ret;
}

/*
 * Disable a kernel event.
 */
int kernel_disable_event(struct ltt_kernel_event *event)
{
	int ret;

	assert(event);

	ret = kernctl_disable(event->fd);
	if (ret < 0) {
		switch (errno) {
		case EEXIST:
			ret = LTTNG_ERR_KERN_EVENT_EXIST;
			break;
		default:
			PERROR("disable kernel event");
			break;
		}
		goto error;
	}

	event->enabled = 0;
	DBG("Kernel event %s disabled (fd: %d)", event->event->name, event->fd);

	return 0;

error:
	return ret;
}

/*
 * Create kernel metadata, open from the kernel tracer and add it to the
 * kernel session.
 */
int kernel_open_metadata(struct ltt_kernel_session *session)
{
	int ret;
	struct ltt_kernel_metadata *lkm = NULL;

	assert(session);

	/* Allocate kernel metadata */
	lkm = trace_kernel_create_metadata();
	if (lkm == NULL) {
		goto error;
	}

	/* Kernel tracer metadata creation */
	ret = kernctl_open_metadata(session->fd, &lkm->conf->attr);
	if (ret < 0) {
		goto error_open;
	}

	lkm->fd = ret;
	/* Prevent fd duplication after execlp() */
	ret = fcntl(lkm->fd, F_SETFD, FD_CLOEXEC);
	if (ret < 0) {
		PERROR("fcntl session fd");
	}

	session->metadata = lkm;

	DBG("Kernel metadata opened (fd: %d)", lkm->fd);

	return 0;

error_open:
	trace_kernel_destroy_metadata(lkm);
error:
	return -1;
}

/*
 * Start tracing session.
 */
int kernel_start_session(struct ltt_kernel_session *session)
{
	int ret;

	assert(session);

	ret = kernctl_start_session(session->fd);
	if (ret < 0) {
		PERROR("ioctl start session");
		goto error;
	}

	DBG("Kernel session started");

	return 0;

error:
	return ret;
}

/*
 * Make a kernel wait to make sure in-flight probe have completed.
 */
void kernel_wait_quiescent(int fd)
{
	int ret;

	DBG("Kernel quiescent wait on %d", fd);

	ret = kernctl_wait_quiescent(fd);
	if (ret < 0) {
		PERROR("wait quiescent ioctl");
		ERR("Kernel quiescent wait failed");
	}
}

/*
 * Kernel calibrate
 */
int kernel_calibrate(int fd, struct lttng_kernel_calibrate *calibrate)
{
	int ret;

	assert(calibrate);

	ret = kernctl_calibrate(fd, calibrate);
	if (ret < 0) {
		PERROR("calibrate ioctl");
		return -1;
	}

	return 0;
}


/*
 *  Force flush buffer of metadata.
 */
int kernel_metadata_flush_buffer(int fd)
{
	int ret;

	ret = kernctl_buffer_flush(fd);
	if (ret < 0) {
		ERR("Fail to flush metadata buffers %d (ret: %d)", fd, ret);
	}

	return 0;
}

/*
 * Force flush buffer for channel.
 */
int kernel_flush_buffer(struct ltt_kernel_channel *channel)
{
	int ret;
	struct ltt_kernel_stream *stream;

	assert(channel);

	DBG("Flush buffer for channel %s", channel->channel->name);

	cds_list_for_each_entry(stream, &channel->stream_list.head, list) {
		DBG("Flushing channel stream %d", stream->fd);
		ret = kernctl_buffer_flush(stream->fd);
		if (ret < 0) {
			PERROR("ioctl");
			ERR("Fail to flush buffer for stream %d (ret: %d)",
					stream->fd, ret);
		}
	}

	return 0;
}

/*
 * Stop tracing session.
 */
int kernel_stop_session(struct ltt_kernel_session *session)
{
	int ret;

	assert(session);

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
 * Open stream of channel, register it to the kernel tracer and add it
 * to the stream list of the channel.
 *
 * Return the number of created stream. Else, a negative value.
 */
int kernel_open_channel_stream(struct ltt_kernel_channel *channel)
{
	int ret, count = 0;
	struct ltt_kernel_stream *lks;

	assert(channel);

	while ((ret = kernctl_create_stream(channel->fd)) >= 0) {
		lks = trace_kernel_create_stream(channel->channel->name, count);
		if (lks == NULL) {
			ret = close(ret);
			if (ret) {
				PERROR("close");
			}
			goto error;
		}

		lks->fd = ret;
		/* Prevent fd duplication after execlp() */
		ret = fcntl(lks->fd, F_SETFD, FD_CLOEXEC);
		if (ret < 0) {
			PERROR("fcntl session fd");
		}

		lks->tracefile_size = channel->channel->attr.tracefile_size;
		lks->tracefile_count = channel->channel->attr.tracefile_count;

		/* Add stream to channe stream list */
		cds_list_add(&lks->list, &channel->stream_list.head);
		channel->stream_count++;

		/* Increment counter which represent CPU number. */
		count++;

		DBG("Kernel stream %s created (fd: %d, state: %d)", lks->name, lks->fd,
				lks->state);
	}

	return channel->stream_count;

error:
	return -1;
}

/*
 * Open the metadata stream and set it to the kernel session.
 */
int kernel_open_metadata_stream(struct ltt_kernel_session *session)
{
	int ret;

	assert(session);

	ret = kernctl_create_stream(session->metadata->fd);
	if (ret < 0) {
		PERROR("kernel create metadata stream");
		goto error;
	}

	DBG("Kernel metadata stream created (fd: %d)", ret);
	session->metadata_stream_fd = ret;
	/* Prevent fd duplication after execlp() */
	ret = fcntl(session->metadata_stream_fd, F_SETFD, FD_CLOEXEC);
	if (ret < 0) {
		PERROR("fcntl session fd");
	}

	return 0;

error:
	return -1;
}

/*
 * Get the event list from the kernel tracer and return the number of elements.
 */
ssize_t kernel_list_events(int tracer_fd, struct lttng_event **events)
{
	int fd, pos, ret;
	char *event;
	size_t nbmem, count = 0;
	FILE *fp;
	struct lttng_event *elist;

	assert(events);

	fd = kernctl_tracepoint_list(tracer_fd);
	if (fd < 0) {
		PERROR("kernel tracepoint list");
		goto error;
	}

	fp = fdopen(fd, "r");
	if (fp == NULL) {
		PERROR("kernel tracepoint list fdopen");
		goto error_fp;
	}

	/*
	 * Init memory size counter
	 * See kernel-ctl.h for explanation of this value
	 */
	nbmem = KERNEL_EVENT_INIT_LIST_SIZE;
	elist = zmalloc(sizeof(struct lttng_event) * nbmem);
	if (elist == NULL) {
		PERROR("alloc list events");
		count = -ENOMEM;
		goto end;
	}

	while (fscanf(fp, "event { name = %m[^;]; };%n\n", &event, &pos) == 1) {
		if (count >= nbmem) {
			struct lttng_event *new_elist;

			DBG("Reallocating event list from %zu to %zu bytes", nbmem,
					nbmem * 2);
			/* Double the size */
			nbmem <<= 1;
			new_elist = realloc(elist, nbmem * sizeof(struct lttng_event));
			if (new_elist == NULL) {
				PERROR("realloc list events");
				free(event);
				free(elist);
				count = -ENOMEM;
				goto end;
			}
			elist = new_elist;
		}
		strncpy(elist[count].name, event, LTTNG_SYMBOL_NAME_LEN);
		elist[count].name[LTTNG_SYMBOL_NAME_LEN - 1] = '\0';
		elist[count].enabled = -1;
		count++;
		free(event);
	}

	*events = elist;
	DBG("Kernel list events done (%zu events)", count);
end:
	ret = fclose(fp);	/* closes both fp and fd */
	if (ret) {
		PERROR("fclose");
	}
	return count;

error_fp:
	ret = close(fd);
	if (ret) {
		PERROR("close");
	}
error:
	return -1;
}

/*
 * Get kernel version and validate it.
 */
int kernel_validate_version(int tracer_fd)
{
	int ret;
	struct lttng_kernel_tracer_version version;

	ret = kernctl_tracer_version(tracer_fd, &version);
	if (ret < 0) {
		ERR("Failed at getting the lttng-modules version");
		goto error;
	}

	/* Validate version */
	if (version.major != KERN_MODULES_PRE_MAJOR
		&& version.major != KERN_MODULES_MAJOR) {
		goto error_version;
	}

	DBG2("Kernel tracer version validated (major version %d)", version.major);
	return 0;

error_version:
	ERR("Kernel major version %d is not compatible (supporting <= %d)",
			version.major, KERN_MODULES_MAJOR)
	ret = -1;

error:
	return ret;
}

/*
 * Kernel work-arounds called at the start of sessiond main().
 */
int init_kernel_workarounds(void)
{
	int ret;
	FILE *fp;

	/*
	 * boot_id needs to be read once before being used concurrently
	 * to deal with a Linux kernel race. A fix is proposed for
	 * upstream, but the work-around is needed for older kernels.
	 */
	fp = fopen("/proc/sys/kernel/random/boot_id", "r");
	if (!fp) {
		goto end_boot_id;
	}
	while (!feof(fp)) {
		char buf[37] = "";

		ret = fread(buf, 1, sizeof(buf), fp);
		if (ret < 0) {
			/* Ignore error, we don't really care */
		}
	}
	ret = fclose(fp);
	if (ret) {
		PERROR("fclose");
	}
end_boot_id:
	return 0;
}

/*
 * Complete teardown of a kernel session.
 */
void kernel_destroy_session(struct ltt_kernel_session *ksess)
{
	if (ksess == NULL) {
		DBG3("No kernel session when tearing down session");
		return;
	}

	DBG("Tearing down kernel session");

	/* Close any relayd session */
	consumer_output_send_destroy_relayd(ksess->consumer);

	trace_kernel_destroy_session(ksess);
}

/*
 * Destroy a kernel channel object. It does not do anything on the tracer side.
 */
void kernel_destroy_channel(struct ltt_kernel_channel *kchan)
{
	struct ltt_kernel_session *ksess = NULL;

	assert(kchan);
	assert(kchan->channel);

	DBG3("Kernel destroy channel %s", kchan->channel->name);

	/* Update channel count of associated session. */
	if (kchan->session) {
		/* Keep pointer reference so we can update it after the destroy. */
		ksess = kchan->session;
	}

	trace_kernel_destroy_channel(kchan);

	/*
	 * At this point the kernel channel is not visible anymore. This is safe
	 * since in order to work on a visible kernel session, the tracing session
	 * lock (ltt_session.lock) MUST be acquired.
	 */
	if (ksess) {
		ksess->channel_count--;
	}
}
