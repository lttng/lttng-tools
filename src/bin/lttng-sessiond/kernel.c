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

#define _LGPL_SOURCE
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>

#include <common/common.h>
#include <common/kernel-ctl/kernel-ctl.h>
#include <common/kernel-ctl/kernel-ioctl.h>
#include <common/sessiond-comm/sessiond-comm.h>

#include "consumer.h"
#include "kernel.h"
#include "kernel-consumer.h"
#include "kern-modules.h"
#include "utils.h"

/*
 * Add context on a kernel channel.
 *
 * Assumes the ownership of ctx.
 */
int kernel_add_channel_context(struct ltt_kernel_channel *chan,
		struct ltt_kernel_context *ctx)
{
	int ret;

	assert(chan);
	assert(ctx);

	DBG("Adding context to channel %s", chan->channel->name);
	ret = kernctl_add_context(chan->fd, &ctx->ctx);
	if (ret < 0) {
		switch (-ret) {
		case ENOSYS:
			/* Exists but not available for this kernel */
			ret = LTTNG_ERR_KERN_CONTEXT_UNAVAILABLE;
			goto error;
		case EEXIST:
			/* If EEXIST, we just ignore the error */
			ret = 0;
			goto end;
		default:
			PERROR("add context ioctl");
			ret = LTTNG_ERR_KERN_CONTEXT_FAIL;
			goto error;
		}
	}
	ret = 0;

end:
	cds_list_add_tail(&ctx->list, &chan->ctx_list);
	ctx->in_list = true;
	ctx = NULL;
error:
	if (ctx) {
		trace_kernel_destroy_context(ctx);
	}
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
	if (lks) {
		trace_kernel_destroy_session(lks);
	}
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

	DBG3("Kernel create channel %s with attr: %d, %" PRIu64 ", %" PRIu64 ", %u, %u, %d, %d",
			chan->name, lkc->channel->attr.overwrite,
			lkc->channel->attr.subbuf_size, lkc->channel->attr.num_subbuf,
			lkc->channel->attr.switch_timer_interval, lkc->channel->attr.read_timer_interval,
			lkc->channel->attr.live_timer_interval, lkc->channel->attr.output);

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
	if (lkc) {
		free(lkc->channel);
		free(lkc);
	}
	return -1;
}

/*
 * Create a kernel event, enable it to the kernel tracer and add it to the
 * channel event list of the kernel session.
 * We own filter_expression and filter.
 */
int kernel_create_event(struct lttng_event *ev,
		struct ltt_kernel_channel *channel,
		char *filter_expression,
		struct lttng_filter_bytecode *filter)
{
	int ret;
	struct ltt_kernel_event *event;

	assert(ev);
	assert(channel);

	/* We pass ownership of filter_expression and filter */
	event = trace_kernel_create_event(ev, filter_expression,
			filter);
	if (event == NULL) {
		ret = -1;
		goto error;
	}

	ret = kernctl_create_event(channel->fd, event->event);
	if (ret < 0) {
		switch (-ret) {
		case EEXIST:
			break;
		case ENOSYS:
			WARN("Event type not implemented");
			break;
		case ENOENT:
			WARN("Event %s not found!", ev->name);
			break;
		default:
			PERROR("create event ioctl");
		}
		goto free_event;
	}

	event->type = ev->type;
	event->fd = ret;
	/* Prevent fd duplication after execlp() */
	ret = fcntl(event->fd, F_SETFD, FD_CLOEXEC);
	if (ret < 0) {
		PERROR("fcntl session fd");
	}

	if (filter) {
		ret = kernctl_filter(event->fd, filter);
		if (ret) {
			goto filter_error;
		}
	}

	ret = kernctl_enable(event->fd);
	if (ret < 0) {
		switch (-ret) {
		case EEXIST:
			ret = LTTNG_ERR_KERN_EVENT_EXIST;
			break;
		default:
			PERROR("enable kernel event");
			break;
		}
		goto enable_error;
	}

	/* Add event to event list */
	cds_list_add(&event->list, &channel->events_list.head);
	channel->event_count++;

	DBG("Event %s created (fd: %d)", ev->name, event->fd);

	return 0;

enable_error:
filter_error:
	{
		int closeret;

		closeret = close(event->fd);
		if (closeret) {
			PERROR("close event fd");
		}
	}
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
	if (ret < 0 && ret != -EEXIST) {
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
		switch (-ret) {
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
		switch (-ret) {
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


int kernel_track_pid(struct ltt_kernel_session *session, int pid)
{
	int ret;

	DBG("Kernel track PID %d for session id %" PRIu64 ".",
			pid, session->id);
	ret = kernctl_track_pid(session->fd, pid);
	if (!ret) {
		return LTTNG_OK;
	}
	switch (-ret) {
	case EINVAL:
		return LTTNG_ERR_INVALID;
	case ENOMEM:
		return LTTNG_ERR_NOMEM;
	case EEXIST:
		return LTTNG_ERR_PID_TRACKED;
	default:
		return LTTNG_ERR_UNK;
	}
}

int kernel_untrack_pid(struct ltt_kernel_session *session, int pid)
{
	int ret;

	DBG("Kernel untrack PID %d for session id %" PRIu64 ".",
			pid, session->id);
	ret = kernctl_untrack_pid(session->fd, pid);
	if (!ret) {
		return LTTNG_OK;
	}
	switch (-ret) {
	case EINVAL:
		return LTTNG_ERR_INVALID;
	case ENOMEM:
		return LTTNG_ERR_NOMEM;
	case ENOENT:
		return LTTNG_ERR_PID_NOT_TRACKED;
	default:
		return LTTNG_ERR_UNK;
	}
}

ssize_t kernel_list_tracker_pids(struct ltt_kernel_session *session,
		int **_pids)
{
	int fd, ret;
	int pid;
	ssize_t nbmem, count = 0;
	FILE *fp;
	int *pids;

	fd = kernctl_list_tracker_pids(session->fd);
	if (fd < 0) {
		PERROR("kernel tracker pids list");
		goto error;
	}

	fp = fdopen(fd, "r");
	if (fp == NULL) {
		PERROR("kernel tracker pids list fdopen");
		goto error_fp;
	}

	nbmem = KERNEL_TRACKER_PIDS_INIT_LIST_SIZE;
	pids = zmalloc(sizeof(*pids) * nbmem);
	if (pids == NULL) {
		PERROR("alloc list pids");
		count = -ENOMEM;
		goto end;
	}

	while (fscanf(fp, "process { pid = %u; };\n", &pid) == 1) {
		if (count >= nbmem) {
			int *new_pids;
			size_t new_nbmem;

			new_nbmem = nbmem << 1;
			DBG("Reallocating pids list from %zu to %zu entries",
					nbmem, new_nbmem);
			new_pids = realloc(pids, new_nbmem * sizeof(*new_pids));
			if (new_pids == NULL) {
				PERROR("realloc list events");
				free(pids);
				count = -ENOMEM;
				goto end;
			}
			/* Zero the new memory */
			memset(new_pids + nbmem, 0,
				(new_nbmem - nbmem) * sizeof(*new_pids));
			nbmem = new_nbmem;
			pids = new_pids;
		}
		pids[count++] = pid;
	}

	*_pids = pids;
	DBG("Kernel list tracker pids done (%zd pids)", count);
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
 *  Force flush buffer of metadata.
 */
int kernel_metadata_flush_buffer(int fd)
{
	int ret;

	DBG("Kernel flushing metadata buffer on fd %d", fd);

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
 * Note: given that the streams may appear in random order wrt CPU
 * number (e.g. cpu hotplug), the index value of the stream number in
 * the stream name is not necessarily linked to the CPU number.
 *
 * Return the number of created stream. Else, a negative value.
 */
int kernel_open_channel_stream(struct ltt_kernel_channel *channel)
{
	int ret;
	struct ltt_kernel_stream *lks;

	assert(channel);

	while ((ret = kernctl_create_stream(channel->fd)) >= 0) {
		lks = trace_kernel_create_stream(channel->channel->name,
				channel->stream_count);
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

		/* Add stream to channel stream list */
		cds_list_add(&lks->list, &channel->stream_list.head);
		channel->stream_count++;

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
	int fd, ret;
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

	while (fscanf(fp, "event { name = %m[^;]; };\n", &event) == 1) {
		if (count >= nbmem) {
			struct lttng_event *new_elist;
			size_t new_nbmem;

			new_nbmem = nbmem << 1;
			DBG("Reallocating event list from %zu to %zu bytes",
					nbmem, new_nbmem);
			new_elist = realloc(elist, new_nbmem * sizeof(struct lttng_event));
			if (new_elist == NULL) {
				PERROR("realloc list events");
				free(event);
				free(elist);
				count = -ENOMEM;
				goto end;
			}
			/* Zero the new memory */
			memset(new_elist + nbmem, 0,
				(new_nbmem - nbmem) * sizeof(struct lttng_event));
			nbmem = new_nbmem;
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
	struct lttng_kernel_tracer_abi_version abi_version;

	ret = kernctl_tracer_version(tracer_fd, &version);
	if (ret < 0) {
		ERR("Failed to retrieve the lttng-modules version");
		goto error;
	}

	/* Validate version */
	if (version.major != VERSION_MAJOR) {
		ERR("Kernel tracer major version (%d) is not compatible with lttng-tools major version (%d)",
			version.major, VERSION_MAJOR);
		goto error_version;
	}
	ret = kernctl_tracer_abi_version(tracer_fd, &abi_version);
	if (ret < 0) {
		ERR("Failed to retrieve lttng-modules ABI version");
		goto error;
	}
	if (abi_version.major != LTTNG_MODULES_ABI_MAJOR_VERSION) {
		ERR("Kernel tracer ABI version (%d.%d) does not match the expected ABI major version (%d.*)",
			abi_version.major, abi_version.minor,
			LTTNG_MODULES_ABI_MAJOR_VERSION);
		goto error;
	}
	DBG2("Kernel tracer version validated (%d.%d, ABI %d.%d)",
			version.major, version.minor,
			abi_version.major, abi_version.minor);
	return 0;

error_version:
	ret = -1;

error:
	ERR("Kernel tracer version check failed; kernel tracing will not be available");
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

	/*
	 * Destroy channels on the consumer if at least one FD has been sent and we
	 * are in no output mode because the streams are in *no* monitor mode so we
	 * have to send a command to clean them up or else they leaked.
	 */
	if (!ksess->output_traces && ksess->consumer_fds_sent) {
		int ret;
		struct consumer_socket *socket;
		struct lttng_ht_iter iter;

		/* For each consumer socket. */
		rcu_read_lock();
		cds_lfht_for_each_entry(ksess->consumer->socks->ht, &iter.iter,
				socket, node.node) {
			struct ltt_kernel_channel *chan;

			/* For each channel, ask the consumer to destroy it. */
			cds_list_for_each_entry(chan, &ksess->channel_list.head, list) {
				ret = kernel_consumer_destroy_channel(socket, chan);
				if (ret < 0) {
					/* Consumer is probably dead. Use next socket. */
					continue;
				}
			}
		}
		rcu_read_unlock();
	}

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

/*
 * Take a snapshot for a given kernel session.
 *
 * Return 0 on success or else return a LTTNG_ERR code.
 */
int kernel_snapshot_record(struct ltt_kernel_session *ksess,
		struct snapshot_output *output, int wait,
		uint64_t nb_packets_per_stream)
{
	int err, ret, saved_metadata_fd;
	struct consumer_socket *socket;
	struct lttng_ht_iter iter;
	struct ltt_kernel_metadata *saved_metadata;

	assert(ksess);
	assert(ksess->consumer);
	assert(output);

	DBG("Kernel snapshot record started");

	/* Save current metadata since the following calls will change it. */
	saved_metadata = ksess->metadata;
	saved_metadata_fd = ksess->metadata_stream_fd;

	rcu_read_lock();

	ret = kernel_open_metadata(ksess);
	if (ret < 0) {
		ret = LTTNG_ERR_KERN_META_FAIL;
		goto error;
	}

	ret = kernel_open_metadata_stream(ksess);
	if (ret < 0) {
		ret = LTTNG_ERR_KERN_META_FAIL;
		goto error_open_stream;
	}

	/* Send metadata to consumer and snapshot everything. */
	cds_lfht_for_each_entry(ksess->consumer->socks->ht, &iter.iter,
			socket, node.node) {
		struct consumer_output *saved_output;
		struct ltt_kernel_channel *chan;

		/*
		 * Temporarly switch consumer output for our snapshot output. As long
		 * as the session lock is taken, this is safe.
		 */
		saved_output = ksess->consumer;
		ksess->consumer = output->consumer;

		pthread_mutex_lock(socket->lock);
		/* This stream must not be monitored by the consumer. */
		ret = kernel_consumer_add_metadata(socket, ksess, 0);
		pthread_mutex_unlock(socket->lock);
		/* Put back the saved consumer output into the session. */
		ksess->consumer = saved_output;
		if (ret < 0) {
			ret = LTTNG_ERR_KERN_CONSUMER_FAIL;
			goto error_consumer;
		}

		/* For each channel, ask the consumer to snapshot it. */
		cds_list_for_each_entry(chan, &ksess->channel_list.head, list) {
			pthread_mutex_lock(socket->lock);
			ret = consumer_snapshot_channel(socket, chan->fd, output, 0,
					ksess->uid, ksess->gid,
					DEFAULT_KERNEL_TRACE_DIR, wait,
					nb_packets_per_stream);
			pthread_mutex_unlock(socket->lock);
			if (ret < 0) {
				ret = LTTNG_ERR_KERN_CONSUMER_FAIL;
				(void) kernel_consumer_destroy_metadata(socket,
						ksess->metadata);
				goto error_consumer;
			}
		}

		/* Snapshot metadata, */
		pthread_mutex_lock(socket->lock);
		ret = consumer_snapshot_channel(socket, ksess->metadata->fd, output,
				1, ksess->uid, ksess->gid,
				DEFAULT_KERNEL_TRACE_DIR, wait, 0);
		pthread_mutex_unlock(socket->lock);
		if (ret < 0) {
			ret = LTTNG_ERR_KERN_CONSUMER_FAIL;
			goto error_consumer;
		}

		/*
		 * The metadata snapshot is done, ask the consumer to destroy it since
		 * it's not monitored on the consumer side.
		 */
		(void) kernel_consumer_destroy_metadata(socket, ksess->metadata);
	}

	ret = LTTNG_OK;

error_consumer:
	/* Close newly opened metadata stream. It's now on the consumer side. */
	err = close(ksess->metadata_stream_fd);
	if (err < 0) {
		PERROR("close snapshot kernel");
	}

error_open_stream:
	trace_kernel_destroy_metadata(ksess->metadata);
error:
	/* Restore metadata state.*/
	ksess->metadata = saved_metadata;
	ksess->metadata_stream_fd = saved_metadata_fd;

	rcu_read_unlock();
	return ret;
}

/*
 * Get the syscall mask array from the kernel tracer.
 *
 * Return 0 on success else a negative value. In both case, syscall_mask should
 * be freed.
 */
int kernel_syscall_mask(int chan_fd, char **syscall_mask, uint32_t *nr_bits)
{
	assert(syscall_mask);
	assert(nr_bits);

	return kernctl_syscall_mask(chan_fd, syscall_mask, nr_bits);
}

/*
 * Check for the support of the RING_BUFFER_SNAPSHOT_SAMPLE_POSITIONS via abi
 * version number.
 *
 * Return 1 on success, 0 when feature is not supported, negative value in case
 * of errors.
 */
int kernel_supports_ring_buffer_snapshot_sample_positions(int tracer_fd)
{
	int ret = 0; // Not supported by default
	struct lttng_kernel_tracer_abi_version abi;

	ret = kernctl_tracer_abi_version(tracer_fd, &abi);
	if (ret < 0) {
		ERR("Failed to retrieve lttng-modules ABI version");
		goto error;
	}

	/*
	 * RING_BUFFER_SNAPSHOT_SAMPLE_POSITIONS was introduced in 2.3
	 */
	if (abi.major >= 2 && abi.minor >= 3) {
		/* Supported */
		ret = 1;
	} else {
		/* Not supported */
		ret = 0;
	}
error:
	return ret;
}
