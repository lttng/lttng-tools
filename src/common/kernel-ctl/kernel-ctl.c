/*
 * Copyright (C) 2011 - Julien Desfossez <julien.desfossez@polymtl.ca>
 *                      Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

#define __USE_LINUX_IOCTL_DEFS
#include <sys/ioctl.h>
#include <string.h>

#include "kernel-ctl.h"
#include "kernel-ioctl.h"

/*
 * This flag indicates which version of the kernel ABI to use. The old
 * ABI (namespace _old) does not support a 32-bit user-space when the
 * kernel is 64-bit. The old ABI is kept here for compatibility but is
 * deprecated and will be removed eventually.
 */
static int lttng_kernel_use_old_abi = -1;

/*
 * Execute the new or old ioctl depending on the ABI version.
 * If the ABI version is not determined yet (lttng_kernel_use_old_abi = -1),
 * this function tests if the new ABI is available and otherwise fallbacks
 * on the old one.
 * This function takes the fd on which the ioctl must be executed and the old
 * and new request codes.
 * It returns the return value of the ioctl executed.
 */
static inline int compat_ioctl_no_arg(int fd, unsigned long oldname,
		unsigned long newname)
{
	int ret;

	if (lttng_kernel_use_old_abi == -1) {
		ret = ioctl(fd, newname);
		if (!ret) {
			lttng_kernel_use_old_abi = 0;
			goto end;
		}
		lttng_kernel_use_old_abi = 1;
	}
	if (lttng_kernel_use_old_abi) {
		ret = ioctl(fd, oldname);
	} else {
		ret = ioctl(fd, newname);
	}

end:
	return ret;
}

int kernctl_create_session(int fd)
{
	return compat_ioctl_no_arg(fd, LTTNG_KERNEL_OLD_SESSION,
			LTTNG_KERNEL_SESSION);
}

/* open the metadata global channel */
int kernctl_open_metadata(int fd, struct lttng_channel_attr *chops)
{
	struct lttng_kernel_old_channel old_channel;
	struct lttng_kernel_channel channel;

	if (lttng_kernel_use_old_abi) {
		old_channel.overwrite = chops->overwrite;
		old_channel.subbuf_size = chops->subbuf_size;
		old_channel.num_subbuf = chops->num_subbuf;
		old_channel.switch_timer_interval = chops->switch_timer_interval;
		old_channel.read_timer_interval = chops->read_timer_interval;
		old_channel.output = chops->output;

		memset(old_channel.padding, 0, sizeof(old_channel.padding));
		/*
		 * The new channel padding is smaller than the old ABI so we use the
		 * new ABI padding size for the memcpy.
		 */
		memcpy(old_channel.padding, chops->padding, sizeof(chops->padding));

		return ioctl(fd, LTTNG_KERNEL_OLD_METADATA, &old_channel);
	}

	channel.overwrite = chops->overwrite;
	channel.subbuf_size = chops->subbuf_size;
	channel.num_subbuf = chops->num_subbuf;
	channel.switch_timer_interval = chops->switch_timer_interval;
	channel.read_timer_interval = chops->read_timer_interval;
	channel.output = chops->output;
	memcpy(channel.padding, chops->padding, sizeof(chops->padding));

	return ioctl(fd, LTTNG_KERNEL_METADATA, &channel);
}

int kernctl_create_channel(int fd, struct lttng_channel_attr *chops)
{
	struct lttng_kernel_channel channel;

	if (lttng_kernel_use_old_abi) {
		struct lttng_kernel_old_channel old_channel;

		old_channel.overwrite = chops->overwrite;
		old_channel.subbuf_size = chops->subbuf_size;
		old_channel.num_subbuf = chops->num_subbuf;
		old_channel.switch_timer_interval = chops->switch_timer_interval;
		old_channel.read_timer_interval = chops->read_timer_interval;
		old_channel.output = chops->output;

		memset(old_channel.padding, 0, sizeof(old_channel.padding));
		/*
		 * The new channel padding is smaller than the old ABI so we use the
		 * new ABI padding size for the memcpy.
		 */
		memcpy(old_channel.padding, chops->padding, sizeof(chops->padding));

		return ioctl(fd, LTTNG_KERNEL_OLD_CHANNEL, &old_channel);
	}

	channel.overwrite = chops->overwrite;
	channel.subbuf_size = chops->subbuf_size;
	channel.num_subbuf = chops->num_subbuf;
	channel.switch_timer_interval = chops->switch_timer_interval;
	channel.read_timer_interval = chops->read_timer_interval;
	channel.output = chops->output;
	memcpy(channel.padding, chops->padding, sizeof(chops->padding));

	return ioctl(fd, LTTNG_KERNEL_CHANNEL, &channel);
}

int kernctl_enable_syscall(int fd, const char *syscall_name)
{
	struct lttng_kernel_event event;

	memset(&event, 0, sizeof(event));
	strncpy(event.name, syscall_name, sizeof(event.name));
	event.name[sizeof(event.name) - 1] = '\0';
	event.instrumentation = LTTNG_KERNEL_SYSCALL;
	event.u.syscall.disable = 0;
	return ioctl(fd, LTTNG_KERNEL_EVENT, &event);
}

int kernctl_disable_syscall(int fd, const char *syscall_name)
{
	struct lttng_kernel_event event;

	memset(&event, 0, sizeof(event));
	strncpy(event.name, syscall_name, sizeof(event.name));
	event.name[sizeof(event.name) - 1] = '\0';
	event.instrumentation = LTTNG_KERNEL_SYSCALL;
	event.u.syscall.disable = 1;
	return ioctl(fd, LTTNG_KERNEL_EVENT, &event);
}

int kernctl_create_stream(int fd)
{
	return compat_ioctl_no_arg(fd, LTTNG_KERNEL_OLD_STREAM,
			LTTNG_KERNEL_STREAM);
}

int kernctl_create_event(int fd, struct lttng_kernel_event *ev)
{
	if (lttng_kernel_use_old_abi) {
		struct lttng_kernel_old_event old_event;

		memcpy(old_event.name, ev->name, sizeof(old_event.name));
		old_event.instrumentation = ev->instrumentation;
		switch (ev->instrumentation) {
		case LTTNG_KERNEL_KPROBE:
			old_event.u.kprobe.addr = ev->u.kprobe.addr;
			old_event.u.kprobe.offset = ev->u.kprobe.offset;
			memcpy(old_event.u.kprobe.symbol_name,
				ev->u.kprobe.symbol_name,
				sizeof(old_event.u.kprobe.symbol_name));
			break;
		case LTTNG_KERNEL_KRETPROBE:
			old_event.u.kretprobe.addr = ev->u.kretprobe.addr;
			old_event.u.kretprobe.offset = ev->u.kretprobe.offset;
			memcpy(old_event.u.kretprobe.symbol_name,
				ev->u.kretprobe.symbol_name,
				sizeof(old_event.u.kretprobe.symbol_name));
			break;
		case LTTNG_KERNEL_FUNCTION:
			memcpy(old_event.u.ftrace.symbol_name,
					ev->u.ftrace.symbol_name,
					sizeof(old_event.u.ftrace.symbol_name));
			break;
		default:
			break;
		}

		return ioctl(fd, LTTNG_KERNEL_OLD_EVENT, &old_event);
	}
	return ioctl(fd, LTTNG_KERNEL_EVENT, ev);
}

int kernctl_add_context(int fd, struct lttng_kernel_context *ctx)
{
	if (lttng_kernel_use_old_abi) {
		struct lttng_kernel_old_context old_ctx;

		old_ctx.ctx = ctx->ctx;
		/* only type that uses the union */
		if (ctx->ctx == LTTNG_KERNEL_CONTEXT_PERF_CPU_COUNTER) {
			old_ctx.u.perf_counter.type =
				ctx->u.perf_counter.type;
			old_ctx.u.perf_counter.config =
				ctx->u.perf_counter.config;
			memcpy(old_ctx.u.perf_counter.name,
				ctx->u.perf_counter.name,
				sizeof(old_ctx.u.perf_counter.name));
		}
		return ioctl(fd, LTTNG_KERNEL_OLD_CONTEXT, &old_ctx);
	}
	return ioctl(fd, LTTNG_KERNEL_CONTEXT, ctx);
}


/* Enable event, channel and session ioctl */
int kernctl_enable(int fd)
{
	return compat_ioctl_no_arg(fd, LTTNG_KERNEL_OLD_ENABLE,
			LTTNG_KERNEL_ENABLE);
}

/* Disable event, channel and session ioctl */
int kernctl_disable(int fd)
{
	return compat_ioctl_no_arg(fd, LTTNG_KERNEL_OLD_DISABLE,
			LTTNG_KERNEL_DISABLE);
}

int kernctl_start_session(int fd)
{
	return compat_ioctl_no_arg(fd, LTTNG_KERNEL_OLD_SESSION_START,
			LTTNG_KERNEL_SESSION_START);
}

int kernctl_stop_session(int fd)
{
	return compat_ioctl_no_arg(fd, LTTNG_KERNEL_OLD_SESSION_STOP,
			LTTNG_KERNEL_SESSION_STOP);
}

int kernctl_tracepoint_list(int fd)
{
	return compat_ioctl_no_arg(fd, LTTNG_KERNEL_OLD_TRACEPOINT_LIST,
			LTTNG_KERNEL_TRACEPOINT_LIST);
}

int kernctl_tracer_version(int fd, struct lttng_kernel_tracer_version *v)
{
	int ret;

	if (lttng_kernel_use_old_abi == -1) {
		ret = ioctl(fd, LTTNG_KERNEL_TRACER_VERSION, v);
		if (!ret) {
			lttng_kernel_use_old_abi = 0;
			goto end;
		}
		lttng_kernel_use_old_abi = 1;
	}
	if (lttng_kernel_use_old_abi) {
		struct lttng_kernel_old_tracer_version old_v;

		ret = ioctl(fd, LTTNG_KERNEL_OLD_TRACER_VERSION, &old_v);
		if (ret) {
			goto end;
		}
		v->major = old_v.major;
		v->minor = old_v.minor;
		v->patchlevel = old_v.patchlevel;
	} else {
		ret = ioctl(fd, LTTNG_KERNEL_TRACER_VERSION, v);
	}

end:
	return ret;
}

int kernctl_wait_quiescent(int fd)
{
	return compat_ioctl_no_arg(fd, LTTNG_KERNEL_OLD_WAIT_QUIESCENT,
			LTTNG_KERNEL_WAIT_QUIESCENT);
}

int kernctl_calibrate(int fd, struct lttng_kernel_calibrate *calibrate)
{
	int ret;

	if (lttng_kernel_use_old_abi == -1) {
		ret = ioctl(fd, LTTNG_KERNEL_CALIBRATE, calibrate);
		if (!ret) {
			lttng_kernel_use_old_abi = 0;
			goto end;
		}
		lttng_kernel_use_old_abi = 1;
	}
	if (lttng_kernel_use_old_abi) {
		struct lttng_kernel_old_calibrate old_calibrate;

		old_calibrate.type = calibrate->type;
		ret = ioctl(fd, LTTNG_KERNEL_OLD_CALIBRATE, &old_calibrate);
		if (ret) {
			goto end;
		}
		calibrate->type = old_calibrate.type;
	} else {
		ret = ioctl(fd, LTTNG_KERNEL_CALIBRATE, calibrate);
	}

end:
	return ret;
}


int kernctl_buffer_flush(int fd)
{
	return ioctl(fd, RING_BUFFER_FLUSH);
}


/* Buffer operations */

/* For mmap mode, readable without "get" operation */

/* returns the length to mmap. */
int kernctl_get_mmap_len(int fd, unsigned long *len)
{
	return ioctl(fd, RING_BUFFER_GET_MMAP_LEN, len);
}

/* returns the maximum size for sub-buffers. */
int kernctl_get_max_subbuf_size(int fd, unsigned long *len)
{
	return ioctl(fd, RING_BUFFER_GET_MAX_SUBBUF_SIZE, len);
}

/*
 * For mmap mode, operate on the current packet (between get/put or
 * get_next/put_next).
 */

/* returns the offset of the subbuffer belonging to the mmap reader. */
int kernctl_get_mmap_read_offset(int fd, unsigned long *off)
{
	return ioctl(fd, RING_BUFFER_GET_MMAP_READ_OFFSET, off);
}

/* returns the size of the current sub-buffer, without padding (for mmap). */
int kernctl_get_subbuf_size(int fd, unsigned long *len)
{
	return ioctl(fd, RING_BUFFER_GET_SUBBUF_SIZE, len);
}

/* returns the size of the current sub-buffer, without padding (for mmap). */
int kernctl_get_padded_subbuf_size(int fd, unsigned long *len)
{
	return ioctl(fd, RING_BUFFER_GET_PADDED_SUBBUF_SIZE, len);
}

/* Get exclusive read access to the next sub-buffer that can be read. */
int kernctl_get_next_subbuf(int fd)
{
	return ioctl(fd, RING_BUFFER_GET_NEXT_SUBBUF);
}


/* Release exclusive sub-buffer access, move consumer forward. */
int kernctl_put_next_subbuf(int fd)
{
	return ioctl(fd, RING_BUFFER_PUT_NEXT_SUBBUF);
}

/* snapshot */

/* Get a snapshot of the current ring buffer producer and consumer positions */
int kernctl_snapshot(int fd)
{
	return ioctl(fd, RING_BUFFER_SNAPSHOT);
}

/* Get the consumer position (iteration start) */
int kernctl_snapshot_get_consumed(int fd, unsigned long *pos)
{
	return ioctl(fd, RING_BUFFER_SNAPSHOT_GET_CONSUMED, pos);
}

/* Get the producer position (iteration end) */
int kernctl_snapshot_get_produced(int fd, unsigned long *pos)
{
	return ioctl(fd, RING_BUFFER_SNAPSHOT_GET_PRODUCED, pos);
}

/* Get exclusive read access to the specified sub-buffer position */
int kernctl_get_subbuf(int fd, unsigned long *len)
{
	return ioctl(fd, RING_BUFFER_GET_SUBBUF, len);
}

/* Release exclusive sub-buffer access */
int kernctl_put_subbuf(int fd)
{
	return ioctl(fd, RING_BUFFER_PUT_SUBBUF);
}

/* Returns the timestamp begin of the current sub-buffer. */
int kernctl_get_timestamp_begin(int fd, uint64_t *timestamp_begin)
{
	return ioctl(fd, LTTNG_RING_BUFFER_GET_TIMESTAMP_BEGIN, timestamp_begin);
}

/* Returns the timestamp end of the current sub-buffer. */
int kernctl_get_timestamp_end(int fd, uint64_t *timestamp_end)
{
	return ioctl(fd, LTTNG_RING_BUFFER_GET_TIMESTAMP_END, timestamp_end);
}

/* Returns the number of discarded events in the current sub-buffer. */
int kernctl_get_events_discarded(int fd, uint64_t *events_discarded)
{
	return ioctl(fd, LTTNG_RING_BUFFER_GET_EVENTS_DISCARDED, events_discarded);
}

/* Returns the content size in the current sub-buffer. */
int kernctl_get_content_size(int fd, uint64_t *content_size)
{
	return ioctl(fd, LTTNG_RING_BUFFER_GET_CONTENT_SIZE, content_size);
}

/* Returns the packet size in the current sub-buffer. */
int kernctl_get_packet_size(int fd, uint64_t *packet_size)
{
	return ioctl(fd, LTTNG_RING_BUFFER_GET_PACKET_SIZE, packet_size);
}

/* Returns the stream id of the current sub-buffer. */
int kernctl_get_stream_id(int fd, uint64_t *stream_id)
{
	return ioctl(fd, LTTNG_RING_BUFFER_GET_STREAM_ID, stream_id);
}

/* Returns the current timestamp. */
int kernctl_get_current_timestamp(int fd, uint64_t *ts)
{
	return ioctl(fd, LTTNG_RING_BUFFER_GET_CURRENT_TIMESTAMP, ts);
}
