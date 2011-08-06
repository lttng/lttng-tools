/*
 * Copyright (C) 2011 - Julien Desfossez <julien.desfossez@polymtl.ca>
 *                      Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; only version 2
 * of the License.
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

#include <sys/ioctl.h>

#include "kernel-ioctl.h"
#include "libkernelctl.h"

int kernctl_add_context(int fd, struct lttng_kernel_context *ctx)
{
	return ioctl(fd, LTTNG_KERNEL_CONTEXT, ctx);
}

int kernctl_buffer_flush(int fd)
{
	return ioctl(fd, RING_BUFFER_FLUSH);
}

int kernctl_create_channel(int fd, struct lttng_channel_attr *chops)
{
	return ioctl(fd, LTTNG_KERNEL_CHANNEL, chops);
}

int kernctl_create_event(int fd, struct lttng_kernel_event *ev)
{
	return ioctl(fd, LTTNG_KERNEL_EVENT, ev);
}

int kernctl_create_session(int fd)
{
	return ioctl(fd, LTTNG_KERNEL_SESSION);
}

int kernctl_create_stream(int fd)
{
	return ioctl(fd, LTTNG_KERNEL_STREAM);
}

/* Enable event, channel and session ioctl */
int kernctl_enable(int fd)
{
	return ioctl(fd, LTTNG_KERNEL_ENABLE);
}

/* Disable event, channel and session ioctl */
int kernctl_disable(int fd)
{
	return ioctl(fd, LTTNG_KERNEL_DISABLE);
}

/* returns the maximum size for sub-buffers. */
int kernctl_get_max_subbuf_size(int fd, unsigned long *len)
{
	return ioctl(fd, RING_BUFFER_GET_MAX_SUBBUF_SIZE, len);
}

/* returns the length to mmap. */
int kernctl_get_mmap_len(int fd, unsigned long *len)
{
	return ioctl(fd, RING_BUFFER_GET_MMAP_LEN, len);
}

/* returns the offset of the subbuffer belonging to the mmap reader. */
int kernctl_get_mmap_read_offset(int fd, unsigned long *off)
{
	return ioctl(fd, RING_BUFFER_GET_MMAP_READ_OFFSET, off);
}

/* Get exclusive read access to the next sub-buffer that can be read. */
int kernctl_get_next_subbuf(int fd)
{
	return ioctl(fd, RING_BUFFER_GET_NEXT_SUBBUF);
}

/* returns the size of the current sub-buffer, without padding (for mmap). */
int kernctl_get_padded_subbuf_size(int fd, unsigned long *len)
{
	return ioctl(fd, RING_BUFFER_GET_PADDED_SUBBUF_SIZE, len);
}

/* Get exclusive read access to the specified sub-buffer position */
int kernctl_get_subbuf(int fd, unsigned long *len)
{
	return ioctl(fd, RING_BUFFER_GET_SUBBUF, len);
}

/* returns the size of the current sub-buffer, without padding (for mmap). */
int kernctl_get_subbuf_size(int fd, unsigned long *len)
{
	return ioctl(fd, RING_BUFFER_GET_SUBBUF_SIZE, len);
}

/* open the metadata global channel */
int kernctl_open_metadata(int fd, struct lttng_channel_attr *chops)
{
	return ioctl(fd, LTTNG_KERNEL_METADATA, chops);
}

/* Release exclusive sub-buffer access, move consumer forward. */
int kernctl_put_next_subbuf(int fd)
{
	return ioctl(fd, RING_BUFFER_PUT_NEXT_SUBBUF);
}

/* Release exclusive sub-buffer access */
int kernctl_put_subbuf(int fd)
{
	return ioctl(fd, RING_BUFFER_PUT_SUBBUF);
}

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

int kernctl_start_session(int fd)
{
	return ioctl(fd, LTTNG_KERNEL_SESSION_START);
}

int kernctl_stop_session(int fd)
{
	return ioctl(fd, LTTNG_KERNEL_SESSION_STOP);
}

int kernctl_tracepoint_list(int fd)
{
	return ioctl(fd, LTTNG_KERNEL_TRACEPOINT_LIST);
}

int kernctl_tracer_version(int fd, struct lttng_kernel_tracer_version *v)
{
	return ioctl(fd, LTTNG_KERNEL_TRACER_VERSION, v);
}

int kernctl_wait_quiescent(int fd)
{
	return ioctl(fd, LTTNG_KERNEL_WAIT_QUIESCENT);
}

int kernctl_calibrate(int fd, struct lttng_kernel_calibrate *calibrate)
{
	return ioctl(fd, LTTNG_KERNEL_CALIBRATE, calibrate);
}
