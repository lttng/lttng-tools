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

#ifndef _LTT_KERNEL_IOCTL_H
#define _LTT_KERNEL_IOCTL_H

/* Get a snapshot of the current ring buffer producer and consumer positions */
#define RING_BUFFER_SNAPSHOT                _IO(0xF6, 0x00)
/* Get the consumer position (iteration start) */
#define RING_BUFFER_SNAPSHOT_GET_CONSUMED   _IOR(0xF6, 0x01, unsigned long)
/* Get the producer position (iteration end) */
#define RING_BUFFER_SNAPSHOT_GET_PRODUCED   _IOR(0xF6, 0x02, unsigned long)
/* Get exclusive read access to the specified sub-buffer position */
#define RING_BUFFER_GET_SUBBUF              _IOW(0xF6, 0x03, unsigned long)
/* Release exclusive sub-buffer access */
#define RING_BUFFER_PUT_SUBBUF              _IO(0xF6, 0x04)

/* Get exclusive read access to the next sub-buffer that can be read. */
#define RING_BUFFER_GET_NEXT_SUBBUF         _IO(0xF6, 0x05)
/* Release exclusive sub-buffer access, move consumer forward. */
#define RING_BUFFER_PUT_NEXT_SUBBUF         _IO(0xF6, 0x06)
/* returns the size of the current sub-buffer, without padding (for mmap). */
#define RING_BUFFER_GET_SUBBUF_SIZE         _IOR(0xF6, 0x07, unsigned long)
/* returns the size of the current sub-buffer, with padding (for splice). */
#define RING_BUFFER_GET_PADDED_SUBBUF_SIZE  _IOR(0xF6, 0x08, unsigned long)
/* returns the maximum size for sub-buffers. */
#define RING_BUFFER_GET_MAX_SUBBUF_SIZE     _IOR(0xF6, 0x09, unsigned long)
/* returns the length to mmap. */
#define RING_BUFFER_GET_MMAP_LEN            _IOR(0xF6, 0x0A, unsigned long)
/* returns the offset of the subbuffer belonging to the mmap reader. */
#define RING_BUFFER_GET_MMAP_READ_OFFSET    _IOR(0xF6, 0x0B, unsigned long)
/* flush the current sub-buffer */
#define RING_BUFFER_FLUSH                   _IO(0xF6, 0x0C)
/* map stream to stream id for network streaming */
#define RING_BUFFER_SET_STREAM_ID           _IOW(0xF6, 0x0D, unsigned long)

/* Old ABI (without support for 32/64 bits compat) */
/* LTTng file descriptor ioctl */
#define LTTNG_KERNEL_OLD_SESSION                _IO(0xF6, 0x40)
#define LTTNG_KERNEL_OLD_TRACER_VERSION         \
		_IOR(0xF6, 0x41, struct lttng_kernel_old_tracer_version)
#define LTTNG_KERNEL_OLD_TRACEPOINT_LIST        _IO(0xF6, 0x42)
#define LTTNG_KERNEL_OLD_WAIT_QUIESCENT         _IO(0xF6, 0x43)
#define LTTNG_KERNEL_OLD_CALIBRATE		\
	_IOWR(0xF6, 0x44, struct lttng_kernel_old_calibrate)

/* Session FD ioctl */
#define LTTNG_KERNEL_OLD_METADATA               \
		_IOW(0xF6, 0x50, struct lttng_kernel_old_channel)
#define LTTNG_KERNEL_OLD_CHANNEL                \
		_IOW(0xF6, 0x51, struct lttng_kernel_old_channel)
#define LTTNG_KERNEL_OLD_SESSION_START          _IO(0xF6, 0x52)
#define LTTNG_KERNEL_OLD_SESSION_STOP           _IO(0xF6, 0x53)

/* Channel FD ioctl */
#define LTTNG_KERNEL_OLD_STREAM                 _IO(0xF6, 0x60)
#define LTTNG_KERNEL_OLD_EVENT                  \
		_IOW(0xF6, 0x61, struct lttng_kernel_old_event)
#define LTTNG_KERNEL_OLD_STREAM_ID_OFFSET       \
		_IOR(0xF6, 0x62, unsigned long)

/* Event and Channel FD ioctl */
#define LTTNG_KERNEL_OLD_CONTEXT                \
		_IOW(0xF6, 0x70, struct lttng_kernel_old_context)

/* Event, Channel and Session ioctl */
#define LTTNG_KERNEL_OLD_ENABLE                 _IO(0xF6, 0x80)
#define LTTNG_KERNEL_OLD_DISABLE                _IO(0xF6, 0x81)


/* Current ABI (with suport for 32/64 bits compat) */
/* LTTng file descriptor ioctl */
#define LTTNG_KERNEL_SESSION			_IO(0xF6, 0x45)
#define LTTNG_KERNEL_TRACER_VERSION		\
	_IOR(0xF6, 0x46, struct lttng_kernel_tracer_version)
#define LTTNG_KERNEL_TRACEPOINT_LIST		_IO(0xF6, 0x47)
#define LTTNG_KERNEL_WAIT_QUIESCENT		_IO(0xF6, 0x48)
#define LTTNG_KERNEL_CALIBRATE			\
	_IOWR(0xF6, 0x49, struct lttng_kernel_calibrate)

/* Session FD ioctl */
#define LTTNG_KERNEL_METADATA			\
	_IOW(0xF6, 0x54, struct lttng_kernel_channel)
#define LTTNG_KERNEL_CHANNEL			\
	_IOW(0xF6, 0x55, struct lttng_kernel_channel)
#define LTTNG_KERNEL_SESSION_START		_IO(0xF6, 0x56)
#define LTTNG_KERNEL_SESSION_STOP		_IO(0xF6, 0x57)

/* Channel FD ioctl */
#define LTTNG_KERNEL_STREAM			_IO(0xF6, 0x62)
#define LTTNG_KERNEL_EVENT			\
	_IOW(0xF6, 0x63, struct lttng_kernel_event)

/* Event and Channel FD ioctl */
#define LTTNG_KERNEL_CONTEXT			\
	_IOW(0xF6, 0x71, struct lttng_kernel_context)

/* Event, Channel and Session ioctl */
#define LTTNG_KERNEL_ENABLE			_IO(0xF6, 0x82)
#define LTTNG_KERNEL_DISABLE			_IO(0xF6, 0x83)

#endif /* _LTT_KERNEL_IOCTL_H */
