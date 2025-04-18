/*
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 * SPDX-FileCopyrightText: 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef _LTT_KERNEL_IOCTL_H
#define _LTT_KERNEL_IOCTL_H

#define LTTNG_KERNEL_ABI_MAJOR_VERSION 2
#define LTTNG_KERNEL_ABI_MINOR_VERSION 7

/* Get a snapshot of the current ring buffer producer and consumer positions */
#define LTTNG_KERNEL_ABI_RING_BUFFER_SNAPSHOT _IO(0xF6, 0x00)
/* Get the consumer position (iteration start) */
#define LTTNG_KERNEL_ABI_RING_BUFFER_SNAPSHOT_GET_CONSUMED _IOR(0xF6, 0x01, unsigned long)
/* Get the producer position (iteration end) */
#define LTTNG_KERNEL_ABI_RING_BUFFER_SNAPSHOT_GET_PRODUCED _IOR(0xF6, 0x02, unsigned long)
/* Get exclusive read access to the specified sub-buffer position */
#define LTTNG_KERNEL_ABI_RING_BUFFER_GET_SUBBUF _IOW(0xF6, 0x03, unsigned long)
/* Release exclusive sub-buffer access */
#define LTTNG_KERNEL_ABI_RING_BUFFER_PUT_SUBBUF _IO(0xF6, 0x04)

/* Get exclusive read access to the next sub-buffer that can be read. */
#define LTTNG_KERNEL_ABI_RING_BUFFER_GET_NEXT_SUBBUF _IO(0xF6, 0x05)
/* Release exclusive sub-buffer access, move consumer forward. */
#define LTTNG_KERNEL_ABI_RING_BUFFER_PUT_NEXT_SUBBUF _IO(0xF6, 0x06)
/* returns the size of the current sub-buffer, without padding (for mmap). */
#define LTTNG_KERNEL_ABI_RING_BUFFER_GET_SUBBUF_SIZE _IOR(0xF6, 0x07, unsigned long)
/* returns the size of the current sub-buffer, with padding (for splice). */
#define LTTNG_KERNEL_ABI_RING_BUFFER_GET_PADDED_SUBBUF_SIZE _IOR(0xF6, 0x08, unsigned long)
/* returns the maximum size for sub-buffers. */
#define LTTNG_KERNEL_ABI_RING_BUFFER_GET_MAX_SUBBUF_SIZE _IOR(0xF6, 0x09, unsigned long)
/* returns the length to mmap. */
#define LTTNG_KERNEL_ABI_RING_BUFFER_GET_MMAP_LEN _IOR(0xF6, 0x0A, unsigned long)
/* returns the offset of the subbuffer belonging to the mmap reader. */
#define LTTNG_KERNEL_ABI_RING_BUFFER_GET_MMAP_READ_OFFSET _IOR(0xF6, 0x0B, unsigned long)
/* Flush the current sub-buffer, if non-empty. */
#define LTTNG_KERNEL_ABI_RING_BUFFER_FLUSH _IO(0xF6, 0x0C)
/* Get the current version of the metadata cache (after a get_next). */
#define LTTNG_KERNEL_ABI_RING_BUFFER_GET_METADATA_VERSION _IOR(0xF6, 0x0D, uint64_t)
/*
 * Get a snapshot of the current ring buffer producer and consumer positions,
 * regardless of whether or not the two positions are contained within the same
 * sub-buffer.
 */
#define LTTNG_KERNEL_ABI_RING_BUFFER_SNAPSHOT_SAMPLE_POSITIONS _IO(0xF6, 0x0E)
/* Flush the current sub-buffer, even if empty. */
#define LTTNG_KERNEL_ABI_RING_BUFFER_FLUSH_EMPTY _IO(0xF6, 0x0F)
/*
 * Reset the position of what has been consumed from the metadata cache to 0
 * so it can be read again.
 */
#define LTTNG_KERNEL_ABI_RING_BUFFER_METADATA_CACHE_DUMP _IO(0xF6, 0x10)
/* Clear ring buffer content */
#define LTTNG_KERNEL_ABI_RING_BUFFER_CLEAR			    _IO(0xF6, 0x11)
#define LTTNG_KERNEL_ABI_RING_BUFFER_GET_NEXT_SUBBUF_METADATA_CHECK _IOR(0xF6, 0x12, uint32_t)
/*
 * Flush the current sub-buffer or populate a packet.
 */
#define LTTNG_KERNEL_ABI_RING_BUFFER_FLUSH_OR_POPULATE_PACKET \
	_IOWR(0xF6, 0x13, struct lttng_kernel_abi_ring_buffer_packet_flush_or_populate_packet_args)

/* returns the timestamp begin of the current sub-buffer */
#define LTTNG_KERNEL_ABI_RING_BUFFER_GET_TIMESTAMP_BEGIN _IOR(0xF6, 0x20, uint64_t)
/* returns the timestamp end of the current sub-buffer */
#define LTTNG_KERNEL_ABI_RING_BUFFER_GET_TIMESTAMP_END _IOR(0xF6, 0x21, uint64_t)
/* returns the number of events discarded */
#define LTTNG_KERNEL_ABI_RING_BUFFER_GET_EVENTS_DISCARDED _IOR(0xF6, 0x22, uint64_t)
/* returns the packet payload size */
#define LTTNG_KERNEL_ABI_RING_BUFFER_GET_CONTENT_SIZE _IOR(0xF6, 0x23, uint64_t)
/* returns the actual packet size */
#define LTTNG_KERNEL_ABI_RING_BUFFER_GET_PACKET_SIZE _IOR(0xF6, 0x24, uint64_t)
/* returns the stream id */
#define LTTNG_KERNEL_ABI_RING_BUFFER_GET_STREAM_ID _IOR(0xF6, 0x25, uint64_t)
/* returns the current timestamp */
#define LTTNG_KERNEL_ABI_RING_BUFFER_GET_CURRENT_TIMESTAMP _IOR(0xF6, 0x26, uint64_t)
/* returns the packet sequence number */
#define LTTNG_KERNEL_ABI_RING_BUFFER_GET_SEQ_NUM _IOR(0xF6, 0x27, uint64_t)
/* returns the stream instance id */
#define LTTNG_KERNEL_ABI_RING_BUFFER_INSTANCE_ID _IOR(0xF6, 0x28, uint64_t)

/* Old ABI (without support for 32/64 bits compat) */
/* LTTng file descriptor ioctl */
#define LTTNG_KERNEL_ABI_OLD_SESSION _IO(0xF6, 0x40)
#define LTTNG_KERNEL_ABI_OLD_TRACER_VERSION \
	_IOR(0xF6, 0x41, struct lttng_kernel_abi_old_tracer_version)
#define LTTNG_KERNEL_ABI_OLD_TRACEPOINT_LIST _IO(0xF6, 0x42)
#define LTTNG_KERNEL_ABI_OLD_WAIT_QUIESCENT  _IO(0xF6, 0x43)

/* Session FD ioctl */
#define LTTNG_KERNEL_ABI_OLD_METADATA	   _IOW(0xF6, 0x50, struct lttng_kernel_abi_old_channel)
#define LTTNG_KERNEL_ABI_OLD_CHANNEL	   _IOW(0xF6, 0x51, struct lttng_kernel_abi_old_channel)
#define LTTNG_KERNEL_ABI_OLD_SESSION_START _IO(0xF6, 0x52)
#define LTTNG_KERNEL_ABI_OLD_SESSION_STOP  _IO(0xF6, 0x53)

/* Channel FD ioctl */
#define LTTNG_KERNEL_ABI_OLD_STREAM _IO(0xF6, 0x60)
#define LTTNG_KERNEL_ABI_OLD_EVENT  _IOW(0xF6, 0x61, struct lttng_kernel_abi_old_event)

/* Event and Channel FD ioctl */
#define LTTNG_KERNEL_ABI_OLD_CONTEXT _IOW(0xF6, 0x70, struct lttng_kernel_abi_old_context)

/* Event, Channel and Session ioctl */
#define LTTNG_KERNEL_ABI_OLD_ENABLE  _IO(0xF6, 0x80)
#define LTTNG_KERNEL_ABI_OLD_DISABLE _IO(0xF6, 0x81)

/* Current ABI (with suport for 32/64 bits compat) */
/* LTTng file descriptor ioctl */
#define LTTNG_KERNEL_ABI_SESSION	 _IO(0xF6, 0x45)
#define LTTNG_KERNEL_ABI_TRACER_VERSION	 _IOR(0xF6, 0x46, struct lttng_kernel_abi_tracer_version)
#define LTTNG_KERNEL_ABI_TRACEPOINT_LIST _IO(0xF6, 0x47)
#define LTTNG_KERNEL_ABI_WAIT_QUIESCENT	 _IO(0xF6, 0x48)
#define LTTNG_KERNEL_ABI_SYSCALL_LIST	 _IO(0xF6, 0x4A)
#define LTTNG_KERNEL_ABI_TRACER_ABI_VERSION \
	_IOR(0xF6, 0x4B, struct lttng_kernel_abi_tracer_abi_version)
#define LTTNG_KERNEL_ABI_EVENT_NOTIFIER_GROUP_CREATE _IO(0xF6, 0x4C)

/* Session FD ioctl */
#define LTTNG_KERNEL_ABI_METADATA	     _IOW(0xF6, 0x54, struct lttng_kernel_abi_channel)
#define LTTNG_KERNEL_ABI_CHANNEL	     _IOW(0xF6, 0x55, struct lttng_kernel_abi_channel)
#define LTTNG_KERNEL_ABI_SESSION_START	     _IO(0xF6, 0x56)
#define LTTNG_KERNEL_ABI_SESSION_STOP	     _IO(0xF6, 0x57)
#define LTTNG_KERNEL_ABI_SESSION_TRACK_PID   _IOW(0xF6, 0x58, int32_t)
#define LTTNG_KERNEL_ABI_SESSION_UNTRACK_PID _IOW(0xF6, 0x59, int32_t)
/*
 * ioctl 0x58 and 0x59 are duplicated here. It works, since _IOR vs _IO
 * are generating two different ioctl numbers, but this was not done on
 * purpose. We should generally try to avoid those duplications.
 */
#define LTTNG_KERNEL_ABI_SESSION_LIST_TRACKER_PIDS _IO(0xF6, 0x58)
#define LTTNG_KERNEL_ABI_SESSION_METADATA_REGEN	   _IO(0xF6, 0x59)
/* 0x5A and 0x5B are reserved for a future ABI-breaking cleanup. */
#define LTTNG_KERNEL_ABI_SESSION_STATEDUMP _IO(0xF6, 0x5C)
#define LTTNG_KERNEL_ABI_SESSION_SET_NAME  _IOW(0xF6, 0x5D, struct lttng_kernel_abi_session_name)
#define LTTNG_KERNEL_ABI_SESSION_SET_CREATION_TIME \
	_IOW(0xF6, 0x5E, struct lttng_kernel_abi_session_creation_time)
#define LTTNG_KERNEL_ABI_SESSION_SET_OUTPUT_FORMAT _IOW(0xF6, 0x5F, uint32_t)

/* Channel FD ioctl */
#define LTTNG_KERNEL_ABI_STREAM	      _IO(0xF6, 0x62)
#define LTTNG_KERNEL_ABI_EVENT	      _IOW(0xF6, 0x63, struct lttng_kernel_abi_event)
#define LTTNG_KERNEL_ABI_SYSCALL_MASK _IOWR(0xF6, 0x64, struct lttng_kernel_abi_syscall_mask)

/* Event and Channel FD ioctl */
#define LTTNG_KERNEL_ABI_CONTEXT _IOW(0xF6, 0x71, struct lttng_kernel_abi_context)

/* Event, event notifier, Channel and Session ioctl */
#define LTTNG_KERNEL_ABI_ENABLE	 _IO(0xF6, 0x82)
#define LTTNG_KERNEL_ABI_DISABLE _IO(0xF6, 0x83)

/* Event notifier group ioctl */
#define LTTNG_KERNEL_ABI_COUNTER _IOW(0xF6, 0x84, struct lttng_kernel_abi_counter_conf)

/* Event and event notifier FD ioctl */
#define LTTNG_KERNEL_ABI_FILTER	      _IO(0xF6, 0x90)
#define LTTNG_KERNEL_ABI_ADD_CALLSITE _IO(0xF6, 0x91)

/* Session FD ioctl (continued) */
#define LTTNG_KERNEL_ABI_SESSION_LIST_TRACKER_IDS \
	_IOW(0xF6, 0xA0, struct lttng_kernel_abi_tracker_args)
#define LTTNG_KERNEL_ABI_SESSION_TRACK_ID   _IOW(0xF6, 0xA1, struct lttng_kernel_abi_tracker_args)
#define LTTNG_KERNEL_ABI_SESSION_UNTRACK_ID _IOW(0xF6, 0xA2, struct lttng_kernel_abi_tracker_args)

/* Event notifier group file descriptor ioctl */
#define LTTNG_KERNEL_ABI_EVENT_NOTIFIER_CREATE \
	_IOW(0xF6, 0xB0, struct lttng_kernel_abi_event_notifier)
#define LTTNG_KERNEL_ABI_EVENT_NOTIFIER_GROUP_NOTIFICATION_FD _IO(0xF6, 0xB1)

/* Event notifier file descriptor ioctl */
#define LTTNG_KERNEL_ABI_CAPTURE _IO(0xF6, 0xB8)

/* Counter file descriptor ioctl */
#define LTTNG_KERNEL_ABI_COUNTER_READ IOWR(0xF6, 0xC0, struct lttng_kernel_abi_counter_read)
#define LTTNG_KERNEL_ABI_COUNTER_AGGREGATE \
	_IOWR(0xF6, 0xC1, struct lttng_kernel_abi_counter_aggregate)
#define LTTNG_KERNEL_ABI_COUNTER_CLEAR		    _IOW(0xF6, 0xC2, struct lttng_kernel_abi_counter_clear)
#define LTTNG_KERNEL_ABI_COUNTER_MAP_NR_DESCRIPTORS _IOR(0xF6, 0xC3, uint64_t)
#define LTTNG_KERNEL_ABI_COUNTER_MAP_DESCRIPTOR \
	_IOWR(0xF6, 0xC4, struct lttng_kernel_abi_counter_map_descriptor)
#define LTTNG_KERNEL_ABI_COUNTER_EVENT _IOW(0xF6, 0xC5, struct lttng_kernel_abi_counter_event)

/*
 * Those ioctl numbers use the wrong direction, but are kept for ABI backward
 * compatibility.
 */
#define LTTNG_KERNEL_ABI_OLD_SESSION_SET_NAME _IOR(0xF6, 0x5D, struct lttng_kernel_abi_session_name)
#define LTTNG_KERNEL_ABI_OLD_SESSION_SET_CREATION_TIME \
	_IOR(0xF6, 0x5E, struct lttng_kernel_abi_session_creation_time)
#define LTTNG_KERNEL_ABI_OLD_SESSION_TRACK_PID	 _IOW(0xF6, 0x58, int32_t)
#define LTTNG_KERNEL_ABI_OLD_SESSION_UNTRACK_PID _IOW(0xF6, 0x59, int32_t)
#define LTTNG_KERNEL_ABI_OLD_SESSION_LIST_TRACKER_IDS \
	_IOR(0xF6, 0xA0, struct lttng_kernel_abi_tracker_args)
#define LTTNG_KERNEL_ABI_OLD_SESSION_TRACK_ID _IOR(0xF6, 0xA1, struct lttng_kernel_abi_tracker_args)
#define LTTNG_KERNEL_ABI_OLD_SESSION_UNTRACK_ID \
	_IOR(0xF6, 0xA2, struct lttng_kernel_abi_tracker_args)

#endif /* _LTT_KERNEL_IOCTL_H */
