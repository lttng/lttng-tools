/*
 * Copyright (C) 2013 - Julien Desfossez <jdesfossez@efficios.com>
 *                      David Goulet <dgoulet@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef LTTNG_INDEX_H
#define LTTNG_INDEX_H

#include <limits.h>

#define INDEX_MAGIC "CTFIDX"
#define INDEX_MAJOR 1
#define INDEX_MINOR 0

/*
 * Header at the beginning of each index file.
 * All integer fields are stored in big endian.
 */
struct lttng_packet_index_file_hdr {
	char magic[6];
	uint32_t index_major;
	uint32_t index_minor;
} __attribute__((__packed__));

/*
 * Packet index generated for each trace packet store in a trace file.
 * All integer fields are stored in big endian.
 */
struct lttng_packet_index {
	uint64_t offset;		/* offset of the packet in the file, in bytes */
	uint64_t packet_size;		/* packet size, in bits */
	uint64_t content_size;		/* content size, in bits */
	uint64_t timestamp_begin;
	uint64_t timestamp_end;
	uint64_t events_discarded;
	uint64_t stream_id;
} __attribute__((__packed__));

#endif /* LTTNG_INDEX_H */
