/*
 * Copyright (C) 2013 - Julien Desfossez <jdesfossez@efficios.com>
 *                      Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *                      David Goulet <dgoulet@efficios.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef LTTNG_INDEX_H
#define LTTNG_INDEX_H

#include <limits.h>

#define CTF_INDEX_MAGIC 0xC1F1DCC1
#define CTF_INDEX_MAJOR 1
#define CTF_INDEX_MINOR 0

/*
 * Header at the beginning of each index file.
 * All integer fields are stored in big endian.
 */
struct ctf_packet_index_file_hdr {
	uint32_t magic;
	uint32_t index_major;
	uint32_t index_minor;
	/* struct packet_index_len, in bytes */
	uint32_t packet_index_len;
} __attribute__((__packed__));

/*
 * Packet index generated for each trace packet stored in a trace file.
 * All integer fields are stored in big endian.
 */
struct ctf_packet_index {
	uint64_t offset;		/* offset of the packet in the file, in bytes */
	uint64_t packet_size;		/* packet size, in bits */
	uint64_t content_size;		/* content size, in bits */
	uint64_t timestamp_begin;
	uint64_t timestamp_end;
	uint64_t events_discarded;
	uint64_t stream_id;
} __attribute__((__packed__));

#endif /* LTTNG_INDEX_H */
