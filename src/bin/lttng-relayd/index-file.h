/*
 * Copyright (C) 2018 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef RELAY_INDEX_FILE_H
#define RELAY_INDEX_FILE_H

#include <stdint.h>
#include <common/index/ctf-index.h>

struct relay_index_file;

/*
 * create and open have refcount of 1. Use put to decrement the
 * refcount. Destroys when reaching 0. Use "get" to increment refcount.
 */
struct relay_index_file *relay_index_file_create(const char *path_name,
		const char *stream_name, uint64_t size,
		uint64_t count, uint32_t major, uint32_t minor);
struct relay_index_file *relay_index_file_open(const char *path_name,
		const char *channel_name, uint64_t tracefile_count,
		uint64_t tracefile_count_current);

int relay_index_file_write(const struct relay_index_file *index_file,
		const struct ctf_packet_index *element);
int relay_index_file_read(const struct relay_index_file *index_file,
		struct ctf_packet_index *element);

int relay_index_file_seek_end(struct relay_index_file *index_file);

void relay_index_file_get(struct relay_index_file *index_file);
void relay_index_file_put(struct relay_index_file *index_file);

#endif /* RELAY_INDEX_FILE_H */
