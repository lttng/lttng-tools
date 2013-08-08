/*
 * Copyright (C) 2013 - Julien Desfossez <jdesfossez@efficios.com>
 *                      David Goulet <dgoulet@efficios.com>
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

#define _GNU_SOURCE
#include <assert.h>

#include <common/common.h>
#include <common/defaults.h>
#include <common/utils.h>

#include "index.h"

/*
 * Create the index file associated with a trace file.
 *
 * Return fd on success, a negative value on error.
 */
int index_create_file(char *path_name, char *stream_name, int uid, int gid,
		uint64_t size, uint64_t count)
{
	int ret, fd = -1;
	struct lttng_packet_index_file_hdr hdr;

	ret = utils_create_stream_file(path_name, stream_name, size, count, uid,
			gid, DEFAULT_INDEX_FILE_SUFFIX);
	if (ret < 0) {
		goto error;
	}
	fd = ret;

	memcpy(hdr.magic, INDEX_MAGIC, sizeof(hdr.magic));
	hdr.index_major = htobe32(INDEX_MAJOR);
	hdr.index_minor = htobe32(INDEX_MINOR);

	do {
		ret = write(fd, &hdr, sizeof(hdr));
	} while (ret < 0 && errno == EINTR);
	if (ret < 0) {
		PERROR("write index header");
		goto error;
	}

	return fd;

error:
	if (fd >= 0) {
		int close_ret;

		close_ret = close(fd);
		if (close_ret < 0) {
			PERROR("close index fd");
		}
	}
	return ret;
}

/*
 * Write index values to the given fd of size len.
 *
 * Return 0 on success or else a negative value on error.
 */
int index_write(int fd, struct lttng_packet_index *index, size_t len)
{
	int ret;

	assert(fd >= 0);
	assert(index);

	do {
		ret = write(fd, index, len);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0) {
		PERROR("writing index file");
	}

	return ret;
}
