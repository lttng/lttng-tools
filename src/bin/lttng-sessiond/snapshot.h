/*
 * Copyright (C) 2013 - David Goulet <dgoulet@efficios.com>
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

#ifndef SNAPSHOT_H
#define SNAPSHOT_H

#include <limits.h>
#include <stdint.h>

#include <common/common.h>
#include <common/hashtable/hashtable.h>
#include <common/uri.h>

#include "consumer.h"

struct consumer_output;

struct snapshot_output {
	uint32_t id;
	uint64_t max_size;
	/* Number of snapshot taken with that output. */
	uint64_t nb_snapshot;
	char name[NAME_MAX];
	struct consumer_output *consumer;
	int kernel_sockets_copied;
	int ust_sockets_copied;
	/*
	 * Contains the string with "<date>-<time>" for when the snapshot command
	 * is triggered. This is to make sure every streams will use the same time
	 * for the directory output.
	 */
	char datetime[16];

	/* Indexed by ID. */
	struct lttng_ht_node_ulong node;
};

struct snapshot {
	unsigned long next_output_id;
	size_t nb_output;
	/*
	 * Number of snapshot taken for that object. This value is used with a
	 * temporary output of a snapshot record.
	 */
	uint64_t nb_snapshot;
	struct lttng_ht *output_ht;
};

/* Snapshot object. */
struct snapshot *snapshot_alloc(void);
void snapshot_destroy(struct snapshot *obj);
int snapshot_init(struct snapshot *obj);
void snapshot_delete_output(struct snapshot *snapshot,
		struct snapshot_output *output);
void snapshot_add_output(struct snapshot *snapshot,
		struct snapshot_output *output);

/* Snapshot output object. */
struct snapshot_output *snapshot_output_alloc(void);
void snapshot_output_destroy(struct snapshot_output *obj);
int snapshot_output_init(uint64_t max_size, const char *name,
		const char *ctrl_url, const char *data_url,
		struct consumer_output *consumer, struct snapshot_output *output,
		struct snapshot *snapshot);
int snapshot_output_init_with_uri(uint64_t max_size, const char *name,
		struct lttng_uri *uris, size_t nb_uri,
		struct consumer_output *consumer, struct snapshot_output *output,
		struct snapshot *snapshot);
struct snapshot_output *snapshot_find_output_by_id(uint32_t id,
		struct snapshot *snapshot);
struct snapshot_output *snapshot_find_output_by_name(const char *name,
		struct snapshot *snapshot);

#endif /* SNAPSHOT_H */
