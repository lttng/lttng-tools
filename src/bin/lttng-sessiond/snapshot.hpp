/*
 * Copyright (C) 2013 David Goulet <dgoulet@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef SNAPSHOT_H
#define SNAPSHOT_H

#include "consumer.hpp"

#include <common/common.hpp>
#include <common/hashtable/hashtable.hpp>
#include <common/uri.hpp>

#include <limits.h>
#include <stdint.h>

struct consumer_output;

struct snapshot_output {
	uint32_t id = 0;
	uint64_t max_size = 0;
	/* Number of snapshot taken with that output. */
	uint64_t nb_snapshot = 0;
	char name[NAME_MAX] = {};
	struct consumer_output *consumer = nullptr;
	bool kernel_sockets_copied = false;
	bool ust_sockets_copied = false;
	/*
	 * Contains the string with "<date>-<time>" for when the snapshot command
	 * is triggered. This is to make sure every streams will use the same time
	 * for the directory output.
	 */
	char datetime[16] = {};

	/* Indexed by ID. */
	struct lttng_ht_node_ulong node = {};
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
struct snapshot *snapshot_alloc();
void snapshot_destroy(struct snapshot *obj);
int snapshot_init(struct snapshot *obj);
void snapshot_delete_output(struct snapshot *snapshot, struct snapshot_output *output);
void snapshot_add_output(struct snapshot *snapshot, struct snapshot_output *output);

/* Snapshot output object. */
struct snapshot_output *snapshot_output_alloc();
void snapshot_output_destroy(struct snapshot_output *obj);

struct snapshot_output *snapshot_find_output_by_id(uint32_t id, struct snapshot *snapshot);
struct snapshot_output *snapshot_find_output_by_name(const char *name, struct snapshot *snapshot);

#endif /* SNAPSHOT_H */
