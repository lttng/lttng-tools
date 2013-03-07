/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _LTT_HT_H
#define _LTT_HT_H

#include <urcu.h>
#include <stdint.h>

#include "rculfhash.h"
#include "rculfhash-internal.h"

extern unsigned long lttng_ht_seed;

typedef unsigned long (*hash_fct)(void *_key, unsigned long seed);
typedef cds_lfht_match_fct hash_match_fct;

enum lttng_ht_type {
	LTTNG_HT_TYPE_STRING,
	LTTNG_HT_TYPE_ULONG,
	LTTNG_HT_TYPE_U64,
};

struct lttng_ht {
	struct cds_lfht *ht;
	cds_lfht_match_fct match_fct;
	hash_fct hash_fct;
};

struct lttng_ht_iter {
	struct cds_lfht_iter iter;
};

struct lttng_ht_node_str {
	char *key;
	struct cds_lfht_node node;
	struct rcu_head head;
};

struct lttng_ht_node_ulong {
	unsigned long key;
	struct cds_lfht_node node;
	struct rcu_head head;
};

struct lttng_ht_node_u64 {
	uint64_t key;
	struct cds_lfht_node node;
	struct rcu_head head;
};

/* Hashtable new and destroy */
extern struct lttng_ht *lttng_ht_new(unsigned long size, int type);
extern void lttng_ht_destroy(struct lttng_ht *ht);

/* Specialized node init and free functions */
extern void lttng_ht_node_init_str(struct lttng_ht_node_str *node, char *key);
extern void lttng_ht_node_init_ulong(struct lttng_ht_node_ulong *node,
		unsigned long key);
extern void lttng_ht_node_init_u64(struct lttng_ht_node_u64 *node,
		uint64_t key);
extern void lttng_ht_node_free_str(struct lttng_ht_node_str *node);
extern void lttng_ht_node_free_ulong(struct lttng_ht_node_ulong *node);
extern void lttng_ht_node_free_u64(struct lttng_ht_node_u64 *node);

extern void lttng_ht_lookup(struct lttng_ht *ht, void *key,
		struct lttng_ht_iter *iter);

/* Specialized add unique functions */
extern void lttng_ht_add_unique_str(struct lttng_ht *ht,
		struct lttng_ht_node_str *node);
extern void lttng_ht_add_unique_ulong(struct lttng_ht *ht,
		struct lttng_ht_node_ulong *node);
extern void lttng_ht_add_unique_u64(struct lttng_ht *ht,
		struct lttng_ht_node_u64 *node);
extern struct lttng_ht_node_ulong *lttng_ht_add_replace_ulong(
		struct lttng_ht *ht, struct lttng_ht_node_ulong *node);
extern struct lttng_ht_node_u64 *lttng_ht_add_replace_u64(
		struct lttng_ht *ht, struct lttng_ht_node_u64 *node);
extern void lttng_ht_add_ulong(struct lttng_ht *ht,
		struct lttng_ht_node_ulong *node);
extern void lttng_ht_add_u64(struct lttng_ht *ht,
		struct lttng_ht_node_u64 *node);

extern int lttng_ht_del(struct lttng_ht *ht, struct lttng_ht_iter *iter);

extern void lttng_ht_get_first(struct lttng_ht *ht,
		struct lttng_ht_iter *iter);
extern void lttng_ht_get_next(struct lttng_ht *ht, struct lttng_ht_iter *iter);

extern unsigned long lttng_ht_get_count(struct lttng_ht *ht);

extern struct lttng_ht_node_str *lttng_ht_iter_get_node_str(
		struct lttng_ht_iter *iter);
extern struct lttng_ht_node_ulong *lttng_ht_iter_get_node_ulong(
		struct lttng_ht_iter *iter);
extern struct lttng_ht_node_u64 *lttng_ht_iter_get_node_u64(
		struct lttng_ht_iter *iter);

#endif /* _LTT_HT_H */
