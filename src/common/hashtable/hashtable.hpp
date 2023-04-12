/*
 * Copyright (C) 2011 EfficiOS Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef _LTT_HT_H
#define _LTT_HT_H

#include <common/macros.hpp>

#include <lttng/lttng-export.h>

#include <memory>
#include <stdint.h>
#include <urcu.h>
#include <urcu/rculfhash.h>

LTTNG_EXPORT extern unsigned long lttng_ht_seed;

using hash_fct_type = unsigned long (*)(const void *, unsigned long);
using hash_match_fct = cds_lfht_match_fct;

enum lttng_ht_type {
	LTTNG_HT_TYPE_STRING,
	LTTNG_HT_TYPE_ULONG,
	LTTNG_HT_TYPE_U64,
	LTTNG_HT_TYPE_TWO_U64,
};

struct lttng_ht_deleter;

struct lttng_ht {
	using uptr = std::unique_ptr<lttng_ht, lttng_ht_deleter>;
	struct cds_lfht *ht;
	cds_lfht_match_fct match_fct;
	hash_fct_type hash_fct;
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

struct lttng_ht_two_u64 {
	uint64_t key1;
	uint64_t key2;
};

struct lttng_ht_node_two_u64 {
	struct lttng_ht_two_u64 key;
	struct cds_lfht_node node;
	struct rcu_head head;
};

/* Hashtable new and destroy */
struct lttng_ht *lttng_ht_new(unsigned long size, enum lttng_ht_type type);
void lttng_ht_destroy(struct lttng_ht *ht);
struct lttng_ht_deleter {
	void operator()(lttng_ht *ht)
	{
		lttng_ht_destroy(ht);
	};
};

/* Specialized node init and free functions */
void lttng_ht_node_init_str(struct lttng_ht_node_str *node, char *key);
void lttng_ht_node_init_ulong(struct lttng_ht_node_ulong *node, unsigned long key);
void lttng_ht_node_init_u64(struct lttng_ht_node_u64 *node, uint64_t key);
void lttng_ht_node_init_two_u64(struct lttng_ht_node_two_u64 *node, uint64_t key1, uint64_t key2);
void lttng_ht_node_free_str(struct lttng_ht_node_str *node);
void lttng_ht_node_free_ulong(struct lttng_ht_node_ulong *node);
void lttng_ht_node_free_u64(struct lttng_ht_node_u64 *node);
void lttng_ht_node_free_two_u64(struct lttng_ht_node_two_u64 *node);

void lttng_ht_lookup(struct lttng_ht *ht, const void *key, struct lttng_ht_iter *iter);

/* Specialized add unique functions */
void lttng_ht_add_unique_str(struct lttng_ht *ht, struct lttng_ht_node_str *node);
void lttng_ht_add_unique_ulong(struct lttng_ht *ht, struct lttng_ht_node_ulong *node);
void lttng_ht_add_unique_u64(struct lttng_ht *ht, struct lttng_ht_node_u64 *node);
void lttng_ht_add_unique_two_u64(struct lttng_ht *ht, struct lttng_ht_node_two_u64 *node);
struct lttng_ht_node_ulong *lttng_ht_add_replace_ulong(struct lttng_ht *ht,
						       struct lttng_ht_node_ulong *node);
struct lttng_ht_node_u64 *lttng_ht_add_replace_u64(struct lttng_ht *ht,
						   struct lttng_ht_node_u64 *node);
void lttng_ht_add_str(struct lttng_ht *ht, struct lttng_ht_node_str *node);
void lttng_ht_add_ulong(struct lttng_ht *ht, struct lttng_ht_node_ulong *node);
void lttng_ht_add_u64(struct lttng_ht *ht, struct lttng_ht_node_u64 *node);

int lttng_ht_del(struct lttng_ht *ht, struct lttng_ht_iter *iter);

void lttng_ht_get_first(struct lttng_ht *ht, struct lttng_ht_iter *iter);
void lttng_ht_get_next(struct lttng_ht *ht, struct lttng_ht_iter *iter);

unsigned long lttng_ht_get_count(struct lttng_ht *ht);

struct lttng_ht_node_str *lttng_ht_iter_get_node_str(struct lttng_ht_iter *iter);
struct lttng_ht_node_ulong *lttng_ht_iter_get_node_ulong(struct lttng_ht_iter *iter);
struct lttng_ht_node_u64 *lttng_ht_iter_get_node_u64(struct lttng_ht_iter *iter);
struct lttng_ht_node_two_u64 *lttng_ht_iter_get_node_two_u64(struct lttng_ht_iter *iter);

#endif /* _LTT_HT_H */
