/*
 * Copyright (C) 2011 EfficiOS Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include <string.h>
#include <urcu.h>
#include <urcu/compiler.h>

#include <common/common.hpp>
#include <common/defaults.hpp>

#include "hashtable.hpp"
#include "utils.hpp"

/* seed_lock protects both seed_init and lttng_ht_seed. */
static pthread_mutex_t seed_lock = PTHREAD_MUTEX_INITIALIZER;
static bool seed_init;

static unsigned long min_hash_alloc_size = 1;
static unsigned long max_hash_buckets_size = 0;

/*
 * Getter/lookup functions need to be called with RCU read-side lock
 * held. However, modification functions (add, add_unique, replace, del)
 * take the RCU lock internally, so it does not matter whether the
 * caller hold the RCU lock or not.
 */

/*
 * Match function for string node.
 */
static int match_str(struct cds_lfht_node *node, const void *key)
{
	struct lttng_ht_node_str *match_node =
		caa_container_of(node, struct lttng_ht_node_str, node);

	return hash_match_key_str(match_node->key, (void *) key);
}

/*
 * Match function for ulong node.
 */
static int match_ulong(struct cds_lfht_node *node, const void *key)
{
	struct lttng_ht_node_ulong *match_node =
		caa_container_of(node, struct lttng_ht_node_ulong, node);

	return hash_match_key_ulong((void *) match_node->key, (void *) key);
}

/*
 * Match function for u64 node.
 */
static int match_u64(struct cds_lfht_node *node, const void *key)
{
	struct lttng_ht_node_u64 *match_node =
		caa_container_of(node, struct lttng_ht_node_u64, node);

	return hash_match_key_u64(&match_node->key, (void *) key);
}

/*
 * Match function for two uint64_t node.
 */
static int match_two_u64(struct cds_lfht_node *node, const void *key)
{
	struct lttng_ht_node_two_u64 *match_node =
		caa_container_of(node, struct lttng_ht_node_two_u64, node);

	return hash_match_key_two_u64((void *) &match_node->key, (void *) key);
}

static inline
const char *lttng_ht_type_str(enum lttng_ht_type type)
{
	switch (type) {
	case LTTNG_HT_TYPE_STRING:
		return "STRING";
	case LTTNG_HT_TYPE_ULONG:
		return "ULONG";
	case LTTNG_HT_TYPE_U64:
		return "U64";
	case LTTNG_HT_TYPE_TWO_U64:
		return "TWO_U64";
	default:
		ERR("Unknown lttng hashtable type %d", type);
		abort();
	}
}

/*
 * Return an allocated lttng hashtable.
 */
struct lttng_ht *lttng_ht_new(unsigned long size, lttng_ht_type type)
{
	struct lttng_ht *ht;

	/* Test size */
	if (!size)
		size = DEFAULT_HT_SIZE;

	pthread_mutex_lock(&seed_lock);
	if (!seed_init) {
		lttng_ht_seed = (unsigned long) time(NULL);
		seed_init = true;
	}
	pthread_mutex_unlock(&seed_lock);

	ht = zmalloc<lttng_ht>();
	if (ht == NULL) {
		PERROR("zmalloc lttng_ht");
		goto error;
	}

	ht->ht = cds_lfht_new(size, min_hash_alloc_size, max_hash_buckets_size,
			CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING, NULL);
	/*
	 * There is already an assert in the RCU hashtable code so if the ht is
	 * NULL here there is a *huge* problem.
	 */
	LTTNG_ASSERT(ht->ht);

	switch (type) {
	case LTTNG_HT_TYPE_STRING:
		ht->match_fct = match_str;
		ht->hash_fct = hash_key_str;
		break;
	case LTTNG_HT_TYPE_ULONG:
		ht->match_fct = match_ulong;
		ht->hash_fct = hash_key_ulong;
		break;
	case LTTNG_HT_TYPE_U64:
		ht->match_fct = match_u64;
		ht->hash_fct = hash_key_u64;
		break;
	case LTTNG_HT_TYPE_TWO_U64:
		ht->match_fct = match_two_u64;
		ht->hash_fct = hash_key_two_u64;
		break;
	default:
		ERR("Unknown lttng hashtable type %d", type);
		lttng_ht_destroy(ht);
		goto error;
	}

	DBG3("Created hashtable size %lu at %p of type %s", size, ht->ht,
			lttng_ht_type_str(type));

	return ht;

error:
	return NULL;
}

/*
 * Free a lttng hashtable.
 */
void lttng_ht_destroy(struct lttng_ht *ht)
{
	int ret;

	ret = cds_lfht_destroy(ht->ht, NULL);
	LTTNG_ASSERT(!ret);
	free(ht);
}

/*
 * Init lttng ht node string.
 */
void lttng_ht_node_init_str(struct lttng_ht_node_str *node, char *key)
{
	LTTNG_ASSERT(node);

	node->key = key;
	cds_lfht_node_init(&node->node);
}

/*
 * Init lttng ht node unsigned long.
 */
void lttng_ht_node_init_ulong(struct lttng_ht_node_ulong *node,
		unsigned long key)
{
	LTTNG_ASSERT(node);

	node->key = key;
	cds_lfht_node_init(&node->node);
}

/*
 * Init lttng ht node uint64_t.
 */
void lttng_ht_node_init_u64(struct lttng_ht_node_u64 *node,
		uint64_t key)
{
	LTTNG_ASSERT(node);

	node->key = key;
	cds_lfht_node_init(&node->node);
}

/*
 * Init lttng ht node with two uint64_t.
 */
void lttng_ht_node_init_two_u64(struct lttng_ht_node_two_u64 *node,
		uint64_t key1, uint64_t key2)
{
	LTTNG_ASSERT(node);

	node->key.key1 = key1;
	node->key.key2 = key2;
	cds_lfht_node_init(&node->node);
}

/*
 * Free lttng ht node string.
 */
void lttng_ht_node_free_str(struct lttng_ht_node_str *node)
{
	LTTNG_ASSERT(node);
	free(node);
}

/*
 * Free lttng ht node unsigned long.
 */
void lttng_ht_node_free_ulong(struct lttng_ht_node_ulong *node)
{
	LTTNG_ASSERT(node);
	free(node);
}

/*
 * Free lttng ht node uint64_t.
 */
void lttng_ht_node_free_u64(struct lttng_ht_node_u64 *node)
{
	LTTNG_ASSERT(node);
	free(node);
}

/*
 * Free lttng ht node two uint64_t.
 */
void lttng_ht_node_free_two_u64(struct lttng_ht_node_two_u64 *node)
{
	LTTNG_ASSERT(node);
	free(node);
}

/*
 * Lookup function in hashtable.
 */
void lttng_ht_lookup(struct lttng_ht *ht, const void *key,
		struct lttng_ht_iter *iter)
{
	LTTNG_ASSERT(ht);
	LTTNG_ASSERT(ht->ht);

	cds_lfht_lookup(ht->ht, ht->hash_fct(key, lttng_ht_seed),
			ht->match_fct, key, &iter->iter);
}

/*
 * Add unique string node to hashtable.
 */
void lttng_ht_add_unique_str(struct lttng_ht *ht,
		struct lttng_ht_node_str *node)
{
	struct cds_lfht_node *node_ptr;
	LTTNG_ASSERT(ht);
	LTTNG_ASSERT(ht->ht);
	LTTNG_ASSERT(node);

	/* RCU read lock protects from ABA. */
	rcu_read_lock();
	node_ptr = cds_lfht_add_unique(ht->ht, ht->hash_fct(node->key, lttng_ht_seed),
			ht->match_fct, node->key, &node->node);
	rcu_read_unlock();
	LTTNG_ASSERT(node_ptr == &node->node);
}

/*
 * Add string node to hashtable.
 */
void lttng_ht_add_str(struct lttng_ht *ht,
		struct lttng_ht_node_str *node)
{
	LTTNG_ASSERT(ht);
	LTTNG_ASSERT(ht->ht);
	LTTNG_ASSERT(node);

	/* RCU read lock protects from ABA. */
	rcu_read_lock();
	cds_lfht_add(ht->ht, ht->hash_fct(node->key, lttng_ht_seed),
			&node->node);
	rcu_read_unlock();
}

/*
 * Add unsigned long node to hashtable.
 */
void lttng_ht_add_ulong(struct lttng_ht *ht, struct lttng_ht_node_ulong *node)
{
	LTTNG_ASSERT(ht);
	LTTNG_ASSERT(ht->ht);
	LTTNG_ASSERT(node);

	/* RCU read lock protects from ABA. */
	rcu_read_lock();
	cds_lfht_add(ht->ht, ht->hash_fct((void *) node->key, lttng_ht_seed),
			&node->node);
	rcu_read_unlock();
}

/*
 * Add uint64_t node to hashtable.
 */
void lttng_ht_add_u64(struct lttng_ht *ht, struct lttng_ht_node_u64 *node)
{
	LTTNG_ASSERT(ht);
	LTTNG_ASSERT(ht->ht);
	LTTNG_ASSERT(node);

	/* RCU read lock protects from ABA. */
	rcu_read_lock();
	cds_lfht_add(ht->ht, ht->hash_fct(&node->key, lttng_ht_seed),
			&node->node);
	rcu_read_unlock();
}

/*
 * Add unique unsigned long node to hashtable.
 */
void lttng_ht_add_unique_ulong(struct lttng_ht *ht,
		struct lttng_ht_node_ulong *node)
{
	struct cds_lfht_node *node_ptr;
	LTTNG_ASSERT(ht);
	LTTNG_ASSERT(ht->ht);
	LTTNG_ASSERT(node);

	/* RCU read lock protects from ABA. */
	rcu_read_lock();
	node_ptr = cds_lfht_add_unique(ht->ht,
			ht->hash_fct((void *) node->key, lttng_ht_seed), ht->match_fct,
			(void *) node->key, &node->node);
	rcu_read_unlock();
	LTTNG_ASSERT(node_ptr == &node->node);
}

/*
 * Add unique uint64_t node to hashtable.
 */
void lttng_ht_add_unique_u64(struct lttng_ht *ht,
		struct lttng_ht_node_u64 *node)
{
	struct cds_lfht_node *node_ptr;
	LTTNG_ASSERT(ht);
	LTTNG_ASSERT(ht->ht);
	LTTNG_ASSERT(node);

	/* RCU read lock protects from ABA. */
	rcu_read_lock();
	node_ptr = cds_lfht_add_unique(ht->ht,
			ht->hash_fct(&node->key, lttng_ht_seed), ht->match_fct,
			&node->key, &node->node);
	rcu_read_unlock();
	LTTNG_ASSERT(node_ptr == &node->node);
}

/*
 * Add unique two uint64_t node to hashtable.
 */
void lttng_ht_add_unique_two_u64(struct lttng_ht *ht,
		struct lttng_ht_node_two_u64 *node)
{
	struct cds_lfht_node *node_ptr;
	LTTNG_ASSERT(ht);
	LTTNG_ASSERT(ht->ht);
	LTTNG_ASSERT(node);

	/* RCU read lock protects from ABA. */
	rcu_read_lock();
	node_ptr = cds_lfht_add_unique(ht->ht,
			ht->hash_fct((void *) &node->key, lttng_ht_seed), ht->match_fct,
			(void *) &node->key, &node->node);
	rcu_read_unlock();
	LTTNG_ASSERT(node_ptr == &node->node);
}

/*
 * Add replace unsigned long node to hashtable.
 */
struct lttng_ht_node_ulong *lttng_ht_add_replace_ulong(struct lttng_ht *ht,
		struct lttng_ht_node_ulong *node)
{
	struct cds_lfht_node *node_ptr;
	LTTNG_ASSERT(ht);
	LTTNG_ASSERT(ht->ht);
	LTTNG_ASSERT(node);

	/* RCU read lock protects from ABA. */
	rcu_read_lock();
	node_ptr = cds_lfht_add_replace(ht->ht,
			ht->hash_fct((void *) node->key, lttng_ht_seed), ht->match_fct,
			(void *) node->key, &node->node);
	rcu_read_unlock();
	if (!node_ptr) {
		return NULL;
	} else {
		return caa_container_of(node_ptr, struct lttng_ht_node_ulong, node);
	}
	LTTNG_ASSERT(node_ptr == &node->node);
}

/*
 * Add replace unsigned long node to hashtable.
 */
struct lttng_ht_node_u64 *lttng_ht_add_replace_u64(struct lttng_ht *ht,
		struct lttng_ht_node_u64 *node)
{
	struct cds_lfht_node *node_ptr;
	LTTNG_ASSERT(ht);
	LTTNG_ASSERT(ht->ht);
	LTTNG_ASSERT(node);

	/* RCU read lock protects from ABA. */
	rcu_read_lock();
	node_ptr = cds_lfht_add_replace(ht->ht,
			ht->hash_fct(&node->key, lttng_ht_seed), ht->match_fct,
			&node->key, &node->node);
	rcu_read_unlock();
	if (!node_ptr) {
		return NULL;
	} else {
		return caa_container_of(node_ptr, struct lttng_ht_node_u64, node);
	}
	LTTNG_ASSERT(node_ptr == &node->node);
}

/*
 * Delete node from hashtable.
 */
int lttng_ht_del(struct lttng_ht *ht, struct lttng_ht_iter *iter)
{
	int ret;

	LTTNG_ASSERT(ht);
	LTTNG_ASSERT(ht->ht);
	LTTNG_ASSERT(iter);

	/* RCU read lock protects from ABA. */
	rcu_read_lock();
	ret = cds_lfht_del(ht->ht, iter->iter.node);
	rcu_read_unlock();
	return ret;
}

/*
 * Get first node in the hashtable.
 */
void lttng_ht_get_first(struct lttng_ht *ht, struct lttng_ht_iter *iter)
{
	LTTNG_ASSERT(ht);
	LTTNG_ASSERT(ht->ht);
	LTTNG_ASSERT(iter);

	cds_lfht_first(ht->ht, &iter->iter);
}

/*
 * Get next node in the hashtable.
 */
void lttng_ht_get_next(struct lttng_ht *ht, struct lttng_ht_iter *iter)
{
	LTTNG_ASSERT(ht);
	LTTNG_ASSERT(ht->ht);
	LTTNG_ASSERT(iter);

	cds_lfht_next(ht->ht, &iter->iter);
}

/*
 * Return the number of nodes in the hashtable.
 */
unsigned long lttng_ht_get_count(struct lttng_ht *ht)
{
	long scb, sca;
	unsigned long count;

	LTTNG_ASSERT(ht);
	LTTNG_ASSERT(ht->ht);

	/* RCU read lock protects from ABA and allows RCU traversal. */
	rcu_read_lock();
	cds_lfht_count_nodes(ht->ht, &scb, &count, &sca);
	rcu_read_unlock();

	return count;
}

/*
 * Return lttng ht string node from iterator.
 */
struct lttng_ht_node_str *lttng_ht_iter_get_node_str(
		struct lttng_ht_iter *iter)
{
	struct cds_lfht_node *node;

	LTTNG_ASSERT(iter);
	node = cds_lfht_iter_get_node(&iter->iter);
	if (!node) {
		return NULL;
	}
	return caa_container_of(node, struct lttng_ht_node_str, node);
}

/*
 * Return lttng ht unsigned long node from iterator.
 */
struct lttng_ht_node_ulong *lttng_ht_iter_get_node_ulong(
		struct lttng_ht_iter *iter)
{
	struct cds_lfht_node *node;

	LTTNG_ASSERT(iter);
	node = cds_lfht_iter_get_node(&iter->iter);
	if (!node) {
		return NULL;
	}
	return caa_container_of(node, struct lttng_ht_node_ulong, node);
}

/*
 * Return lttng ht unsigned long node from iterator.
 */
struct lttng_ht_node_u64 *lttng_ht_iter_get_node_u64(
		struct lttng_ht_iter *iter)
{
	struct cds_lfht_node *node;

	LTTNG_ASSERT(iter);
	node = cds_lfht_iter_get_node(&iter->iter);
	if (!node) {
		return NULL;
	}
	return caa_container_of(node, struct lttng_ht_node_u64, node);
}

/*
 * Return lttng ht stream and index id node from iterator.
 */
struct lttng_ht_node_two_u64 *lttng_ht_iter_get_node_two_u64(
		struct lttng_ht_iter *iter)
{
	struct cds_lfht_node *node;

	LTTNG_ASSERT(iter);
	node = cds_lfht_iter_get_node(&iter->iter);
	if (!node) {
		return NULL;
	}
	return caa_container_of(node, struct lttng_ht_node_two_u64, node);
}
