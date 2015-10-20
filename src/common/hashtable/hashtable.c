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

#define _LGPL_SOURCE
#include <assert.h>
#include <string.h>
#include <urcu.h>
#include <urcu/compiler.h>

#include <common/common.h>
#include <common/defaults.h>

#include "hashtable.h"
#include "utils.h"

/* seed_lock protects both seed_init and lttng_ht_seed. */
static pthread_mutex_t seed_lock = PTHREAD_MUTEX_INITIALIZER;
static bool seed_init;
unsigned long lttng_ht_seed;

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

/*
 * Return an allocated lttng hashtable.
 */
LTTNG_HIDDEN
struct lttng_ht *lttng_ht_new(unsigned long size, int type)
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

	ht = zmalloc(sizeof(*ht));
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
	assert(ht->ht);

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

	DBG3("Created hashtable size %lu at %p of type %d", size, ht->ht, type);

	return ht;

error:
	return NULL;
}

/*
 * Free a lttng hashtable.
 */
LTTNG_HIDDEN
void lttng_ht_destroy(struct lttng_ht *ht)
{
	int ret;

	ret = cds_lfht_destroy(ht->ht, NULL);
	assert(!ret);
	free(ht);
}

/*
 * Init lttng ht node string.
 */
LTTNG_HIDDEN
void lttng_ht_node_init_str(struct lttng_ht_node_str *node, char *key)
{
	assert(node);

	node->key = key;
	cds_lfht_node_init(&node->node);
}

/*
 * Init lttng ht node unsigned long.
 */
LTTNG_HIDDEN
void lttng_ht_node_init_ulong(struct lttng_ht_node_ulong *node,
		unsigned long key)
{
	assert(node);

	node->key = key;
	cds_lfht_node_init(&node->node);
}

/*
 * Init lttng ht node uint64_t.
 */
LTTNG_HIDDEN
void lttng_ht_node_init_u64(struct lttng_ht_node_u64 *node,
		uint64_t key)
{
	assert(node);

	node->key = key;
	cds_lfht_node_init(&node->node);
}

/*
 * Init lttng ht node with two uint64_t.
 */
LTTNG_HIDDEN
void lttng_ht_node_init_two_u64(struct lttng_ht_node_two_u64 *node,
		uint64_t key1, uint64_t key2)
{
	assert(node);

	node->key.key1 = key1;
	node->key.key2 = key2;
	cds_lfht_node_init(&node->node);
}

/*
 * Free lttng ht node string.
 */
LTTNG_HIDDEN
void lttng_ht_node_free_str(struct lttng_ht_node_str *node)
{
	assert(node);
	free(node);
}

/*
 * Free lttng ht node unsigned long.
 */
LTTNG_HIDDEN
void lttng_ht_node_free_ulong(struct lttng_ht_node_ulong *node)
{
	assert(node);
	free(node);
}

/*
 * Free lttng ht node uint64_t.
 */
LTTNG_HIDDEN
void lttng_ht_node_free_u64(struct lttng_ht_node_u64 *node)
{
	assert(node);
	free(node);
}

/*
 * Free lttng ht node two uint64_t.
 */
LTTNG_HIDDEN
void lttng_ht_node_free_two_u64(struct lttng_ht_node_two_u64 *node)
{
	assert(node);
	free(node);
}

/*
 * Lookup function in hashtable.
 */
LTTNG_HIDDEN
void lttng_ht_lookup(struct lttng_ht *ht, void *key,
		struct lttng_ht_iter *iter)
{
	assert(ht);
	assert(ht->ht);

	cds_lfht_lookup(ht->ht, ht->hash_fct(key, lttng_ht_seed),
			ht->match_fct, key, &iter->iter);
}

/*
 * Add unique string node to hashtable.
 */
LTTNG_HIDDEN
void lttng_ht_add_unique_str(struct lttng_ht *ht,
		struct lttng_ht_node_str *node)
{
	struct cds_lfht_node *node_ptr;
	assert(ht);
	assert(ht->ht);
	assert(node);

	/* RCU read lock protects from ABA. */
	rcu_read_lock();
	node_ptr = cds_lfht_add_unique(ht->ht, ht->hash_fct(node->key, lttng_ht_seed),
			ht->match_fct, node->key, &node->node);
	rcu_read_unlock();
	assert(node_ptr == &node->node);
}

/*
 * Add string node to hashtable.
 */
LTTNG_HIDDEN
void lttng_ht_add_str(struct lttng_ht *ht,
		struct lttng_ht_node_str *node)
{
	assert(ht);
	assert(ht->ht);
	assert(node);

	/* RCU read lock protects from ABA. */
	rcu_read_lock();
	cds_lfht_add(ht->ht, ht->hash_fct(node->key, lttng_ht_seed),
			&node->node);
	rcu_read_unlock();
}

/*
 * Add unsigned long node to hashtable.
 */
LTTNG_HIDDEN
void lttng_ht_add_ulong(struct lttng_ht *ht, struct lttng_ht_node_ulong *node)
{
	assert(ht);
	assert(ht->ht);
	assert(node);

	/* RCU read lock protects from ABA. */
	rcu_read_lock();
	cds_lfht_add(ht->ht, ht->hash_fct((void *) node->key, lttng_ht_seed),
			&node->node);
	rcu_read_unlock();
}

/*
 * Add uint64_t node to hashtable.
 */
LTTNG_HIDDEN
void lttng_ht_add_u64(struct lttng_ht *ht, struct lttng_ht_node_u64 *node)
{
	assert(ht);
	assert(ht->ht);
	assert(node);

	/* RCU read lock protects from ABA. */
	rcu_read_lock();
	cds_lfht_add(ht->ht, ht->hash_fct(&node->key, lttng_ht_seed),
			&node->node);
	rcu_read_unlock();
}

/*
 * Add unique unsigned long node to hashtable.
 */
LTTNG_HIDDEN
void lttng_ht_add_unique_ulong(struct lttng_ht *ht,
		struct lttng_ht_node_ulong *node)
{
	struct cds_lfht_node *node_ptr;
	assert(ht);
	assert(ht->ht);
	assert(node);

	/* RCU read lock protects from ABA. */
	rcu_read_lock();
	node_ptr = cds_lfht_add_unique(ht->ht,
			ht->hash_fct((void *) node->key, lttng_ht_seed), ht->match_fct,
			(void *) node->key, &node->node);
	rcu_read_unlock();
	assert(node_ptr == &node->node);
}

/*
 * Add unique uint64_t node to hashtable.
 */
LTTNG_HIDDEN
void lttng_ht_add_unique_u64(struct lttng_ht *ht,
		struct lttng_ht_node_u64 *node)
{
	struct cds_lfht_node *node_ptr;
	assert(ht);
	assert(ht->ht);
	assert(node);

	/* RCU read lock protects from ABA. */
	rcu_read_lock();
	node_ptr = cds_lfht_add_unique(ht->ht,
			ht->hash_fct(&node->key, lttng_ht_seed), ht->match_fct,
			&node->key, &node->node);
	rcu_read_unlock();
	assert(node_ptr == &node->node);
}

/*
 * Add unique two uint64_t node to hashtable.
 */
LTTNG_HIDDEN
void lttng_ht_add_unique_two_u64(struct lttng_ht *ht,
		struct lttng_ht_node_two_u64 *node)
{
	struct cds_lfht_node *node_ptr;
	assert(ht);
	assert(ht->ht);
	assert(node);

	/* RCU read lock protects from ABA. */
	rcu_read_lock();
	node_ptr = cds_lfht_add_unique(ht->ht,
			ht->hash_fct((void *) &node->key, lttng_ht_seed), ht->match_fct,
			(void *) &node->key, &node->node);
	rcu_read_unlock();
	assert(node_ptr == &node->node);
}

/*
 * Add replace unsigned long node to hashtable.
 */
LTTNG_HIDDEN
struct lttng_ht_node_ulong *lttng_ht_add_replace_ulong(struct lttng_ht *ht,
		struct lttng_ht_node_ulong *node)
{
	struct cds_lfht_node *node_ptr;
	assert(ht);
	assert(ht->ht);
	assert(node);

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
	assert(node_ptr == &node->node);
}

/*
 * Add replace unsigned long node to hashtable.
 */
LTTNG_HIDDEN
struct lttng_ht_node_u64 *lttng_ht_add_replace_u64(struct lttng_ht *ht,
		struct lttng_ht_node_u64 *node)
{
	struct cds_lfht_node *node_ptr;
	assert(ht);
	assert(ht->ht);
	assert(node);

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
	assert(node_ptr == &node->node);
}

/*
 * Delete node from hashtable.
 */
LTTNG_HIDDEN
int lttng_ht_del(struct lttng_ht *ht, struct lttng_ht_iter *iter)
{
	int ret;

	assert(ht);
	assert(ht->ht);
	assert(iter);

	/* RCU read lock protects from ABA. */
	rcu_read_lock();
	ret = cds_lfht_del(ht->ht, iter->iter.node);
	rcu_read_unlock();
	return ret;
}

/*
 * Get first node in the hashtable.
 */
LTTNG_HIDDEN
void lttng_ht_get_first(struct lttng_ht *ht, struct lttng_ht_iter *iter)
{
	assert(ht);
	assert(ht->ht);
	assert(iter);

	cds_lfht_first(ht->ht, &iter->iter);
}

/*
 * Get next node in the hashtable.
 */
LTTNG_HIDDEN
void lttng_ht_get_next(struct lttng_ht *ht, struct lttng_ht_iter *iter)
{
	assert(ht);
	assert(ht->ht);
	assert(iter);

	cds_lfht_next(ht->ht, &iter->iter);
}

/*
 * Return the number of nodes in the hashtable.
 */
LTTNG_HIDDEN
unsigned long lttng_ht_get_count(struct lttng_ht *ht)
{
	long scb, sca;
	unsigned long count;

	assert(ht);
	assert(ht->ht);

	/* RCU read lock protects from ABA and allows RCU traversal. */
	rcu_read_lock();
	cds_lfht_count_nodes(ht->ht, &scb, &count, &sca);
	rcu_read_unlock();

	return count;
}

/*
 * Return lttng ht string node from iterator.
 */
LTTNG_HIDDEN
struct lttng_ht_node_str *lttng_ht_iter_get_node_str(
		struct lttng_ht_iter *iter)
{
	struct cds_lfht_node *node;

	assert(iter);
	node = cds_lfht_iter_get_node(&iter->iter);
	if (!node) {
		return NULL;
	}
	return caa_container_of(node, struct lttng_ht_node_str, node);
}

/*
 * Return lttng ht unsigned long node from iterator.
 */
LTTNG_HIDDEN
struct lttng_ht_node_ulong *lttng_ht_iter_get_node_ulong(
		struct lttng_ht_iter *iter)
{
	struct cds_lfht_node *node;

	assert(iter);
	node = cds_lfht_iter_get_node(&iter->iter);
	if (!node) {
		return NULL;
	}
	return caa_container_of(node, struct lttng_ht_node_ulong, node);
}

/*
 * Return lttng ht unsigned long node from iterator.
 */
LTTNG_HIDDEN
struct lttng_ht_node_u64 *lttng_ht_iter_get_node_u64(
		struct lttng_ht_iter *iter)
{
	struct cds_lfht_node *node;

	assert(iter);
	node = cds_lfht_iter_get_node(&iter->iter);
	if (!node) {
		return NULL;
	}
	return caa_container_of(node, struct lttng_ht_node_u64, node);
}

/*
 * Return lttng ht stream and index id node from iterator.
 */
LTTNG_HIDDEN
struct lttng_ht_node_two_u64 *lttng_ht_iter_get_node_two_u64(
		struct lttng_ht_iter *iter)
{
	struct cds_lfht_node *node;

	assert(iter);
	node = cds_lfht_iter_get_node(&iter->iter);
	if (!node) {
		return NULL;
	}
	return caa_container_of(node, struct lttng_ht_node_two_u64, node);
}
