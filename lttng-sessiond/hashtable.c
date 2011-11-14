/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; only version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#include <urcu.h>

#include <lttng-share.h>

#include "hashtable.h"
#include "../hashtable/rculfhash.h"
#include "../hashtable/hash.h"

struct cds_lfht *hashtable_new(unsigned long size)
{
	if (size == 0) {
		size = DEFAULT_HT_SIZE;
	}

	return cds_lfht_new(hash_key, hash_compare_key, 0x42UL,
			size, size, CDS_LFHT_AUTO_RESIZE, NULL);
}

struct cds_lfht *hashtable_new_str(unsigned long size)
{
	if (size == 0) {
		size = DEFAULT_HT_SIZE;
	}

	return cds_lfht_new(hash_key_str, hash_compare_key_str, 0x42UL,
			size, size, CDS_LFHT_AUTO_RESIZE, NULL);
}

struct cds_lfht_node *hashtable_iter_get_node(struct cds_lfht_iter *iter)
{
	/* Safety net */
	if (iter == NULL) {
		return NULL;
	}

	return cds_lfht_iter_get_node(iter);
}

struct cds_lfht_node *hashtable_lookup(struct cds_lfht *ht, void *key,
		size_t key_len, struct cds_lfht_iter *iter)
{
	/* Safety net */
	if (ht == NULL || iter == NULL || key == NULL) {
		return NULL;
	}

	cds_lfht_lookup(ht, key, key_len, iter);

	return hashtable_iter_get_node(iter);
}

void hashtable_get_first(struct cds_lfht *ht, struct cds_lfht_iter *iter)
{
	cds_lfht_first(ht, iter);
}

void hashtable_get_next(struct cds_lfht *ht, struct cds_lfht_iter *iter)
{
	cds_lfht_next(ht, iter);
}

void hashtable_add_unique(struct cds_lfht *ht, struct cds_lfht_node *node)
{
	cds_lfht_add_unique(ht, node);
}

void hashtable_node_init(struct cds_lfht_node *node, void *key,
		size_t key_len)
{
	cds_lfht_node_init(node, key, key_len);
}

int hashtable_del(struct cds_lfht *ht, struct cds_lfht_iter *iter)
{
	/* Safety net */
	if (ht == NULL || iter == NULL) {
		return -1;
	}

	return cds_lfht_del(ht, iter);
}

unsigned long hashtable_get_count(struct cds_lfht *ht)
{
	long ab, aa;
	unsigned long count, removed;

	cds_lfht_count_nodes(ht, &ab, &count, &removed, &aa);

	return count;
}

int hashtable_destroy(struct cds_lfht *ht)
{
	return cds_lfht_destroy(ht, NULL);
}
