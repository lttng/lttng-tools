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

#ifndef _LTT_HASHTABLE_H 
#define _LTT_HASHTABLE_H

#include <urcu.h>
#include "../hashtable/rculfhash.h"

struct cds_lfht *hashtable_new(unsigned long size);
struct cds_lfht *hashtable_new_str(unsigned long size);

struct cds_lfht_node *hashtable_iter_get_node(struct cds_lfht_iter *iter);
struct cds_lfht_node *hashtable_lookup(struct cds_lfht *ht, void *key,
		size_t key_len, struct cds_lfht_iter *iter);

void hashtable_get_first(struct cds_lfht *ht, struct cds_lfht_iter *iter);
void hashtable_get_next(struct cds_lfht *ht, struct cds_lfht_iter *iter);
void hashtable_add_unique(struct cds_lfht *ht, struct cds_lfht_node *node);
void hashtable_node_init(struct cds_lfht_node *node,
		void *key, size_t key_len);

int hashtable_del(struct cds_lfht *ht, struct cds_lfht_iter *iter);
unsigned long hashtable_get_count(struct cds_lfht *ht);
int hashtable_destroy(struct cds_lfht *ht);

#endif /* _LTT_HASHTABLE_H */
