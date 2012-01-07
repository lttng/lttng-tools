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

#ifndef _LTT_HASH_H
#define _LTT_HASH_H

unsigned long hash_key(void *_key, size_t length, unsigned long seed);

unsigned long hash_key_str(void *_key, size_t length, unsigned long seed);

unsigned long hash_compare_key(void *key1, size_t key1_len,
		void *key2, size_t key2_len);

unsigned long hash_compare_key_str(void *key1, size_t key1_len,
		void *key2, size_t key2_len);

#endif /* _LTT_HASH_H */
