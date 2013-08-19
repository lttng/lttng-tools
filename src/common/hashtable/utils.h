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

#ifndef _LTT_HT_UTILS_H
#define _LTT_HT_UTILS_H

#include <stdint.h>

unsigned long hash_key_ulong(void *_key, unsigned long seed);
unsigned long hash_key_u64(void *_key, unsigned long seed);
unsigned long hash_key_str(void *key, unsigned long seed);
unsigned long hash_key_two_u64(void *key, unsigned long seed);
int hash_match_key_ulong(void *key1, void *key2);
int hash_match_key_u64(void *key1, void *key2);
int hash_match_key_str(void *key1, void *key2);
int hash_match_key_two_u64(void *key1, void *key2);

#endif /* _LTT_HT_UTILS_H */
