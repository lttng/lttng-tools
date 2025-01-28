/*
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef _LTT_HT_UTILS_H
#define _LTT_HT_UTILS_H

#include <stdint.h>

unsigned long hash_key_ulong(const void *_key, unsigned long seed);
unsigned long hash_key_u64(const void *_key, unsigned long seed);
unsigned long hash_key_str(const void *key, unsigned long seed);
unsigned long hash_key_two_u64(const void *key, unsigned long seed);
int hash_match_key_ulong(const void *key1, const void *key2);
int hash_match_key_u64(const void *key1, const void *key2);
int hash_match_key_str(const void *key1, const void *key2);
int hash_match_key_two_u64(const void *key1, const void *key2);

#endif /* _LTT_HT_UTILS_H */
