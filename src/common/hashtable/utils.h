/*
 * Copyright (C) 2011 David Goulet <david.goulet@polymtl.ca>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef _LTT_HT_UTILS_H
#define _LTT_HT_UTILS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

unsigned long hash_key_ulong(const void *_key, unsigned long seed);
unsigned long hash_key_u64(const void *_key, unsigned long seed);
unsigned long hash_key_str(const void *key, unsigned long seed);
unsigned long hash_key_two_u64(const void *key, unsigned long seed);
int hash_match_key_ulong(const void *key1, const void *key2);
int hash_match_key_u64(const void *key1, const void *key2);
int hash_match_key_str(const void *key1, const void *key2);
int hash_match_key_two_u64(const void *key1, const void *key2);

#ifdef __cplusplus
}
#endif

#endif /* _LTT_HT_UTILS_H */
