/*
 * Copyright (C) 2019 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef _STRING_UTILS_FORMAT_H
#define _STRING_UTILS_FORMAT_H

/*
 * Maximal length of `val` when formatted in decimal.
 *
 * Note that this is an upper bound that can exceed the length
 * required to hold the largest textual value of `val`. Note that this length
 * assumes that no grouping/locale-aware formatting is performed (i.e. using
 * the `'` specifier in POSIX formatting functions).
 */
#define MAX_INT_DEC_LEN(val) ((3 * sizeof(val)) + 2)

#endif /* _STRING_UTILS_FORMAT_H */
