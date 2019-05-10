/*
 * Copyright (C) 2019 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License, version 2.1 only,
 * as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
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
#define MAX_INT_DEC_LEN(val)       ((3 * sizeof(val)) + 2)

#endif /* _STRING_UTILS_FORMAT_H */
