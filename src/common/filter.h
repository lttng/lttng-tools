/*
 * Copyright 2016 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef LTTNG_COMMON_FILTER_H
#define LTTNG_COMMON_FILTER_H

#include <common/sessiond-comm/sessiond-comm.h>

struct bytecode_symbol_iterator;

/*
 * Create an iterator on a bytecode's symbols. The iterator points to the
 * first element after creation.
 */
LTTNG_HIDDEN
struct bytecode_symbol_iterator *bytecode_symbol_iterator_create(
		struct lttng_filter_bytecode *bytecode);

/*
 * Advance iterator of one element.
 *
 * Returns 0 if a next element exists or a negative value at the end.
 */
LTTNG_HIDDEN
int bytecode_symbol_iterator_next(struct bytecode_symbol_iterator *it);

LTTNG_HIDDEN
int bytecode_symbol_iterator_get_type(struct bytecode_symbol_iterator *it);

LTTNG_HIDDEN
const char *bytecode_symbol_iterator_get_name(
		struct bytecode_symbol_iterator *it);

LTTNG_HIDDEN
void bytecode_symbol_iterator_destroy(struct bytecode_symbol_iterator *it);

#endif /* LTTNG_COMMON_FILTER_H */
