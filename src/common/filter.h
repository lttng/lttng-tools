/*
 * Copyright (C) 2016 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
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
		struct lttng_bytecode *bytecode);

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
