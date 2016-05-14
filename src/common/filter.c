/*
 * filter.c
 *
 * LTTng filter bytecode utilities.
 *
 * Copyright 2016 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License, version 2.1 only,
 * as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "filter.h"
#include <stddef.h>

struct bytecode_symbol_iterator {
	/* No ownership of bytecode is taken. */
	char *bytecode;
	size_t offset, len;
};

LTTNG_HIDDEN
struct bytecode_symbol_iterator *bytecode_symbol_iterator_create(
		struct lttng_filter_bytecode *bytecode)
{
	struct bytecode_symbol_iterator *it = NULL;

	if (!bytecode) {
		goto end;
	}

	it = zmalloc(sizeof(*it));
	if (!it) {
		goto end;
	}

	it->bytecode = bytecode->data;
	it->offset = bytecode->reloc_table_offset;
	it->len = bytecode->len;
end:
	return it;
}

LTTNG_HIDDEN
int bytecode_symbol_iterator_next(struct bytecode_symbol_iterator *it)
{
	int ret;
	size_t len;

	if (!it || it->offset >= it->len) {
		ret = -1;
		goto end;
	}

	len = strlen(it->bytecode + it->offset + sizeof(uint16_t)) + 1;
	it->offset += len + sizeof(uint16_t);
	ret = it->offset >= it->len ? -1 : 0;
end:
	return ret;
}

LTTNG_HIDDEN
int bytecode_symbol_iterator_get_type(struct bytecode_symbol_iterator *it)
{
	int ret;

	if (!it) {
		ret = -1;
		goto end;
	}

	ret = *((uint16_t *) (it->bytecode + it->offset));
end:
	return ret;
 }

LTTNG_HIDDEN
const char *bytecode_symbol_iterator_get_name(
		struct bytecode_symbol_iterator *it)
{
	const char *ret = NULL;

	if (!it) {
		goto end;
	}

	ret = it->bytecode + it->offset + sizeof(uint16_t);
end:
	return ret;
}

LTTNG_HIDDEN
void bytecode_symbol_iterator_destroy(struct bytecode_symbol_iterator *it)
{
	free(it);
}
