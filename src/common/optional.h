/*
 * Copyright (C) 2019 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
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

#ifndef LTTNG_OPTIONAL_H
#define LTTNG_OPTIONAL_H

#include <stdint.h>
#include <assert.h>

/*
 * Define wrapper structure representing an optional value.
 *
 * This macro defines an "is_set" boolean field that must be checked
 * when accessing the optional field. This "is_set" field provides
 * the semantics that would be expected of a typical "raw pointer" field
 * which would be checked for NULL.
 *
 * Prefer using this macro where "special" values would be used, e.g.
 * -1ULL for uint64_t types.
 *
 * LTTNG_OPTIONAL should be combined with the LTTNG_PACKED macro when
 * used for IPC / network communication.
 *
 * Declaration example:
 * struct my_struct {
 * 	int a;
 * 	LTTNG_OPTIONAL(int, b);
 * };
 *
 * Usage example:
 * struct my_struct foo = LTTNG_OPTIONAL_INIT;
 *
 * LTTNG_OPTIONAL_SET(&foo.b, 42);
 * if (foo.b.is_set) {
 * 	printf("%d", foo.b.value);
 * }
 *
 * LTTNG_OPTIONAL_UNSET(&foo.b);
 */
#define LTTNG_OPTIONAL(type) \
	struct {             \
		uint8_t is_set; \
		type value;  \
	}

/*
 * This macro is available as a 'convenience' to allow sites that assume
 * an optional value is set to assert() that it is set when accessing it.
 *
 * Since this returns the 'optional' by value, it is not suitable for all
 * wrapped optional types. It is meant to be used with PODs.
 */
#define LTTNG_OPTIONAL_GET(optional)			\
        ({						\
		assert(optional.is_set);		\
		optional.value;				\
	})

/*
 * Initialize an optional field.
 *
 * The wrapped field is set to the value it would gave if it had static storage
 * duration.
 */
#define LTTNG_OPTIONAL_INIT { .is_set = 0 }

/* Set the value of an optional field. */
#define LTTNG_OPTIONAL_SET(field_ptr, val) \
	(field_ptr)->value = val;	   \
	(field_ptr)->is_set = 1;

/* Put an optional field in the "unset" (NULL-ed) state. */
#define LTTNG_OPTIONAL_UNSET(field_ptr)    \
	(field_ptr)->is_set = 0;

#endif /* LTTNG_OPTIONAL_H */
