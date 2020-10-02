/*
 * Copyright (C) 2019 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
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
 * Alias used for communication structures. If the layout of an LTTNG_OPTIONAL
 * is changed, the original layout should still be used for communication
 * purposes.
 *
 * LTTNG_OPTIONAL_COMM should be combined with the LTTNG_PACKED macro when
 * used for IPC / network communication.
 */
#define LTTNG_OPTIONAL_COMM LTTNG_OPTIONAL

/*
 * This macro is available as a 'convenience' to allow sites that assume
 * an optional value is set to assert() that it is set when accessing it.
 *
 * Since this returns the 'optional' by value, it is not suitable for all
 * wrapped optional types. It is meant to be used with PODs.
 */
#define LTTNG_OPTIONAL_GET(optional)			\
	({						\
		assert((optional).is_set);		\
		(optional).value;			\
	})

/*
 * This macro is available as a 'convenience' to allow sites that assume
 * an optional value is set to assert() that it is set when fecthing the
 * underlying value's address.
 */
#define LTTNG_OPTIONAL_GET_PTR(optional)			\
	({						\
		assert((optional).is_set);		\
		&(optional).value;			\
	})

/*
 * Initialize an optional field as unset.
 *
 * The wrapped field is set to the value it would gave if it had static storage
 * duration.
 */
#define LTTNG_OPTIONAL_INIT_UNSET { .is_set = 0 }

/*
 * Initialize an optional field as 'set' with a given value.
 */
#define LTTNG_OPTIONAL_INIT_VALUE(val) { .value = val, .is_set = 1 }

/* Set the value of an optional field. */
#define LTTNG_OPTIONAL_SET(field_ptr, val)	\
	do {					\
		(field_ptr)->value = (val);	\
		(field_ptr)->is_set = 1;	\
	} while (0)

/* Put an optional field in the "unset" (NULL-ed) state. */
#define LTTNG_OPTIONAL_UNSET(field_ptr)		\
	do {					\
		(field_ptr)->is_set = 0;	\
	} while (0)

#endif /* LTTNG_OPTIONAL_H */
