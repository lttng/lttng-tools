/*
 * Copyright (C) 2020 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_KERNEL_PROBE_H
#define LTTNG_KERNEL_PROBE_H

#include <lttng/lttng-export.h>

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct lttng_kernel_probe_location;

enum lttng_kernel_probe_location_status {
	LTTNG_KERNEL_PROBE_LOCATION_STATUS_OK = 0,
	/* Invalid parameters provided. */
	LTTNG_KERNEL_PROBE_LOCATION_STATUS_INVALID = -1,
};

enum lttng_kernel_probe_location_type {
	LTTNG_KERNEL_PROBE_LOCATION_TYPE_UNKNOWN = -1,
	/* Location derived from a symbol and an offset. */
	LTTNG_KERNEL_PROBE_LOCATION_TYPE_SYMBOL_OFFSET = 0,
	/* Location derived from an address. */
	LTTNG_KERNEL_PROBE_LOCATION_TYPE_ADDRESS = 1,
};

/*
 * Get the type of the kernel probe location.
 */
LTTNG_EXPORT extern enum lttng_kernel_probe_location_type
lttng_kernel_probe_location_get_type(const struct lttng_kernel_probe_location *location);

/*
 * Destroy the kernel probe location.
 */
LTTNG_EXPORT extern void
lttng_kernel_probe_location_destroy(struct lttng_kernel_probe_location *location);

/*
 * Create a symbol derived probe location.
 * On failure, NULL is returned.
 */
LTTNG_EXPORT extern struct lttng_kernel_probe_location *
lttng_kernel_probe_location_symbol_create(const char *symbol_name, uint64_t offset);

/*
 * Get the symbol name of a symbol derived probe location.
 */
LTTNG_EXPORT extern const char *
lttng_kernel_probe_location_symbol_get_name(const struct lttng_kernel_probe_location *location);

/*
 * Get the offset of a symbol derived location.
 */
LTTNG_EXPORT extern enum lttng_kernel_probe_location_status
lttng_kernel_probe_location_symbol_get_offset(const struct lttng_kernel_probe_location *location,
					      uint64_t *offset);

/*
 * Create an address derived probe location.
 * On failure, NULL is returned.
 */
LTTNG_EXPORT extern struct lttng_kernel_probe_location *
lttng_kernel_probe_location_address_create(uint64_t address);

/*
 * Get the address of an address derived probe location.
 */
LTTNG_EXPORT extern enum lttng_kernel_probe_location_status
lttng_kernel_probe_location_address_get_address(const struct lttng_kernel_probe_location *location,
						uint64_t *offset);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_KERNEL_PROBE_H */
