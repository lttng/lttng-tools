/*
 * Copyright (C) 2020 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_KERNEL_PROBE_INTERNAL_H
#define LTTNG_KERNEL_PROBE_INTERNAL_H

#include <common/fd-handle.h>
#include <common/macros.h>
#include <lttng/kernel-probe.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

struct lttng_payload;
struct lttng_payload_view;
struct lttng_dynamic_buffer;

typedef bool (*kernel_probe_location_equal_cb)(
		const struct lttng_kernel_probe_location *a,
		const struct lttng_kernel_probe_location *b);
typedef int (*kernel_probe_location_serialize_cb)(
		const struct lttng_kernel_probe_location *kernel_probe_location,
		struct lttng_payload *payload);
typedef bool (*kernel_probe_location_equal_cb)(
		const struct lttng_kernel_probe_location *a,
		const struct lttng_kernel_probe_location *b);
typedef ssize_t (*kernel_probe_location_create_from_payload_cb)(
		struct lttng_payload_view *view,
		struct lttng_kernel_probe_location **kernel_probe_location);

struct lttng_kernel_probe_location_comm {
	/* enum lttng_kernel_probe_location_type */
	int8_t type;
	/*
	 * Payload is composed of, in that order,
	 *   - type-specific payload
	 */
	char payload[];
} LTTNG_PACKED;

struct lttng_kernel_probe_location_symbol_comm {
	/* Includes the trailing \0. */
	uint32_t symbol_len;
	/* The offset from the symbol. */
	uint64_t offset;
	/*
	 * Payload is composed of, in that order,
	 *   - symbol name (with trailing \0).
	 */
	char payload[];
} LTTNG_PACKED;

struct lttng_kernel_probe_location_address_comm {
	uint64_t address;
} LTTNG_PACKED;

/* Common ancestor of all kernel probe locations. */
struct lttng_kernel_probe_location {
	enum lttng_kernel_probe_location_type type;
	kernel_probe_location_equal_cb equal;
	kernel_probe_location_serialize_cb serialize;
};

struct lttng_kernel_probe_location_symbol {
	struct lttng_kernel_probe_location parent;
	char *symbol_name;
	uint64_t offset;
};

struct lttng_kernel_probe_location_address {
	struct lttng_kernel_probe_location parent;
	uint64_t address;
};

LTTNG_HIDDEN
int lttng_kernel_probe_location_serialize(
		const struct lttng_kernel_probe_location *location,
		struct lttng_payload *payload);

LTTNG_HIDDEN
ssize_t lttng_kernel_probe_location_create_from_payload(
		struct lttng_payload_view *view,
		struct lttng_kernel_probe_location **probe_location);

LTTNG_HIDDEN
bool lttng_kernel_probe_location_is_equal(
		const struct lttng_kernel_probe_location *a,
		const struct lttng_kernel_probe_location *b);

LTTNG_HIDDEN
struct lttng_kernel_probe_location *lttng_kernel_probe_location_copy(
		const struct lttng_kernel_probe_location *location);

#endif /* LTTNG_KERNEL_PROBE_INTERNAL_H */
