/*
 * Copyright (C) 2020 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_KERNEL_PROBE_INTERNAL_H
#define LTTNG_KERNEL_PROBE_INTERNAL_H

#include <common/fd-handle.hpp>
#include <common/macros.hpp>

#include <lttng/kernel-probe.h>
#include <lttng/lttng-error.h>

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

struct lttng_payload;
struct lttng_payload_view;
struct lttng_dynamic_buffer;
struct mi_writer;

using kernel_probe_location_equal_cb = bool (*)(const struct lttng_kernel_probe_location *,
						const struct lttng_kernel_probe_location *);
using kernel_probe_location_serialize_cb = int (*)(const struct lttng_kernel_probe_location *,
						   struct lttng_payload *);
using kernel_probe_location_equal_cb = bool (*)(const struct lttng_kernel_probe_location *,
						const struct lttng_kernel_probe_location *);
using kernel_probe_location_create_from_payload_cb =
	ssize_t (*)(struct lttng_payload_view *, struct lttng_kernel_probe_location **);
using kernel_probe_location_hash_cb = unsigned long (*)(const struct lttng_kernel_probe_location *);
using kernel_probe_location_mi_serialize_cb =
	enum lttng_error_code (*)(const struct lttng_kernel_probe_location *, struct mi_writer *);

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
	kernel_probe_location_hash_cb hash;
	kernel_probe_location_mi_serialize_cb mi_serialize;
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

int lttng_kernel_probe_location_serialize(const struct lttng_kernel_probe_location *location,
					  struct lttng_payload *payload);

ssize_t lttng_kernel_probe_location_create_from_payload(
	struct lttng_payload_view *view, struct lttng_kernel_probe_location **probe_location);

bool lttng_kernel_probe_location_is_equal(const struct lttng_kernel_probe_location *a,
					  const struct lttng_kernel_probe_location *b);

struct lttng_kernel_probe_location *
lttng_kernel_probe_location_copy(const struct lttng_kernel_probe_location *location);

unsigned long lttng_kernel_probe_location_hash(const struct lttng_kernel_probe_location *location);

enum lttng_error_code
lttng_kernel_probe_location_mi_serialize(const struct lttng_kernel_probe_location *location,
					 struct mi_writer *writer);

#endif /* LTTNG_KERNEL_PROBE_INTERNAL_H */
