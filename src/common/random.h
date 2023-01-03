/*
 * Copyright (C) 2023 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_RANDOM_H
#define LTTNG_RANDOM_H

#include <stddef.h>

typedef unsigned int seed_t;

/*
 * Get a seed from a reliable source of randomness without blocking. Returns 0
 * on success, -1 on failure.
 */
int lttng_produce_true_random_seed(seed_t *out_seed);

/*
 * Get a random seed making a best-effort to use a true randomness source,
 * but falling back to a pseudo-random seed based on the time and various system
 * configuration values on failure. Returns 0 on success, -1 on failure.
 */
int lttng_produce_best_effort_random_seed(seed_t *out_seed);

#endif /* LTTNG_RANDOM_H */
