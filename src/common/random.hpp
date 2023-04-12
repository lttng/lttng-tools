/*
 * Copyright (C) 2023 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_RANDOM_H
#define LTTNG_RANDOM_H

#include "exception.hpp"

#include <cstddef>
#include <string>

namespace lttng {
namespace random {

using seed_t = unsigned int;

class production_error : public ::lttng::runtime_error {
public:
	explicit production_error(const std::string& msg,
				  const char *file_name,
				  const char *function_name,
				  unsigned int line_number);
};

/*
 * Get a seed from a reliable source of randomness without blocking, raising
 * an exception on failure.
 */
seed_t produce_true_random_seed();

/*
 * Get a random seed making a best-effort to use a true randomness source,
 * but falling back to a pseudo-random seed based on the time and various system
 * configuration values on failure.
 *
 * Note that this function attempts to use the urandom device, which will block
 * in the unlikely event that its pool is uninitialized, on platforms that don't
 * provide getrandom().
 */
seed_t produce_best_effort_random_seed();

} /* namespace random */
} /* namespace lttng */

#endif /* LTTNG_RANDOM_H */
