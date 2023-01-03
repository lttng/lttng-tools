/*
 * Copyright (C) 2023 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_LOGGING_UTILS_H
#define LTTNG_LOGGING_UTILS_H

#include <common/error.hpp>

namespace lttng {
namespace logging {

/* Output system information as logging statements. */
void log_system_information(lttng_error_level error_level);

} /* namespace logging */
} /* namespace lttng */

#endif /* LTTNG_LOGGING_UTILS_H */
