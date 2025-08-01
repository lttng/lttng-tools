/*
 * SPDX-FileCopyrightText: 2020 Simon Marchi <simon.marchi@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_DOMAIN_INTERNAL_H
#define LTTNG_DOMAIN_INTERNAL_H

#include "common/macros.hpp"
#include "lttng/domain.h"
#include "lttng/lttng-error.h"

enum lttng_error_code lttng_domain_type_parse(const char *str, enum lttng_domain_type *domain_type);
const char *lttng_domain_type_str(enum lttng_domain_type domain_type);

#endif /* LTTNG_DOMAIN_INTERNAL_H */
