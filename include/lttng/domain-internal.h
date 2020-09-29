/*
 * Copyright (C) 2020 Simon Marchi <simon.marchi@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_DOMAIN_INTERNAL_H
#define LTTNG_DOMAIN_INTERNAL_H

#include "lttng/domain.h"
#include "common/macros.h"

#ifdef __cplusplus
extern "C" {
#endif

LTTNG_HIDDEN
const char *lttng_domain_type_str(enum lttng_domain_type domain_type);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_DOMAIN_INTERNAL_H */
