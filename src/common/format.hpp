/*
 * Copyright (C) 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */
#ifndef LTTNG_FORMAT_H
#define LTTNG_FORMAT_H

#include <common/macros.hpp>

DIAGNOSTIC_PUSH
DIAGNOSTIC_IGNORE_SUGGEST_ATTRIBUTE_FORMAT
DIAGNOSTIC_IGNORE_DUPLICATED_BRANCHES
#define FMT_HEADER_ONLY
#include <vendor/fmt/core.h>
DIAGNOSTIC_POP

#endif /* LTTNG_FORMAT_H */
