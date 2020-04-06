#ifndef SRC_COMMON_EVENT_EXPR_TO_BYTECODE_H
#define SRC_COMMON_EVENT_EXPR_TO_BYTECODE_H

/*
 * Copyright 2020 EfficiOS, Inc.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <common/macros.h>

struct lttng_bytecode;
struct lttng_event_expr;

LTTNG_HIDDEN
int lttng_event_expr_to_bytecode (const struct lttng_event_expr *expr,
		struct lttng_bytecode **bytecode_out);

#endif /* SRC_COMMON_EVENT_EXPR_TO_BYTECODE_H */
