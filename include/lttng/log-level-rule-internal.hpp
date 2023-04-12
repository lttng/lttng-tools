/*
 * Copyright (C) 2020 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_LOG_LEVEL_RULE_INTERNAL_H
#define LTTNG_LOG_LEVEL_RULE_INTERNAL_H

#include <common/buffer-view.hpp>
#include <common/dynamic-array.hpp>
#include <common/macros.hpp>
#include <common/payload-view.hpp>
#include <common/payload.hpp>

#include <lttng/event.h>
#include <lttng/log-level-rule.h>
#include <lttng/lttng-error.h>

#include <stdint.h>

struct mi_writer;

/*
 * For now only a single backing struct is used for both type of log level
 * rule (exactly, as_severe) since both only have require "level" as property.
 */
struct lttng_log_level_rule {
	enum lttng_log_level_rule_type type;
	int level;
};

struct lttng_log_level_rule_comm {
	/* enum lttng_log_level_rule_type */
	int8_t type;
	int32_t level;
};

ssize_t lttng_log_level_rule_create_from_payload(struct lttng_payload_view *view,
						 struct lttng_log_level_rule **rule);

int lttng_log_level_rule_serialize(const struct lttng_log_level_rule *rule,
				   struct lttng_payload *payload);

bool lttng_log_level_rule_is_equal(const struct lttng_log_level_rule *a,
				   const struct lttng_log_level_rule *b);

struct lttng_log_level_rule *lttng_log_level_rule_copy(const struct lttng_log_level_rule *source);

void lttng_log_level_rule_to_loglevel(const struct lttng_log_level_rule *log_level_rule,
				      enum lttng_loglevel_type *loglevel_type,
				      int *loglevel_value);

unsigned long lttng_log_level_rule_hash(const struct lttng_log_level_rule *log_level_rule);

enum lttng_error_code lttng_log_level_rule_mi_serialize(const struct lttng_log_level_rule *rule,
							struct mi_writer *writer);

#endif /* LTTNG_LOG_LEVEL_RULE_INTERNAL_H */
