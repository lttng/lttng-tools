/*
 * Copyright (C) 2019 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_EVENT_RULE_INTERNAL_H
#define LTTNG_EVENT_RULE_INTERNAL_H

#include <common/credentials.hpp>
#include <common/macros.hpp>
#include <common/sessiond-comm/sessiond-comm.hpp>

#include <lttng/domain.h>
#include <lttng/event-rule/event-rule.h>
#include <lttng/event.h>
#include <lttng/lttng-error.h>

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <urcu/ref.h>

struct lttng_payload;
struct lttng_payload_view;
struct mi_writer;

enum lttng_event_rule_generate_exclusions_status {
	LTTNG_EVENT_RULE_GENERATE_EXCLUSIONS_STATUS_OK,
	LTTNG_EVENT_RULE_GENERATE_EXCLUSIONS_STATUS_NONE,
	LTTNG_EVENT_RULE_GENERATE_EXCLUSIONS_STATUS_ERROR,
	LTTNG_EVENT_RULE_GENERATE_EXCLUSIONS_STATUS_OUT_OF_MEMORY,
};

using event_rule_destroy_cb = void (*)(struct lttng_event_rule *);
using event_rule_validate_cb = bool (*)(const struct lttng_event_rule *);
using event_rule_serialize_cb = int (*)(const struct lttng_event_rule *, struct lttng_payload *);
using event_rule_equal_cb = bool (*)(const struct lttng_event_rule *,
				     const struct lttng_event_rule *);
using event_rule_create_from_payload_cb = ssize_t (*)(struct lttng_payload_view *,
						      struct lttng_event_rule **);
using event_rule_generate_filter_bytecode_cb =
	enum lttng_error_code (*)(struct lttng_event_rule *, const struct lttng_credentials *);
using event_rule_get_filter_cb = const char *(*) (const struct lttng_event_rule *);
using event_rule_get_filter_bytecode_cb =
	const struct lttng_bytecode *(*) (const struct lttng_event_rule *);
using event_rule_generate_exclusions_cb = enum lttng_event_rule_generate_exclusions_status (*)(
	const struct lttng_event_rule *, struct lttng_event_exclusion **);
using event_rule_hash_cb = unsigned long (*)(const struct lttng_event_rule *);
using event_rule_generate_lttng_event_cb = struct lttng_event *(*) (const struct lttng_event_rule *);
using event_rule_mi_serialize_cb = enum lttng_error_code (*)(const struct lttng_event_rule *,
							     struct mi_writer *);

struct lttng_event_rule {
	struct urcu_ref ref;
	enum lttng_event_rule_type type;
	event_rule_validate_cb validate;
	event_rule_serialize_cb serialize;
	event_rule_equal_cb equal;
	event_rule_destroy_cb destroy;
	event_rule_generate_filter_bytecode_cb generate_filter_bytecode;
	event_rule_get_filter_cb get_filter;
	event_rule_get_filter_bytecode_cb get_filter_bytecode;
	event_rule_generate_exclusions_cb generate_exclusions;
	event_rule_hash_cb hash;
	event_rule_generate_lttng_event_cb generate_lttng_event;
	event_rule_mi_serialize_cb mi_serialize;
};

struct lttng_event_rule_comm {
	/* enum lttng_event_rule_type */
	int8_t event_rule_type;
	char payload[];
};

void lttng_event_rule_init(struct lttng_event_rule *event_rule, enum lttng_event_rule_type type);

bool lttng_event_rule_validate(const struct lttng_event_rule *event_rule);

ssize_t lttng_event_rule_create_from_payload(struct lttng_payload_view *payload,
					     struct lttng_event_rule **event_rule);

int lttng_event_rule_serialize(const struct lttng_event_rule *event_rule,
			       struct lttng_payload *payload);

bool lttng_event_rule_is_equal(const struct lttng_event_rule *a, const struct lttng_event_rule *b);

bool lttng_event_rule_get(struct lttng_event_rule *rule);

void lttng_event_rule_put(struct lttng_event_rule *rule);

enum lttng_domain_type lttng_event_rule_get_domain_type(const struct lttng_event_rule *rule);

enum lttng_error_code
lttng_event_rule_generate_filter_bytecode(struct lttng_event_rule *rule,
					  const struct lttng_credentials *creds);

/*
 * If not present/implemented returns NULL.
 * Caller DOES NOT own the returned object.
 */
const char *lttng_event_rule_get_filter(const struct lttng_event_rule *rule);

/*
 * If not present/implemented returns NULL.
 * Caller DOES NOT own the returned object.
 */
const struct lttng_bytecode *
lttng_event_rule_get_filter_bytecode(const struct lttng_event_rule *rule);

/*
 * If not present/implemented return NULL.
 * Caller OWNS the returned object.
 */
enum lttng_event_rule_generate_exclusions_status
lttng_event_rule_generate_exclusions(const struct lttng_event_rule *rule,
				     struct lttng_event_exclusion **exclusions);

const char *lttng_event_rule_type_str(enum lttng_event_rule_type type);

unsigned long lttng_event_rule_hash(const struct lttng_event_rule *rule);

/*
 * This is a compatibility helper allowing us to generate a sessiond-side (not
 * communication) `struct lttng_event` object from an event rule.
 *
 * This effectively bridges older parts of the code using those structures and
 * new event-rule based code.
 *
 * The caller owns the returned object.
 */
struct lttng_event *lttng_event_rule_generate_lttng_event(const struct lttng_event_rule *rule);

/* Test if an event rule targets an agent domain. */
bool lttng_event_rule_targets_agent_domain(const struct lttng_event_rule *rule);

enum lttng_error_code lttng_event_rule_mi_serialize(const struct lttng_event_rule *rule,
						    struct mi_writer *writer);

#endif /* LTTNG_EVENT_RULE_INTERNAL_H */
