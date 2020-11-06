/*
 * Copyright (C) 2020 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <assert.h>
#include <common/dynamic-buffer.h>
#include <common/error.h>
#include <common/macros.h>
#include <common/hashtable/hashtable.h>
#include <common/hashtable/utils.h>
#include <lttng/log-level-rule-internal.h>
#include <lttng/log-level-rule.h>
#include <stdbool.h>
#include <stdlib.h>

static bool is_log_level_rule_exactly_type(const struct lttng_log_level_rule *rule)
{
	enum lttng_log_level_rule_type type =
			lttng_log_level_rule_get_type(rule);

	return type == LTTNG_LOG_LEVEL_RULE_TYPE_EXACTLY;
}

static bool is_log_level_rule_at_least_as_severe_type(const struct lttng_log_level_rule *rule)
{

	enum lttng_log_level_rule_type type =
			lttng_log_level_rule_get_type(rule);

	return type == LTTNG_LOG_LEVEL_RULE_TYPE_AT_LEAST_AS_SEVERE_AS;
}

enum lttng_log_level_rule_type lttng_log_level_rule_get_type(
		const struct lttng_log_level_rule *rule)
{
	return rule ? rule->type : LTTNG_LOG_LEVEL_RULE_TYPE_UNKNOWN;
}

struct lttng_log_level_rule *lttng_log_level_rule_exactly_create(
		int level)
{
	struct lttng_log_level_rule *rule = NULL;

	rule = zmalloc(sizeof(struct lttng_log_level_rule));
	if (!rule) {
		goto end;
	}

	rule->type = LTTNG_LOG_LEVEL_RULE_TYPE_EXACTLY;
	rule->level = level;

end:
	return rule;
}

enum lttng_log_level_rule_status lttng_log_level_rule_exactly_get_level(
		const struct lttng_log_level_rule *rule, int *level)
{
	enum lttng_log_level_rule_status status =
			LTTNG_LOG_LEVEL_RULE_STATUS_OK;

	if (!rule || !level || !is_log_level_rule_exactly_type(rule)) {
		status = LTTNG_LOG_LEVEL_RULE_STATUS_INVALID;
		goto end;
	}

	*level = rule->level;
end:
	return status;
}

struct lttng_log_level_rule *
lttng_log_level_rule_at_least_as_severe_as_create(int level)
{
	struct lttng_log_level_rule *rule = NULL;

	rule = zmalloc(sizeof(struct lttng_log_level_rule));
	if (!rule) {
		goto end;
	}

	rule->type = LTTNG_LOG_LEVEL_RULE_TYPE_AT_LEAST_AS_SEVERE_AS;
	rule->level = level;

end:
	return rule;
}

enum lttng_log_level_rule_status
lttng_log_level_rule_at_least_as_severe_as_get_level(
		const struct lttng_log_level_rule *rule, int *level)
{
	enum lttng_log_level_rule_status status = LTTNG_LOG_LEVEL_RULE_STATUS_OK;

	if (!rule || !level ||
			!is_log_level_rule_at_least_as_severe_type(rule)) {
		status = LTTNG_LOG_LEVEL_RULE_STATUS_INVALID;
		goto end;
	}

	*level = rule->level;
end:
	return status;
}

void lttng_log_level_rule_destroy(struct lttng_log_level_rule *log_level_rule)
{
	free(log_level_rule);
}

LTTNG_HIDDEN
ssize_t lttng_log_level_rule_create_from_payload(
		struct lttng_payload_view *view,
		struct lttng_log_level_rule **_rule)
{
	ssize_t ret;
	size_t offset = 0;
	struct lttng_log_level_rule *rule = NULL;
	const struct lttng_log_level_rule_comm *comm =
			(const struct lttng_log_level_rule_comm *)
					view->buffer.data;

	offset += sizeof(*comm);

	if (!_rule) {
		ret = -1;
		goto end;
	}

	if (view->buffer.size < sizeof(*comm)) {
		ret = -1;
		goto end;
	}

	switch (comm->type) {
	case LTTNG_LOG_LEVEL_RULE_TYPE_EXACTLY:
		rule = lttng_log_level_rule_exactly_create((int) comm->level);
		break;
	case LTTNG_LOG_LEVEL_RULE_TYPE_AT_LEAST_AS_SEVERE_AS:
		rule = lttng_log_level_rule_at_least_as_severe_as_create(
				(int) comm->level);
		break;
	default:
		abort();
	}

	if (!rule) {
		ret = -1;
		goto end;
	}

	*_rule = rule;
	ret = offset;

end:
	return ret;
}

LTTNG_HIDDEN
int lttng_log_level_rule_serialize(const struct lttng_log_level_rule *rule,
		struct lttng_payload *payload)
{
	int ret;
	struct lttng_log_level_rule_comm comm;


	if (!rule) {
		ret = 0;
		goto end;
	}

	comm.type = (int8_t) rule->type;
	comm.level = (int32_t) rule->level;

	DBG("Serializing log level rule of type %d", rule->type);
	ret = lttng_dynamic_buffer_append(&payload->buffer, &comm,
			sizeof(comm));
	if (ret) {
		goto end;
	}

end:
	return ret;
}

LTTNG_HIDDEN
bool lttng_log_level_rule_is_equal(const struct lttng_log_level_rule *a,
		const struct lttng_log_level_rule *b)
{
	bool is_equal = false;

	if (a == NULL && b == NULL) {
		/* Both are null. */
		is_equal = true;
		goto end;
	}

	if (a == NULL || b == NULL) {
		/* One is NULL.*/
		goto end;
	}

	if (a == b) {
		/* Same object.*/
		is_equal = true;
		goto end;
	}

	if (a->type != b->type) {
		goto end;
	}

	if (a->level != b->level) {
		goto end;
	}

	is_equal = true;

end:
	return is_equal;
}

LTTNG_HIDDEN
struct lttng_log_level_rule *lttng_log_level_rule_copy(
		const struct lttng_log_level_rule *source)
{
	struct lttng_log_level_rule *copy = NULL;

	assert(source);

	copy = zmalloc(sizeof(struct lttng_log_level_rule));
	if (!copy) {
		goto end;
	}

	copy->type = source->type;
	copy->level = source->level;
end:
	return copy;
}

LTTNG_HIDDEN
void lttng_log_level_rule_to_loglevel(
		const struct lttng_log_level_rule *log_level_rule,
		enum lttng_loglevel_type *loglevel_type,
		int *loglevel_value)
{
	assert(log_level_rule);

	switch (log_level_rule->type) {
	case LTTNG_LOG_LEVEL_RULE_TYPE_EXACTLY:
		*loglevel_type = LTTNG_EVENT_LOGLEVEL_SINGLE;
		break;
	case LTTNG_LOG_LEVEL_RULE_TYPE_AT_LEAST_AS_SEVERE_AS:
		*loglevel_type = LTTNG_EVENT_LOGLEVEL_RANGE;
		break;
	default:
		abort();
	}

	*loglevel_value = log_level_rule->level;
}

LTTNG_HIDDEN
unsigned long lttng_log_level_rule_hash(
		const struct lttng_log_level_rule *log_level_rule)
{
	unsigned long hash;
	enum lttng_log_level_rule_status llr_status;
	int log_level_value;
	enum lttng_log_level_rule_type type;

	assert(log_level_rule);

	type = lttng_log_level_rule_get_type(log_level_rule);

	switch (type) {
	case LTTNG_LOG_LEVEL_RULE_TYPE_EXACTLY:
		llr_status = lttng_log_level_rule_exactly_get_level(
				log_level_rule, &log_level_value);
		break;
	case LTTNG_LOG_LEVEL_RULE_TYPE_AT_LEAST_AS_SEVERE_AS:
		llr_status = lttng_log_level_rule_at_least_as_severe_as_get_level(
				log_level_rule, &log_level_value);
		break;
	default:
		abort();
		break;
	}

	assert(llr_status == LTTNG_LOG_LEVEL_RULE_STATUS_OK);

	hash = hash_key_ulong((void *) (unsigned long) type, lttng_ht_seed);

	hash ^= hash_key_ulong((void *) (unsigned long) log_level_value,
			lttng_ht_seed);

	return hash;
}
