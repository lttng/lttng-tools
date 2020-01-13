/*
 * Copyright (C) 2019 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <assert.h>
#include <common/credentials.h>
#include <common/error.h>
#include <common/macros.h>
#include <common/payload.h>
#include <common/payload-view.h>
#include <common/runas.h>
#include <common/hashtable/hashtable.h>
#include <common/hashtable/utils.h>
#include <lttng/event-rule/event-rule-internal.h>
#include <lttng/event-rule/tracepoint-internal.h>

#define IS_TRACEPOINT_EVENT_RULE(rule) \
	(lttng_event_rule_get_type(rule) == LTTNG_EVENT_RULE_TYPE_TRACEPOINT)

static void lttng_event_rule_tracepoint_destroy(struct lttng_event_rule *rule)
{
	struct lttng_event_rule_tracepoint *tracepoint;

	if (rule == NULL) {
		return;
	}

	tracepoint = container_of(
			rule, struct lttng_event_rule_tracepoint, parent);

	lttng_dynamic_pointer_array_reset(&tracepoint->exclusions);
	free(tracepoint->pattern);
	free(tracepoint->filter_expression);
	free(tracepoint->internal_filter.filter);
	free(tracepoint->internal_filter.bytecode);
	free(tracepoint);
}

static bool lttng_event_rule_tracepoint_validate(
		const struct lttng_event_rule *rule)
{
	bool valid = false;
	struct lttng_event_rule_tracepoint *tracepoint;

	if (!rule) {
		goto end;
	}

	tracepoint = container_of(
			rule, struct lttng_event_rule_tracepoint, parent);

	/* Required field. */
	if (!tracepoint->pattern) {
		ERR("Invalid tracepoint event rule: a pattern must be set.");
		goto end;
	}

	/* Required field. */
	if (tracepoint->domain == LTTNG_DOMAIN_NONE) {
		ERR("Invalid tracepoint event rule: a domain must be set.");
		goto end;
	}

	valid = true;
end:
	return valid;
}

static int lttng_event_rule_tracepoint_serialize(
		const struct lttng_event_rule *rule,
		struct lttng_payload *payload)
{
	int ret, i;
	size_t pattern_len, filter_expression_len, exclusions_len;
	struct lttng_event_rule_tracepoint *tracepoint;
	struct lttng_event_rule_tracepoint_comm tracepoint_comm;
	enum lttng_event_rule_status status;
	unsigned int exclusion_count;
	size_t exclusions_appended_len = 0;

	if (!rule || !IS_TRACEPOINT_EVENT_RULE(rule)) {
		ret = -1;
		goto end;
	}

	DBG("Serializing tracepoint event rule.");
	tracepoint = container_of(
			rule, struct lttng_event_rule_tracepoint, parent);

	status = lttng_event_rule_tracepoint_get_exclusions_count(rule, &exclusion_count);
	assert(status == LTTNG_EVENT_RULE_STATUS_OK);

	pattern_len = strlen(tracepoint->pattern) + 1;

	if (tracepoint->filter_expression != NULL) {
		filter_expression_len =
				strlen(tracepoint->filter_expression) + 1;
	} else {
		filter_expression_len = 0;
	}

	exclusions_len = 0;
	for (i = 0; i < exclusion_count; i++) {
		const char *exclusion;

		status = lttng_event_rule_tracepoint_get_exclusion_at_index(
				rule, i, &exclusion);
		assert(status == LTTNG_EVENT_RULE_STATUS_OK);

		/* Length field. */
		exclusions_len += sizeof(uint32_t);
		/* Payload (null terminated). */
		exclusions_len += strlen(exclusion) + 1;
	}

	tracepoint_comm.domain_type = (int8_t) tracepoint->domain;
	tracepoint_comm.loglevel_type = (int8_t) tracepoint->loglevel.type;
	tracepoint_comm.loglevel_value = tracepoint->loglevel.value;
	tracepoint_comm.pattern_len = pattern_len;
	tracepoint_comm.filter_expression_len = filter_expression_len;
	tracepoint_comm.exclusions_count = exclusion_count;
	tracepoint_comm.exclusions_len = exclusions_len;

	ret = lttng_dynamic_buffer_append(&payload->buffer, &tracepoint_comm,
			sizeof(tracepoint_comm));
	if (ret) {
		goto end;
	}

	ret = lttng_dynamic_buffer_append(
			&payload->buffer, tracepoint->pattern, pattern_len);
	if (ret) {
		goto end;
	}

	ret = lttng_dynamic_buffer_append(&payload->buffer, tracepoint->filter_expression,
			filter_expression_len);
	if (ret) {
		goto end;
	}

	for (i = 0; i < exclusion_count; i++) {
		size_t len;
		const char *exclusion;

		status = lttng_event_rule_tracepoint_get_exclusion_at_index(
				rule, i, &exclusion);
		assert(status == LTTNG_EVENT_RULE_STATUS_OK);

		len = strlen(exclusion) + 1;
		/* Append exclusion length, includes the null terminator. */
		ret = lttng_dynamic_buffer_append(
				&payload->buffer, &len, sizeof(uint32_t));
		if (ret) {
			goto end;
		}

		exclusions_appended_len += sizeof(uint32_t);

		/* Include the '\0' in the payload. */
		ret = lttng_dynamic_buffer_append(
				&payload->buffer, exclusion, len);
		if (ret) {
			goto end;
		}

		exclusions_appended_len += len;
	}

	assert(exclusions_len == exclusions_appended_len);

end:
	return ret;
}

static bool lttng_event_rule_tracepoint_is_equal(
		const struct lttng_event_rule *_a,
		const struct lttng_event_rule *_b)
{
	int i;
	bool is_equal = false;
	struct lttng_event_rule_tracepoint *a, *b;
	unsigned int count_a, count_b;
	enum lttng_event_rule_status status;

	a = container_of(_a, struct lttng_event_rule_tracepoint, parent);
	b = container_of(_b, struct lttng_event_rule_tracepoint, parent);

	status = lttng_event_rule_tracepoint_get_exclusions_count(_a, &count_a);
	assert(status == LTTNG_EVENT_RULE_STATUS_OK);
	status = lttng_event_rule_tracepoint_get_exclusions_count(_b, &count_b);
	assert(status == LTTNG_EVENT_RULE_STATUS_OK);

	/* Quick checks. */
	if (a->domain != b->domain) {
		goto end;
	}

	if (count_a != count_b) {
		goto end;
	}

	if (!!a->filter_expression != !!b->filter_expression) {
		goto end;
	}

	/* Long check. */
	assert(a->pattern);
	assert(b->pattern);
	if (strcmp(a->pattern, b->pattern)) {
		goto end;
	}

	if (a->filter_expression && b->filter_expression) {
		if (strcmp(a->filter_expression, b->filter_expression)) {
			goto end;
		}
	} else if (!!a->filter_expression != !!b->filter_expression) {
		/* One is set; not the other. */
		goto end;
	}

	if (a->loglevel.type != b->loglevel.type) {
		goto end;
	}

	if (a->loglevel.value != b->loglevel.value) {
		goto end;
	}

	for (i = 0; i < count_a; i++) {
		const char *exclusion_a, *exclusion_b;

		status = lttng_event_rule_tracepoint_get_exclusion_at_index(
				_a, i, &exclusion_a);
		assert(status == LTTNG_EVENT_RULE_STATUS_OK);
		status = lttng_event_rule_tracepoint_get_exclusion_at_index(
				_b, i, &exclusion_b);
		assert(status == LTTNG_EVENT_RULE_STATUS_OK);
		if (strcmp(exclusion_a, exclusion_b)) {
			goto end;
		}
	}

	is_equal = true;
end:
	return is_equal;
}

/*
 * On success ret is 0;
 *
 * On error ret is negative.
 *
 * An event with NO loglevel and the name is * will return NULL.
 */
static int generate_agent_filter(
		const struct lttng_event_rule *rule, char **_agent_filter)
{
	int err;
	int ret = 0;
	char *agent_filter = NULL;
	const char *pattern;
	const char *filter;
	enum lttng_loglevel_type loglevel_type;
	enum lttng_event_rule_status status;

	assert(rule);
	assert(_agent_filter);

	status = lttng_event_rule_tracepoint_get_pattern(rule, &pattern);
	if (status != LTTNG_EVENT_RULE_STATUS_OK) {
		ret = -1;
		goto end;
	}

	status = lttng_event_rule_tracepoint_get_filter(rule, &filter);
	if (status == LTTNG_EVENT_RULE_STATUS_UNSET) {
		filter = NULL;
	} else if (status != LTTNG_EVENT_RULE_STATUS_OK) {
		ret = -1;
		goto end;
	}

	status = lttng_event_rule_tracepoint_get_log_level_type(
			rule, &loglevel_type);
	if (status != LTTNG_EVENT_RULE_STATUS_OK) {
		ret = -1;
		goto end;
	}

	/* Don't add filter for the '*' event. */
	if (strcmp(pattern, "*") != 0) {
		if (filter) {
			err = asprintf(&agent_filter,
					"(%s) && (logger_name == \"%s\")",
					filter, pattern);
		} else {
			err = asprintf(&agent_filter, "logger_name == \"%s\"",
					pattern);
		}

		if (err < 0) {
			PERROR("Failed to format agent filter string");
			ret = -1;
			goto end;
		}
	}

	if (loglevel_type != LTTNG_EVENT_LOGLEVEL_ALL) {
		const char *op;
		int loglevel_value;

		status = lttng_event_rule_tracepoint_get_log_level(
				rule, &loglevel_value);
		if (status != LTTNG_EVENT_RULE_STATUS_OK) {
			ret = -1;
			goto end;
		}

		if (loglevel_type == LTTNG_EVENT_LOGLEVEL_RANGE) {
			op = ">=";
		} else {
			op = "==";
		}

		if (filter || agent_filter) {
			char *new_filter;

			err = asprintf(&new_filter,
					"(%s) && (int_loglevel %s %d)",
					agent_filter ? agent_filter : filter,
					op, loglevel_value);
			if (agent_filter) {
				free(agent_filter);
			}
			agent_filter = new_filter;
		} else {
			err = asprintf(&agent_filter, "int_loglevel %s %d", op,
					loglevel_value);
		}

		if (err < 0) {
			PERROR("Failed to format agent filter string");
			ret = -1;
			goto end;
		}
	}

	*_agent_filter = agent_filter;
	agent_filter = NULL;

end:
	free(agent_filter);
	return ret;
}

static enum lttng_error_code
lttng_event_rule_tracepoint_generate_filter_bytecode(
		struct lttng_event_rule *rule,
		const struct lttng_credentials *creds)
{
	int ret;
	enum lttng_error_code ret_code;
	struct lttng_event_rule_tracepoint *tracepoint;
	enum lttng_domain_type domain_type;
	enum lttng_event_rule_status status;
	const char *filter;
	struct lttng_filter_bytecode *bytecode = NULL;

	assert(rule);

	tracepoint = container_of(
			rule, struct lttng_event_rule_tracepoint, parent);

	status = lttng_event_rule_tracepoint_get_filter(rule, &filter);
	if (status == LTTNG_EVENT_RULE_STATUS_UNSET) {
		filter = NULL;
	} else if (status != LTTNG_EVENT_RULE_STATUS_OK) {
		ret_code = LTTNG_ERR_FILTER_INVAL;
		goto end;
	}

	if (filter && filter[0] == '\0') {
		ret_code = LTTNG_ERR_FILTER_INVAL;
		goto error;
	}

	status = lttng_event_rule_tracepoint_get_domain_type(
			rule, &domain_type);
	if (status != LTTNG_EVENT_RULE_STATUS_OK) {
		ret_code = LTTNG_ERR_UNK;
		goto error;
	}

	switch (domain_type) {
	case LTTNG_DOMAIN_LOG4J:
	case LTTNG_DOMAIN_JUL:
	case LTTNG_DOMAIN_PYTHON:
	{
		char *agent_filter;

		ret = generate_agent_filter(rule, &agent_filter);
		if (ret) {
			ret_code = LTTNG_ERR_FILTER_INVAL;
			goto error;
		}

		tracepoint->internal_filter.filter = agent_filter;
		break;
	}
	default:
	{
		if (filter) {
			tracepoint->internal_filter.filter = strdup(filter);
			if (tracepoint->internal_filter.filter == NULL) {
				ret_code = LTTNG_ERR_NOMEM;
				goto error;
			}
		} else {
			tracepoint->internal_filter.filter = NULL;
		}
		break;
	}
	}

	if (tracepoint->internal_filter.filter == NULL) {
		ret_code = LTTNG_OK;
		goto end;
	}

	ret = run_as_generate_filter_bytecode(
			tracepoint->internal_filter.filter, creds,
			&bytecode);
	if (ret) {
		ret_code = LTTNG_ERR_FILTER_INVAL;
		goto end;
	}

	tracepoint->internal_filter.bytecode = bytecode;
	bytecode = NULL;
	ret_code = LTTNG_OK;

error:
end:
	free(bytecode);
	return ret_code;
}

static const char *lttng_event_rule_tracepoint_get_internal_filter(
		const struct lttng_event_rule *rule)
{
	struct lttng_event_rule_tracepoint *tracepoint;

	assert(rule);
	tracepoint = container_of(
			rule, struct lttng_event_rule_tracepoint, parent);
	return tracepoint->internal_filter.filter;
}

static const struct lttng_filter_bytecode *
lttng_event_rule_tracepoint_get_internal_filter_bytecode(
		const struct lttng_event_rule *rule)
{
	struct lttng_event_rule_tracepoint *tracepoint;

	assert(rule);
	tracepoint = container_of(
			rule, struct lttng_event_rule_tracepoint, parent);
	return tracepoint->internal_filter.bytecode;
}

static enum lttng_event_rule_generate_exclusions_status
lttng_event_rule_tracepoint_generate_exclusions(
		const struct lttng_event_rule *rule,
		struct lttng_event_exclusion **_exclusions)
{
	unsigned int nb_exclusions = 0, i;
	enum lttng_domain_type domain_type;
	struct lttng_event_exclusion *exclusions;
	enum lttng_event_rule_status event_rule_status;
	enum lttng_event_rule_generate_exclusions_status ret_status;

	assert(_exclusions);

	event_rule_status = lttng_event_rule_tracepoint_get_domain_type(
			rule, &domain_type);
	assert(event_rule_status == LTTNG_EVENT_RULE_STATUS_OK);

	switch (domain_type) {
	case LTTNG_DOMAIN_KERNEL:
	case LTTNG_DOMAIN_JUL:
	case LTTNG_DOMAIN_LOG4J:
	case LTTNG_DOMAIN_PYTHON:
		/* Not supported. */
		exclusions = NULL;
		ret_status = LTTNG_EVENT_RULE_GENERATE_EXCLUSIONS_STATUS_NONE;
		goto end;
	case LTTNG_DOMAIN_UST:
		/* Exclusions supported. */
		break;
	default:
		/* Unknown domain. */
		abort();
	}

	event_rule_status = lttng_event_rule_tracepoint_get_exclusions_count(
			rule, &nb_exclusions);
	assert(event_rule_status == LTTNG_EVENT_RULE_STATUS_OK);
	if (nb_exclusions == 0) {
		/* Nothing to do. */
		exclusions = NULL;
		ret_status = LTTNG_EVENT_RULE_GENERATE_EXCLUSIONS_STATUS_NONE;
		goto end;
	}

	exclusions = zmalloc(sizeof(struct lttng_event_exclusion) +
			(LTTNG_SYMBOL_NAME_LEN * nb_exclusions));
	if (!exclusions) {
		PERROR("Failed to allocate exclusions buffer");
		ret_status = LTTNG_EVENT_RULE_GENERATE_EXCLUSIONS_STATUS_OUT_OF_MEMORY;
		goto end;
	}

	exclusions->count = nb_exclusions;
	for (i = 0; i < nb_exclusions; i++) {
		int copy_ret;
		const char *exclusion_str;

		event_rule_status =
				lttng_event_rule_tracepoint_get_exclusion_at_index(
						rule, i, &exclusion_str);
		assert(event_rule_status == LTTNG_EVENT_RULE_STATUS_OK);

		copy_ret = lttng_strncpy(exclusions->names[i], exclusion_str,
				LTTNG_SYMBOL_NAME_LEN);
		if (copy_ret) {
			free(exclusions);
			exclusions = NULL;
			ret_status = LTTNG_EVENT_RULE_GENERATE_EXCLUSIONS_STATUS_ERROR;
			goto end;
		}
	}

	ret_status = LTTNG_EVENT_RULE_GENERATE_EXCLUSIONS_STATUS_OK;

end:
	*_exclusions = exclusions;
	return ret_status;
}

static void destroy_lttng_exclusions_element(void *ptr)
{
	free(ptr);
}

static unsigned long lttng_event_rule_tracepoint_hash(
		const struct lttng_event_rule *rule)
{
	unsigned long hash;
	unsigned int i, exclusion_count;
	enum lttng_event_rule_status status;
	struct lttng_event_rule_tracepoint *tp_rule =
			container_of(rule, typeof(*tp_rule), parent);

	hash = hash_key_ulong((void *) LTTNG_EVENT_RULE_TYPE_TRACEPOINT,
			lttng_ht_seed);
	hash ^= hash_key_ulong((void *) tp_rule->domain, lttng_ht_seed);
	hash ^= hash_key_str(tp_rule->pattern, lttng_ht_seed);

	if (tp_rule->filter_expression) {
		hash ^= hash_key_str(tp_rule->filter_expression, lttng_ht_seed);
	}

	hash ^= hash_key_ulong((void *) tp_rule->loglevel.type,
			       lttng_ht_seed);
	if (tp_rule->loglevel.type != LTTNG_EVENT_LOGLEVEL_ALL) {
		hash ^= hash_key_ulong(
				(void *) (unsigned long) tp_rule->loglevel.value,
				lttng_ht_seed);
	}

	status = lttng_event_rule_tracepoint_get_exclusions_count(rule,
			&exclusion_count);
	assert(status == LTTNG_EVENT_RULE_STATUS_OK);

	for (i = 0; i < exclusion_count; i++) {
		const char *exclusion;

		status = lttng_event_rule_tracepoint_get_exclusion_at_index(
				rule, i, &exclusion);
		assert(status == LTTNG_EVENT_RULE_STATUS_OK);
		hash ^= hash_key_str(exclusion, lttng_ht_seed);
	}

	return hash;
}

struct lttng_event_rule *lttng_event_rule_tracepoint_create(
		enum lttng_domain_type domain_type)
{
	struct lttng_event_rule *rule = NULL;
	struct lttng_event_rule_tracepoint *tp_rule;

	if (domain_type == LTTNG_DOMAIN_NONE) {
		goto end;
	}

	tp_rule = zmalloc(sizeof(struct lttng_event_rule_tracepoint));
	if (!tp_rule) {
		goto end;
	}

	rule = &tp_rule->parent;
	lttng_event_rule_init(&tp_rule->parent, LTTNG_EVENT_RULE_TYPE_TRACEPOINT);
	tp_rule->parent.validate = lttng_event_rule_tracepoint_validate;
	tp_rule->parent.serialize = lttng_event_rule_tracepoint_serialize;
	tp_rule->parent.equal = lttng_event_rule_tracepoint_is_equal;
	tp_rule->parent.destroy = lttng_event_rule_tracepoint_destroy;
	tp_rule->parent.generate_filter_bytecode =
			lttng_event_rule_tracepoint_generate_filter_bytecode;
	tp_rule->parent.get_filter =
			lttng_event_rule_tracepoint_get_internal_filter;
	tp_rule->parent.get_filter_bytecode =
			lttng_event_rule_tracepoint_get_internal_filter_bytecode;
	tp_rule->parent.generate_exclusions =
			lttng_event_rule_tracepoint_generate_exclusions;
	tp_rule->parent.hash = lttng_event_rule_tracepoint_hash;

	tp_rule->domain = domain_type;
	tp_rule->loglevel.type = LTTNG_EVENT_LOGLEVEL_ALL;

	lttng_dynamic_pointer_array_init(&tp_rule->exclusions,
			destroy_lttng_exclusions_element);
end:
	return rule;
}

LTTNG_HIDDEN
ssize_t lttng_event_rule_tracepoint_create_from_payload(
		struct lttng_payload_view *view,
		struct lttng_event_rule **_event_rule)
{
	ssize_t ret, offset = 0;
	int i;
	enum lttng_event_rule_status status;
	enum lttng_domain_type domain_type;
	enum lttng_loglevel_type loglevel_type;
	const struct lttng_event_rule_tracepoint_comm *tracepoint_comm;
	const char *pattern;
	const char *filter_expression = NULL;
	const char **exclusions = NULL;
	const uint32_t *exclusion_len;
	const char *exclusion;
	struct lttng_buffer_view current_buffer_view;
	struct lttng_event_rule *rule = NULL;

	if (!_event_rule) {
		ret = -1;
		goto end;
	}

	current_buffer_view = lttng_buffer_view_from_view(
			&view->buffer, offset, sizeof(*tracepoint_comm));
	if (!lttng_buffer_view_is_valid(&current_buffer_view)) {
		ERR("Failed to initialize from malformed event rule tracepoint: buffer too short to contain header.");
		ret = -1;
		goto end;
	}

	tracepoint_comm = (typeof(tracepoint_comm)) current_buffer_view.data;

	if (tracepoint_comm->domain_type <= LTTNG_DOMAIN_NONE ||
			tracepoint_comm->domain_type > LTTNG_DOMAIN_PYTHON) {
		/* Invalid domain value. */
		ERR("Invalid domain type value (%i) found in tracepoint_comm buffer.",
				(int) tracepoint_comm->domain_type);
		ret = -1;
		goto end;
	}

	domain_type = (enum lttng_domain_type) tracepoint_comm->domain_type;
	rule = lttng_event_rule_tracepoint_create(domain_type);
	if (!rule) {
		ERR("Failed to create event rule tracepoint.");
		ret = -1;
		goto end;
	}

	loglevel_type = (enum lttng_loglevel_type)
					tracepoint_comm->loglevel_type;
	switch (loglevel_type) {
	case LTTNG_EVENT_LOGLEVEL_ALL:
		status = lttng_event_rule_tracepoint_set_log_level_all(rule);
		break;
	case LTTNG_EVENT_LOGLEVEL_RANGE:
		status = lttng_event_rule_tracepoint_set_log_level_range_lower_bound(rule,
				(enum lttng_loglevel_type) tracepoint_comm
						->loglevel_value);
		break;
	case LTTNG_EVENT_LOGLEVEL_SINGLE:
		status = lttng_event_rule_tracepoint_set_log_level(rule,
				(enum lttng_loglevel_type) tracepoint_comm
						->loglevel_value);
		break;
	default:
		ERR("Failed to set event rule tracepoint loglevel: unknown loglevel type.");
		ret = -1;
		goto end;
	}

	if (status != LTTNG_EVENT_RULE_STATUS_OK) {
		ERR("Failed to set event rule tracepoint loglevel.");
	}

	/* Skip to payload. */
	offset += current_buffer_view.size;

	/* Map the pattern. */
	current_buffer_view = lttng_buffer_view_from_view(
			&view->buffer, offset, tracepoint_comm->pattern_len);

	if (!lttng_buffer_view_is_valid(&current_buffer_view)) {
		ret = -1;
		goto end;
	}

	pattern = current_buffer_view.data;
	if (!lttng_buffer_view_contains_string(&current_buffer_view, pattern,
			tracepoint_comm->pattern_len)) {
		ret = -1;
		goto end;
	}

	/* Skip after the pattern. */
	offset += tracepoint_comm->pattern_len;

	if (!tracepoint_comm->filter_expression_len) {
		goto skip_filter_expression;
	}

	/* Map the filter_expression. */
	current_buffer_view = lttng_buffer_view_from_view(&view->buffer, offset,
			tracepoint_comm->filter_expression_len);
	if (!lttng_buffer_view_is_valid(&current_buffer_view)) {
		ret = -1;
		goto end;
	}

	filter_expression = current_buffer_view.data;
	if (!lttng_buffer_view_contains_string(&current_buffer_view,
			filter_expression,
			tracepoint_comm->filter_expression_len)) {
		ret = -1;
		goto end;
	}

	/* Skip after the pattern. */
	offset += tracepoint_comm->filter_expression_len;

skip_filter_expression:
	for (i = 0; i < tracepoint_comm->exclusions_count; i++) {
		current_buffer_view = lttng_buffer_view_from_view(
				&view->buffer, offset, sizeof(*exclusion_len));
		if (!lttng_buffer_view_is_valid(&current_buffer_view)) {
			ret = -1;
			goto end;
		}

		exclusion_len = (typeof(exclusion_len)) current_buffer_view.data;
		offset += sizeof(*exclusion_len);

		current_buffer_view = lttng_buffer_view_from_view(
				&view->buffer, offset, *exclusion_len);
		if (!lttng_buffer_view_is_valid(&current_buffer_view)) {
			ret = -1;
			goto end;
		}

		exclusion = current_buffer_view.data;
		if (!lttng_buffer_view_contains_string(&current_buffer_view,
				exclusion, *exclusion_len)) {
			ret = -1;
			goto end;
		}

		status = lttng_event_rule_tracepoint_add_exclusion(rule, exclusion);
		if (status != LTTNG_EVENT_RULE_STATUS_OK) {
			ERR("Failed to add event rule tracepoint exclusion \"%s\".",
					exclusion);
			ret = -1;
			goto end;
		}

		/* Skip to next exclusion. */
		offset += *exclusion_len;
	}

	status = lttng_event_rule_tracepoint_set_pattern(rule, pattern);
	if (status != LTTNG_EVENT_RULE_STATUS_OK) {
		ERR("Failed to set event rule tracepoint pattern.");
		ret = -1;
		goto end;
	}

	if (filter_expression) {
		status = lttng_event_rule_tracepoint_set_filter(
				rule, filter_expression);
		if (status != LTTNG_EVENT_RULE_STATUS_OK) {
			ERR("Failed to set event rule tracepoint pattern.");
			ret = -1;
			goto end;
		}
	}

	*_event_rule = rule;
	rule = NULL;
	ret = offset;
end:
	free(exclusions);
	lttng_event_rule_destroy(rule);
	return ret;
}

enum lttng_event_rule_status lttng_event_rule_tracepoint_set_pattern(
		struct lttng_event_rule *rule, const char *pattern)
{
	char *pattern_copy = NULL;
	struct lttng_event_rule_tracepoint *tracepoint;
	enum lttng_event_rule_status status = LTTNG_EVENT_RULE_STATUS_OK;

	if (!rule || !IS_TRACEPOINT_EVENT_RULE(rule) || !pattern ||
			strlen(pattern) == 0) {
		status = LTTNG_EVENT_RULE_STATUS_INVALID;
		goto end;
	}

	tracepoint = container_of(
			rule, struct lttng_event_rule_tracepoint, parent);
	pattern_copy = strdup(pattern);
	if (!pattern_copy) {
		status = LTTNG_EVENT_RULE_STATUS_ERROR;
		goto end;
	}

	free(tracepoint->pattern);

	tracepoint->pattern = pattern_copy;
	pattern_copy = NULL;
end:
	return status;
}

enum lttng_event_rule_status lttng_event_rule_tracepoint_get_pattern(
		const struct lttng_event_rule *rule, const char **pattern)
{
	struct lttng_event_rule_tracepoint *tracepoint;
	enum lttng_event_rule_status status = LTTNG_EVENT_RULE_STATUS_OK;

	if (!rule || !IS_TRACEPOINT_EVENT_RULE(rule) || !pattern) {
		status = LTTNG_EVENT_RULE_STATUS_INVALID;
		goto end;
	}

	tracepoint = container_of(
			rule, struct lttng_event_rule_tracepoint, parent);
	if (!tracepoint->pattern) {
		status = LTTNG_EVENT_RULE_STATUS_UNSET;
		goto end;
	}

	*pattern = tracepoint->pattern;
end:
	return status;
}

enum lttng_event_rule_status lttng_event_rule_tracepoint_get_domain_type(
		const struct lttng_event_rule *rule,
		enum lttng_domain_type *type)
{
	struct lttng_event_rule_tracepoint *tracepoint;
	enum lttng_event_rule_status status = LTTNG_EVENT_RULE_STATUS_OK;

	if (!rule || !IS_TRACEPOINT_EVENT_RULE(rule) || !type) {
		status = LTTNG_EVENT_RULE_STATUS_INVALID;
		goto end;
	}

	tracepoint = container_of(
			rule, struct lttng_event_rule_tracepoint, parent);
	*type = tracepoint->domain;
end:
	return status;
}

enum lttng_event_rule_status lttng_event_rule_tracepoint_set_filter(
		struct lttng_event_rule *rule, const char *expression)
{
	char *expression_copy = NULL;
	struct lttng_event_rule_tracepoint *tracepoint;
	enum lttng_event_rule_status status = LTTNG_EVENT_RULE_STATUS_OK;

	if (!rule || !IS_TRACEPOINT_EVENT_RULE(rule) || !expression ||
			strlen(expression) == 0) {
		status = LTTNG_EVENT_RULE_STATUS_INVALID;
		goto end;
	}

	tracepoint = container_of(
			rule, struct lttng_event_rule_tracepoint, parent);
	expression_copy = strdup(expression);
	if (!expression_copy) {
		PERROR("Failed to copy filter expression");
		status = LTTNG_EVENT_RULE_STATUS_ERROR;
		goto end;
	}

	if (tracepoint->filter_expression) {
		free(tracepoint->filter_expression);
	}

	tracepoint->filter_expression = expression_copy;
	expression_copy = NULL;
end:
	return status;
}

enum lttng_event_rule_status lttng_event_rule_tracepoint_get_filter(
		const struct lttng_event_rule *rule, const char **expression)
{
	struct lttng_event_rule_tracepoint *tracepoint;
	enum lttng_event_rule_status status = LTTNG_EVENT_RULE_STATUS_OK;

	if (!rule || !IS_TRACEPOINT_EVENT_RULE(rule) || !expression) {
		status = LTTNG_EVENT_RULE_STATUS_INVALID;
		goto end;
	}

	tracepoint = container_of(
			rule, struct lttng_event_rule_tracepoint, parent);
	if (!tracepoint->filter_expression) {
		status = LTTNG_EVENT_RULE_STATUS_UNSET;
		goto end;
	}

	*expression = tracepoint->filter_expression;
end:
	return status;
}

static bool log_level_value_valid(
		int level, enum lttng_domain_type domain)
{
	bool valid = false;

	switch (domain) {
	case LTTNG_DOMAIN_KERNEL:
	case LTTNG_DOMAIN_UST:
		if (level < LTTNG_LOGLEVEL_EMERG) {
			/* Invalid. */
			goto end;
		}
		if (level > LTTNG_LOGLEVEL_DEBUG) {
			/* Invalid. */
			goto end;
		}

		valid = true;
		break;
	case LTTNG_DOMAIN_JUL:
	case LTTNG_DOMAIN_LOG4J:
	case LTTNG_DOMAIN_PYTHON:
		/*
		 * For both JUL and LOG4J custom log level are possible and can
		 * spawn the entire int32 range.
		 * For python, custom log level are possible, it is not clear if
		 * negative value are accepted (NOTSET == 0) but the source code
		 * validate against the int type implying that negative values
		 * are accepted.
		 */
		valid = true;
		goto end;

	case LTTNG_DOMAIN_NONE:
	default:
		abort();
	}

end:
	return valid;
}

enum lttng_event_rule_status lttng_event_rule_tracepoint_set_log_level(
		struct lttng_event_rule *rule, int level)
{
	struct lttng_event_rule_tracepoint *tracepoint;
	enum lttng_event_rule_status status = LTTNG_EVENT_RULE_STATUS_OK;

	if (!rule || !IS_TRACEPOINT_EVENT_RULE(rule)) {
		status = LTTNG_EVENT_RULE_STATUS_INVALID;
		goto end;
	}

	tracepoint = container_of(
			rule, struct lttng_event_rule_tracepoint, parent);

	if (!log_level_value_valid(level, tracepoint->domain)) {
		status = LTTNG_EVENT_RULE_STATUS_INVALID;
		goto end;
	}

	tracepoint->loglevel.value = level;
	tracepoint->loglevel.type = LTTNG_EVENT_LOGLEVEL_SINGLE;
end:
	return status;
}

enum lttng_event_rule_status
lttng_event_rule_tracepoint_set_log_level_range_lower_bound(
		struct lttng_event_rule *rule, int level)
{
	struct lttng_event_rule_tracepoint *tracepoint;
	enum lttng_event_rule_status status = LTTNG_EVENT_RULE_STATUS_OK;

	if (!rule || !IS_TRACEPOINT_EVENT_RULE(rule)) {
		status = LTTNG_EVENT_RULE_STATUS_INVALID;
		goto end;
	}

	tracepoint = container_of(
			rule, struct lttng_event_rule_tracepoint, parent);

	if (!log_level_value_valid(level, tracepoint->domain)) {
		status = LTTNG_EVENT_RULE_STATUS_INVALID;
		goto end;
	}

	tracepoint->loglevel.value = level;
	tracepoint->loglevel.type = LTTNG_EVENT_LOGLEVEL_RANGE;
end:
	return status;
}

enum lttng_event_rule_status lttng_event_rule_tracepoint_set_log_level_all(
		struct lttng_event_rule *rule)
{
	struct lttng_event_rule_tracepoint *tracepoint;
	enum lttng_event_rule_status status = LTTNG_EVENT_RULE_STATUS_OK;

	if (!rule || !IS_TRACEPOINT_EVENT_RULE(rule)) {
		status = LTTNG_EVENT_RULE_STATUS_INVALID;
		goto end;
	}

	tracepoint = container_of(
			rule, struct lttng_event_rule_tracepoint, parent);
	tracepoint->loglevel.type = LTTNG_EVENT_LOGLEVEL_ALL;
end:
	return status;
}

enum lttng_event_rule_status lttng_event_rule_tracepoint_get_log_level_type(
		const struct lttng_event_rule *rule,
		enum lttng_loglevel_type *type)
{
	struct lttng_event_rule_tracepoint *tracepoint;
	enum lttng_event_rule_status status = LTTNG_EVENT_RULE_STATUS_OK;

	if (!rule || !IS_TRACEPOINT_EVENT_RULE(rule) || !type) {
		status = LTTNG_EVENT_RULE_STATUS_INVALID;
		goto end;
	}

	tracepoint = container_of(
			rule, struct lttng_event_rule_tracepoint, parent);
	*type = tracepoint->loglevel.type;
end:
	return status;
}

enum lttng_event_rule_status lttng_event_rule_tracepoint_get_log_level(
		const struct lttng_event_rule *rule, int *level)
{
	struct lttng_event_rule_tracepoint *tracepoint;
	enum lttng_event_rule_status status = LTTNG_EVENT_RULE_STATUS_OK;

	if (!rule || !IS_TRACEPOINT_EVENT_RULE(rule) || !level) {
		status = LTTNG_EVENT_RULE_STATUS_INVALID;
		goto end;
	}

	tracepoint = container_of(
			rule, struct lttng_event_rule_tracepoint, parent);
	if (tracepoint->loglevel.type == LTTNG_EVENT_LOGLEVEL_ALL) {
		status = LTTNG_EVENT_RULE_STATUS_UNSET;
		goto end;
	}

	*level = tracepoint->loglevel.value;
end:
	return status;
}

enum lttng_event_rule_status lttng_event_rule_tracepoint_add_exclusion(
		struct lttng_event_rule *rule,
		const char *exclusion)
{
	int ret;
	char *exclusion_copy = NULL;
	struct lttng_event_rule_tracepoint *tracepoint;
	enum lttng_event_rule_status status = LTTNG_EVENT_RULE_STATUS_OK;
	enum lttng_domain_type domain_type;

	if (!rule || !IS_TRACEPOINT_EVENT_RULE(rule) ||
			!exclusion) {
		status = LTTNG_EVENT_RULE_STATUS_INVALID;
		goto end;
	}

	tracepoint = container_of(
			rule, struct lttng_event_rule_tracepoint, parent);

	status = lttng_event_rule_tracepoint_get_domain_type(
			rule, &domain_type);
	if (status != LTTNG_EVENT_RULE_STATUS_OK) {
		goto end;
	}

	switch (domain_type) {
	case LTTNG_DOMAIN_KERNEL:
	case LTTNG_DOMAIN_JUL:
	case LTTNG_DOMAIN_LOG4J:
	case LTTNG_DOMAIN_PYTHON:
		status = LTTNG_EVENT_RULE_STATUS_UNSUPPORTED;
		goto end;
	case LTTNG_DOMAIN_UST:
		/* Exclusions supported. */
		break;
	default:
		abort();
	}

	if (strlen(exclusion) >= LTTNG_SYMBOL_NAME_LEN) {
		status = LTTNG_EVENT_RULE_STATUS_INVALID;
		goto end;
	}

	exclusion_copy = strdup(exclusion);
	if (!exclusion_copy) {
		status = LTTNG_EVENT_RULE_STATUS_ERROR;
		goto end;
	}

	ret = lttng_dynamic_pointer_array_add_pointer(&tracepoint->exclusions,
			exclusion_copy);
	if (ret < 0) {
		status = LTTNG_EVENT_RULE_STATUS_ERROR;
		goto end;
	}

	exclusion_copy = NULL;
end:
	free(exclusion_copy);
	return status;
}

enum lttng_event_rule_status lttng_event_rule_tracepoint_get_exclusions_count(
		const struct lttng_event_rule *rule, unsigned int *count)
{
	struct lttng_event_rule_tracepoint *tracepoint;
	enum lttng_event_rule_status status = LTTNG_EVENT_RULE_STATUS_OK;

	if (!rule || !IS_TRACEPOINT_EVENT_RULE(rule) || !count) {
		status = LTTNG_EVENT_RULE_STATUS_INVALID;
		goto end;
	}

	tracepoint = container_of(
			rule, struct lttng_event_rule_tracepoint, parent);
	*count = lttng_dynamic_pointer_array_get_count(&tracepoint->exclusions);
end:
	return status;
}

enum lttng_event_rule_status lttng_event_rule_tracepoint_get_exclusion_at_index(
		const struct lttng_event_rule *rule,
		unsigned int index,
		const char **exclusion)
{
	unsigned int count;
	struct lttng_event_rule_tracepoint *tracepoint;
	enum lttng_event_rule_status status = LTTNG_EVENT_RULE_STATUS_OK;

	if (!rule || !IS_TRACEPOINT_EVENT_RULE(rule) || !exclusion) {
		status = LTTNG_EVENT_RULE_STATUS_INVALID;
		goto end;
	}

	tracepoint = container_of(
			rule, struct lttng_event_rule_tracepoint, parent);
	if (lttng_event_rule_tracepoint_get_exclusions_count(rule, &count) !=
			LTTNG_EVENT_RULE_STATUS_OK) {
		goto end;
	}

	if (index >= count) {
		goto end;
	}

	*exclusion = lttng_dynamic_pointer_array_get_pointer(
			&tracepoint->exclusions, index);
end:
	return status;
}
