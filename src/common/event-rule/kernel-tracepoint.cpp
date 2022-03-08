/*
 * Copyright (C) 2019 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <common/credentials.h>
#include <common/error.h>
#include <common/hashtable/hashtable.h>
#include <common/hashtable/utils.h>
#include <common/macros.h>
#include <common/mi-lttng.h>
#include <common/optional.h>
#include <common/payload-view.h>
#include <common/payload.h>
#include <common/runas.h>
#include <common/string-utils/string-utils.h>
#include <lttng/event-rule/event-rule-internal.h>
#include <lttng/event-rule/kernel-tracepoint-internal.h>
#include <lttng/event.h>

#define IS_KERNEL_TRACEPOINT_EVENT_RULE(rule) \
	(lttng_event_rule_get_type(rule) == LTTNG_EVENT_RULE_TYPE_KERNEL_TRACEPOINT)

static void lttng_event_rule_kernel_tracepoint_destroy(struct lttng_event_rule *rule)
{
	struct lttng_event_rule_kernel_tracepoint *tracepoint;

	if (rule == NULL) {
		return;
	}

	tracepoint = container_of(
			rule, struct lttng_event_rule_kernel_tracepoint, parent);

	free(tracepoint->pattern);
	free(tracepoint->filter_expression);
	free(tracepoint->internal_filter.filter);
	free(tracepoint->internal_filter.bytecode);
	free(tracepoint);
}

static bool lttng_event_rule_kernel_tracepoint_validate(
		const struct lttng_event_rule *rule)
{
	bool valid = false;
	struct lttng_event_rule_kernel_tracepoint *tracepoint;

	if (!rule) {
		goto end;
	}

	tracepoint = container_of(
			rule, struct lttng_event_rule_kernel_tracepoint, parent);

	/* Required field. */
	if (!tracepoint->pattern) {
		ERR("Invalid kernel tracepoint event rule: a pattern must be set.");
		goto end;
	}

	valid = true;
end:
	return valid;
}

static int lttng_event_rule_kernel_tracepoint_serialize(
		const struct lttng_event_rule *rule,
		struct lttng_payload *payload)
{
	int ret;
	size_t pattern_len, filter_expression_len;
	struct lttng_event_rule_kernel_tracepoint *tracepoint;
	struct lttng_event_rule_kernel_tracepoint_comm tracepoint_comm;

	if (!rule || !IS_KERNEL_TRACEPOINT_EVENT_RULE(rule)) {
		ret = -1;
		goto end;
	}

	DBG("Serializing kernel tracepoint event rule.");
	tracepoint = container_of(
			rule, struct lttng_event_rule_kernel_tracepoint, parent);

	pattern_len = strlen(tracepoint->pattern) + 1;

	if (tracepoint->filter_expression != NULL) {
		filter_expression_len =
				strlen(tracepoint->filter_expression) + 1;
	} else {
		filter_expression_len = 0;
	}

	tracepoint_comm.pattern_len = pattern_len;
	tracepoint_comm.filter_expression_len = filter_expression_len;

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

end:
	return ret;
}

static bool lttng_event_rule_kernel_tracepoint_is_equal(
		const struct lttng_event_rule *_a,
		const struct lttng_event_rule *_b)
{
	bool is_equal = false;
	struct lttng_event_rule_kernel_tracepoint *a, *b;

	a = container_of(_a, struct lttng_event_rule_kernel_tracepoint, parent);
	b = container_of(_b, struct lttng_event_rule_kernel_tracepoint, parent);

	if (!!a->filter_expression != !!b->filter_expression) {
		goto end;
	}

	/* Long check. */
	LTTNG_ASSERT(a->pattern);
	LTTNG_ASSERT(b->pattern);
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

	is_equal = true;
end:
	return is_equal;
}

static enum lttng_error_code
lttng_event_rule_kernel_tracepoint_generate_filter_bytecode(
		struct lttng_event_rule *rule,
		const struct lttng_credentials *creds)
{
	int ret;
	enum lttng_error_code ret_code;
	struct lttng_event_rule_kernel_tracepoint *tracepoint;
	enum lttng_event_rule_status status;
	const char *filter;
	struct lttng_bytecode *bytecode = NULL;

	LTTNG_ASSERT(rule);

	tracepoint = container_of(
			rule, struct lttng_event_rule_kernel_tracepoint, parent);

	status = lttng_event_rule_kernel_tracepoint_get_filter(rule, &filter);
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

	if (filter) {
		tracepoint->internal_filter.filter = strdup(filter);
		if (tracepoint->internal_filter.filter == NULL) {
			ret_code = LTTNG_ERR_NOMEM;
			goto error;
		}
	} else {
		tracepoint->internal_filter.filter = NULL;
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

static const char *lttng_event_rule_kernel_tracepoint_get_internal_filter(
		const struct lttng_event_rule *rule)
{
	struct lttng_event_rule_kernel_tracepoint *tracepoint;

	LTTNG_ASSERT(rule);
	tracepoint = container_of(
			rule, struct lttng_event_rule_kernel_tracepoint, parent);
	return tracepoint->internal_filter.filter;
}

static const struct lttng_bytecode *
lttng_event_rule_kernel_tracepoint_get_internal_filter_bytecode(
		const struct lttng_event_rule *rule)
{
	struct lttng_event_rule_kernel_tracepoint *tracepoint;

	LTTNG_ASSERT(rule);
	tracepoint = container_of(
			rule, struct lttng_event_rule_kernel_tracepoint, parent);
	return tracepoint->internal_filter.bytecode;
}

static enum lttng_event_rule_generate_exclusions_status
lttng_event_rule_kernel_tracepoint_generate_exclusions(
		const struct lttng_event_rule *rule __attribute__((unused)),
		struct lttng_event_exclusion **_exclusions)
{
	/* Unsupported. */
	*_exclusions = NULL;
	return LTTNG_EVENT_RULE_GENERATE_EXCLUSIONS_STATUS_NONE;
}

static unsigned long lttng_event_rule_kernel_tracepoint_hash(
		const struct lttng_event_rule *rule)
{
	unsigned long hash;
	struct lttng_event_rule_kernel_tracepoint *tp_rule =
			container_of(rule, typeof(*tp_rule), parent);

	hash = hash_key_ulong((void *) LTTNG_EVENT_RULE_TYPE_KERNEL_TRACEPOINT,
			lttng_ht_seed);
	hash ^= hash_key_str(tp_rule->pattern, lttng_ht_seed);

	if (tp_rule->filter_expression) {
		hash ^= hash_key_str(tp_rule->filter_expression, lttng_ht_seed);
	}

	return hash;
}

static enum lttng_error_code lttng_event_rule_kernel_tracepoint_mi_serialize(
		const struct lttng_event_rule *rule, struct mi_writer *writer)
{
	int ret;
	enum lttng_error_code ret_code;
	enum lttng_event_rule_status status;
	const char *filter = NULL;
	const char *name_pattern = NULL;

	LTTNG_ASSERT(rule);
	LTTNG_ASSERT(writer);
	LTTNG_ASSERT(IS_KERNEL_TRACEPOINT_EVENT_RULE(rule));

	status = lttng_event_rule_kernel_tracepoint_get_name_pattern(
			rule, &name_pattern);
	LTTNG_ASSERT(status == LTTNG_EVENT_RULE_STATUS_OK);
	LTTNG_ASSERT(name_pattern);

	status = lttng_event_rule_kernel_tracepoint_get_filter(rule, &filter);
	LTTNG_ASSERT(status == LTTNG_EVENT_RULE_STATUS_OK ||
			status == LTTNG_EVENT_RULE_STATUS_UNSET);

	/* Open event rule kernel tracepoint element. */
	ret = mi_lttng_writer_open_element(
			writer, mi_lttng_element_event_rule_kernel_tracepoint);
	if (ret) {
		goto mi_error;
	}

	/* Name pattern. */
	ret = mi_lttng_writer_write_element_string(writer,
			mi_lttng_element_event_rule_name_pattern, name_pattern);
	if (ret) {
		goto mi_error;
	}

	/* Filter. */
	if (filter != NULL) {
		ret = mi_lttng_writer_write_element_string(writer,
				mi_lttng_element_event_rule_filter_expression,
				filter);
		if (ret) {
			goto mi_error;
		}
	}

	/* Close event rule kernel tracepoint element. */
	ret = mi_lttng_writer_close_element(writer);
	if (ret) {
		goto mi_error;
	}

	ret_code = LTTNG_OK;
	goto end;

mi_error:
	ret_code = LTTNG_ERR_MI_IO_FAIL;
end:
	return ret_code;
}

struct lttng_event_rule *lttng_event_rule_kernel_tracepoint_create(void)
{
	struct lttng_event_rule *rule = NULL;
	struct lttng_event_rule_kernel_tracepoint *tp_rule;
	enum lttng_event_rule_status status;

	tp_rule = (lttng_event_rule_kernel_tracepoint *) zmalloc(sizeof(struct lttng_event_rule_kernel_tracepoint));
	if (!tp_rule) {
		goto end;
	}

	rule = &tp_rule->parent;
	lttng_event_rule_init(&tp_rule->parent, LTTNG_EVENT_RULE_TYPE_KERNEL_TRACEPOINT);
	tp_rule->parent.validate = lttng_event_rule_kernel_tracepoint_validate;
	tp_rule->parent.serialize = lttng_event_rule_kernel_tracepoint_serialize;
	tp_rule->parent.equal = lttng_event_rule_kernel_tracepoint_is_equal;
	tp_rule->parent.destroy = lttng_event_rule_kernel_tracepoint_destroy;
	tp_rule->parent.generate_filter_bytecode =
			lttng_event_rule_kernel_tracepoint_generate_filter_bytecode;
	tp_rule->parent.get_filter =
			lttng_event_rule_kernel_tracepoint_get_internal_filter;
	tp_rule->parent.get_filter_bytecode =
			lttng_event_rule_kernel_tracepoint_get_internal_filter_bytecode;
	tp_rule->parent.generate_exclusions =
			lttng_event_rule_kernel_tracepoint_generate_exclusions;
	tp_rule->parent.hash = lttng_event_rule_kernel_tracepoint_hash;
	tp_rule->parent.mi_serialize = lttng_event_rule_kernel_tracepoint_mi_serialize;

	/* Not necessary for now. */
	tp_rule->parent.generate_lttng_event = NULL;

	/* Default pattern is '*'. */
	status = lttng_event_rule_kernel_tracepoint_set_name_pattern(rule, "*");
	if (status != LTTNG_EVENT_RULE_STATUS_OK) {
		lttng_event_rule_destroy(rule);
		rule = NULL;
	}

end:
	return rule;
}

ssize_t lttng_event_rule_kernel_tracepoint_create_from_payload(
		struct lttng_payload_view *view,
		struct lttng_event_rule **_event_rule)
{
	ssize_t ret, offset = 0;
	enum lttng_event_rule_status status;
	const struct lttng_event_rule_kernel_tracepoint_comm *tracepoint_comm;
	const char *pattern;
	const char *filter_expression = NULL;
	struct lttng_buffer_view current_buffer_view;
	struct lttng_event_rule *rule = NULL;

	if (!_event_rule) {
		ret = -1;
		goto end;
	}

	current_buffer_view = lttng_buffer_view_from_view(
			&view->buffer, offset, sizeof(*tracepoint_comm));
	if (!lttng_buffer_view_is_valid(&current_buffer_view)) {
		ERR("Failed to initialize from malformed event rule kernel tracepoint: buffer too short to contain header.");
		ret = -1;
		goto end;
	}

	tracepoint_comm = (typeof(tracepoint_comm)) current_buffer_view.data;

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

	rule = lttng_event_rule_kernel_tracepoint_create();
	if (!rule) {
		ERR("Failed to create event rule kernel tracepoint.");
		ret = -1;
		goto end;
	}

	status = lttng_event_rule_kernel_tracepoint_set_name_pattern(rule, pattern);
	if (status != LTTNG_EVENT_RULE_STATUS_OK) {
		ERR("Failed to set event rule kernel tracepoint pattern.");
		ret = -1;
		goto end;
	}

	if (filter_expression) {
		status = lttng_event_rule_kernel_tracepoint_set_filter(
				rule, filter_expression);
		if (status != LTTNG_EVENT_RULE_STATUS_OK) {
			ERR("Failed to set event rule kernel tracepoint pattern.");
			ret = -1;
			goto end;
		}
	}

	*_event_rule = rule;
	rule = NULL;
	ret = offset;
end:
	lttng_event_rule_destroy(rule);
	return ret;
}

enum lttng_event_rule_status lttng_event_rule_kernel_tracepoint_set_name_pattern(
		struct lttng_event_rule *rule, const char *pattern)
{
	char *pattern_copy = NULL;
	struct lttng_event_rule_kernel_tracepoint *tracepoint;
	enum lttng_event_rule_status status = LTTNG_EVENT_RULE_STATUS_OK;

	if (!rule || !IS_KERNEL_TRACEPOINT_EVENT_RULE(rule) || !pattern ||
			strlen(pattern) == 0) {
		status = LTTNG_EVENT_RULE_STATUS_INVALID;
		goto end;
	}

	tracepoint = container_of(
			rule, struct lttng_event_rule_kernel_tracepoint, parent);
	pattern_copy = strdup(pattern);
	if (!pattern_copy) {
		status = LTTNG_EVENT_RULE_STATUS_ERROR;
		goto end;
	}

	/* Normalize the pattern. */
	strutils_normalize_star_glob_pattern(pattern_copy);

	free(tracepoint->pattern);

	tracepoint->pattern = pattern_copy;
	pattern_copy = NULL;
end:
	return status;
}

enum lttng_event_rule_status lttng_event_rule_kernel_tracepoint_get_name_pattern(
		const struct lttng_event_rule *rule, const char **pattern)
{
	struct lttng_event_rule_kernel_tracepoint *tracepoint;
	enum lttng_event_rule_status status = LTTNG_EVENT_RULE_STATUS_OK;

	if (!rule || !IS_KERNEL_TRACEPOINT_EVENT_RULE(rule) || !pattern) {
		status = LTTNG_EVENT_RULE_STATUS_INVALID;
		goto end;
	}

	tracepoint = container_of(
			rule, struct lttng_event_rule_kernel_tracepoint, parent);
	if (!tracepoint->pattern) {
		status = LTTNG_EVENT_RULE_STATUS_UNSET;
		goto end;
	}

	*pattern = tracepoint->pattern;
end:
	return status;
}

enum lttng_event_rule_status lttng_event_rule_kernel_tracepoint_set_filter(
		struct lttng_event_rule *rule, const char *expression)
{
	char *expression_copy = NULL;
	struct lttng_event_rule_kernel_tracepoint *tracepoint;
	enum lttng_event_rule_status status = LTTNG_EVENT_RULE_STATUS_OK;

	if (!rule || !IS_KERNEL_TRACEPOINT_EVENT_RULE(rule) || !expression ||
			strlen(expression) == 0) {
		status = LTTNG_EVENT_RULE_STATUS_INVALID;
		goto end;
	}

	tracepoint = container_of(
			rule, struct lttng_event_rule_kernel_tracepoint, parent);
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

enum lttng_event_rule_status lttng_event_rule_kernel_tracepoint_get_filter(
		const struct lttng_event_rule *rule, const char **expression)
{
	struct lttng_event_rule_kernel_tracepoint *tracepoint;
	enum lttng_event_rule_status status = LTTNG_EVENT_RULE_STATUS_OK;

	if (!rule || !IS_KERNEL_TRACEPOINT_EVENT_RULE(rule) || !expression) {
		status = LTTNG_EVENT_RULE_STATUS_INVALID;
		goto end;
	}

	tracepoint = container_of(
			rule, struct lttng_event_rule_kernel_tracepoint, parent);
	if (!tracepoint->filter_expression) {
		status = LTTNG_EVENT_RULE_STATUS_UNSET;
		goto end;
	}

	*expression = tracepoint->filter_expression;
end:
	return status;
}
