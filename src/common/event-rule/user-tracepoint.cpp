/*
 * Copyright (C) 2019 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <common/credentials.hpp>
#include <common/error.hpp>
#include <common/hashtable/hashtable.hpp>
#include <common/hashtable/utils.hpp>
#include <common/macros.hpp>
#include <common/mi-lttng.hpp>
#include <common/optional.hpp>
#include <common/payload-view.hpp>
#include <common/payload.hpp>
#include <common/runas.hpp>
#include <common/string-utils/string-utils.hpp>

#include <lttng/event-rule/event-rule-internal.hpp>
#include <lttng/event-rule/user-tracepoint-internal.hpp>
#include <lttng/event.h>
#include <lttng/log-level-rule.h>

#define IS_USER_TRACEPOINT_EVENT_RULE(rule) \
	(lttng_event_rule_get_type(rule) == LTTNG_EVENT_RULE_TYPE_USER_TRACEPOINT)

static void lttng_event_rule_user_tracepoint_destroy(struct lttng_event_rule *rule)
{
	struct lttng_event_rule_user_tracepoint *tracepoint;

	if (rule == nullptr) {
		return;
	}

	tracepoint = lttng::utils::container_of(rule, &lttng_event_rule_user_tracepoint::parent);

	lttng_log_level_rule_destroy(tracepoint->log_level_rule);
	lttng_dynamic_pointer_array_reset(&tracepoint->exclusions);
	free(tracepoint->pattern);
	free(tracepoint->filter_expression);
	free(tracepoint->internal_filter.filter);
	free(tracepoint->internal_filter.bytecode);
	free(tracepoint);
}

static bool lttng_event_rule_user_tracepoint_validate(const struct lttng_event_rule *rule)
{
	bool valid = false;
	struct lttng_event_rule_user_tracepoint *tracepoint;

	if (!rule) {
		goto end;
	}

	tracepoint = lttng::utils::container_of(rule, &lttng_event_rule_user_tracepoint::parent);

	/* Required field. */
	if (!tracepoint->pattern) {
		ERR("Invalid user tracepoint event rule: a pattern must be set.");
		goto end;
	}

	valid = true;
end:
	return valid;
}

static int lttng_event_rule_user_tracepoint_serialize(const struct lttng_event_rule *rule,
						      struct lttng_payload *payload)
{
	int ret, i;
	size_t pattern_len, filter_expression_len, exclusions_len, header_offset;
	size_t size_before_log_level_rule;
	struct lttng_event_rule_user_tracepoint *tracepoint;
	struct lttng_event_rule_user_tracepoint_comm tracepoint_comm;
	enum lttng_event_rule_status status;
	unsigned int exclusion_count;
	size_t exclusions_appended_len = 0;
	struct lttng_event_rule_user_tracepoint_comm *header;

	if (!rule || !IS_USER_TRACEPOINT_EVENT_RULE(rule)) {
		ret = -1;
		goto end;
	}

	header_offset = payload->buffer.size;

	DBG("Serializing user tracepoint event rule.");
	tracepoint = lttng::utils::container_of(rule, &lttng_event_rule_user_tracepoint::parent);

	status = lttng_event_rule_user_tracepoint_get_name_pattern_exclusion_count(
		rule, &exclusion_count);
	LTTNG_ASSERT(status == LTTNG_EVENT_RULE_STATUS_OK);

	pattern_len = strlen(tracepoint->pattern) + 1;

	if (tracepoint->filter_expression != nullptr) {
		filter_expression_len = strlen(tracepoint->filter_expression) + 1;
	} else {
		filter_expression_len = 0;
	}

	exclusions_len = 0;
	for (i = 0; i < exclusion_count; i++) {
		const char *exclusion;

		status = lttng_event_rule_user_tracepoint_get_name_pattern_exclusion_at_index(
			rule, i, &exclusion);
		LTTNG_ASSERT(status == LTTNG_EVENT_RULE_STATUS_OK);

		/* Length field. */
		exclusions_len += sizeof(uint32_t);
		/* Payload (null terminated). */
		exclusions_len += strlen(exclusion) + 1;
	}

	tracepoint_comm.pattern_len = pattern_len;
	tracepoint_comm.filter_expression_len = filter_expression_len;
	tracepoint_comm.exclusions_count = exclusion_count;
	tracepoint_comm.exclusions_len = exclusions_len;

	ret = lttng_dynamic_buffer_append(
		&payload->buffer, &tracepoint_comm, sizeof(tracepoint_comm));
	if (ret) {
		goto end;
	}

	ret = lttng_dynamic_buffer_append(&payload->buffer, tracepoint->pattern, pattern_len);
	if (ret) {
		goto end;
	}

	ret = lttng_dynamic_buffer_append(
		&payload->buffer, tracepoint->filter_expression, filter_expression_len);
	if (ret) {
		goto end;
	}

	size_before_log_level_rule = payload->buffer.size;

	ret = lttng_log_level_rule_serialize(tracepoint->log_level_rule, payload);
	if (ret < 0) {
		goto end;
	}

	header = (typeof(header)) ((char *) payload->buffer.data + header_offset);
	header->log_level_rule_len = payload->buffer.size - size_before_log_level_rule;

	for (i = 0; i < exclusion_count; i++) {
		size_t len;
		uint32_t serialized_len;
		const char *exclusion;

		status = lttng_event_rule_user_tracepoint_get_name_pattern_exclusion_at_index(
			rule, i, &exclusion);
		LTTNG_ASSERT(status == LTTNG_EVENT_RULE_STATUS_OK);

		len = strlen(exclusion) + 1;

		serialized_len = len;
		/* Append exclusion length, includes the null terminator. */
		ret = lttng_dynamic_buffer_append(
			&payload->buffer, &serialized_len, sizeof(serialized_len));
		if (ret) {
			goto end;
		}

		exclusions_appended_len += sizeof(uint32_t);

		/* Include the '\0' in the payload. */
		ret = lttng_dynamic_buffer_append(&payload->buffer, exclusion, len);
		if (ret) {
			goto end;
		}

		exclusions_appended_len += len;
	}

	LTTNG_ASSERT(exclusions_len == exclusions_appended_len);

end:
	return ret;
}

static bool lttng_event_rule_user_tracepoint_is_equal(const struct lttng_event_rule *_a,
						      const struct lttng_event_rule *_b)
{
	int i;
	bool is_equal = false;
	struct lttng_event_rule_user_tracepoint *a, *b;
	unsigned int count_a, count_b;
	enum lttng_event_rule_status status;

	a = lttng::utils::container_of(_a, &lttng_event_rule_user_tracepoint::parent);
	b = lttng::utils::container_of(_b, &lttng_event_rule_user_tracepoint::parent);

	status = lttng_event_rule_user_tracepoint_get_name_pattern_exclusion_count(_a, &count_a);
	LTTNG_ASSERT(status == LTTNG_EVENT_RULE_STATUS_OK);
	status = lttng_event_rule_user_tracepoint_get_name_pattern_exclusion_count(_b, &count_b);
	LTTNG_ASSERT(status == LTTNG_EVENT_RULE_STATUS_OK);

	/* Quick checks. */
	if (count_a != count_b) {
		goto end;
	}

	if (!!a->filter_expression != !!b->filter_expression) {
		goto end;
	}

	/* Long check. */
	LTTNG_ASSERT(a->pattern);
	LTTNG_ASSERT(b->pattern);
	if (strcmp(a->pattern, b->pattern) != 0) {
		goto end;
	}

	if (a->filter_expression && b->filter_expression) {
		if (strcmp(a->filter_expression, b->filter_expression) != 0) {
			goto end;
		}
	} else if (!!a->filter_expression != !!b->filter_expression) {
		/* One is set; not the other. */
		goto end;
	}

	if (!lttng_log_level_rule_is_equal(a->log_level_rule, b->log_level_rule)) {
		goto end;
	}

	for (i = 0; i < count_a; i++) {
		const char *exclusion_a, *exclusion_b;

		status = lttng_event_rule_user_tracepoint_get_name_pattern_exclusion_at_index(
			_a, i, &exclusion_a);
		LTTNG_ASSERT(status == LTTNG_EVENT_RULE_STATUS_OK);
		status = lttng_event_rule_user_tracepoint_get_name_pattern_exclusion_at_index(
			_b, i, &exclusion_b);
		LTTNG_ASSERT(status == LTTNG_EVENT_RULE_STATUS_OK);
		if (strcmp(exclusion_a, exclusion_b) != 0) {
			goto end;
		}
	}

	is_equal = true;
end:
	return is_equal;
}

static enum lttng_error_code
lttng_event_rule_user_tracepoint_generate_filter_bytecode(struct lttng_event_rule *rule,
							  const struct lttng_credentials *creds)
{
	int ret;
	enum lttng_error_code ret_code;
	struct lttng_event_rule_user_tracepoint *tracepoint;
	enum lttng_event_rule_status status;
	const char *filter;
	struct lttng_bytecode *bytecode = nullptr;

	LTTNG_ASSERT(rule);

	tracepoint = lttng::utils::container_of(rule, &lttng_event_rule_user_tracepoint::parent);

	status = lttng_event_rule_user_tracepoint_get_filter(rule, &filter);
	if (status == LTTNG_EVENT_RULE_STATUS_UNSET) {
		filter = nullptr;
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
		if (tracepoint->internal_filter.filter == nullptr) {
			ret_code = LTTNG_ERR_NOMEM;
			goto error;
		}
	} else {
		tracepoint->internal_filter.filter = nullptr;
	}

	if (tracepoint->internal_filter.filter == nullptr) {
		ret_code = LTTNG_OK;
		goto end;
	}

	ret = run_as_generate_filter_bytecode(tracepoint->internal_filter.filter, creds, &bytecode);
	if (ret) {
		ret_code = LTTNG_ERR_FILTER_INVAL;
		goto end;
	}

	tracepoint->internal_filter.bytecode = bytecode;
	bytecode = nullptr;
	ret_code = LTTNG_OK;

error:
end:
	free(bytecode);
	return ret_code;
}

static const char *
lttng_event_rule_user_tracepoint_get_internal_filter(const struct lttng_event_rule *rule)
{
	struct lttng_event_rule_user_tracepoint *tracepoint;

	LTTNG_ASSERT(rule);
	tracepoint = lttng::utils::container_of(rule, &lttng_event_rule_user_tracepoint::parent);
	return tracepoint->internal_filter.filter;
}

static const struct lttng_bytecode *
lttng_event_rule_user_tracepoint_get_internal_filter_bytecode(const struct lttng_event_rule *rule)
{
	struct lttng_event_rule_user_tracepoint *tracepoint;

	LTTNG_ASSERT(rule);
	tracepoint = lttng::utils::container_of(rule, &lttng_event_rule_user_tracepoint::parent);
	return tracepoint->internal_filter.bytecode;
}

static enum lttng_event_rule_generate_exclusions_status
lttng_event_rule_user_tracepoint_generate_exclusions(const struct lttng_event_rule *rule,
						     struct lttng_event_exclusion **_exclusions)
{
	unsigned int nb_exclusions = 0, i;
	struct lttng_event_exclusion *exclusions;
	enum lttng_event_rule_status event_rule_status;
	enum lttng_event_rule_generate_exclusions_status ret_status;

	LTTNG_ASSERT(_exclusions);

	event_rule_status = lttng_event_rule_user_tracepoint_get_name_pattern_exclusion_count(
		rule, &nb_exclusions);
	LTTNG_ASSERT(event_rule_status == LTTNG_EVENT_RULE_STATUS_OK);
	if (nb_exclusions == 0) {
		/* Nothing to do. */
		exclusions = nullptr;
		ret_status = LTTNG_EVENT_RULE_GENERATE_EXCLUSIONS_STATUS_NONE;
		goto end;
	}

	exclusions = zmalloc<lttng_event_exclusion>(sizeof(struct lttng_event_exclusion) +
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
			lttng_event_rule_user_tracepoint_get_name_pattern_exclusion_at_index(
				rule, i, &exclusion_str);
		LTTNG_ASSERT(event_rule_status == LTTNG_EVENT_RULE_STATUS_OK);

		copy_ret = lttng_strncpy(LTTNG_EVENT_EXCLUSION_NAME_AT(exclusions, i),
					 exclusion_str,
					 sizeof(LTTNG_EVENT_EXCLUSION_NAME_AT(exclusions, i)));
		if (copy_ret) {
			free(exclusions);
			exclusions = nullptr;
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

static unsigned long lttng_event_rule_user_tracepoint_hash(const struct lttng_event_rule *rule)
{
	unsigned long hash;
	unsigned int i, exclusion_count;
	enum lttng_event_rule_status status;
	struct lttng_event_rule_user_tracepoint *tp_rule =
		lttng::utils::container_of(rule, &lttng_event_rule_user_tracepoint::parent);

	hash = hash_key_ulong((void *) LTTNG_EVENT_RULE_TYPE_USER_TRACEPOINT, lttng_ht_seed);
	hash ^= hash_key_str(tp_rule->pattern, lttng_ht_seed);

	if (tp_rule->filter_expression) {
		hash ^= hash_key_str(tp_rule->filter_expression, lttng_ht_seed);
	}

	if (tp_rule->log_level_rule) {
		hash ^= lttng_log_level_rule_hash(tp_rule->log_level_rule);
	}

	status = lttng_event_rule_user_tracepoint_get_name_pattern_exclusion_count(
		rule, &exclusion_count);
	LTTNG_ASSERT(status == LTTNG_EVENT_RULE_STATUS_OK);

	for (i = 0; i < exclusion_count; i++) {
		const char *exclusion;

		status = lttng_event_rule_user_tracepoint_get_name_pattern_exclusion_at_index(
			rule, i, &exclusion);
		LTTNG_ASSERT(status == LTTNG_EVENT_RULE_STATUS_OK);
		hash ^= hash_key_str(exclusion, lttng_ht_seed);
	}

	return hash;
}

static enum lttng_error_code
lttng_event_rule_user_tracepoint_mi_serialize(const struct lttng_event_rule *rule,
					      struct mi_writer *writer)
{
	int ret;
	enum lttng_error_code ret_code;
	enum lttng_event_rule_status status;
	const char *filter = nullptr;
	const char *name_pattern = nullptr;
	const struct lttng_log_level_rule *log_level_rule = nullptr;
	unsigned int exclusion_count = 0;

	LTTNG_ASSERT(rule);
	LTTNG_ASSERT(writer);
	LTTNG_ASSERT(IS_USER_TRACEPOINT_EVENT_RULE(rule));

	status = lttng_event_rule_user_tracepoint_get_name_pattern(rule, &name_pattern);
	LTTNG_ASSERT(status == LTTNG_EVENT_RULE_STATUS_OK);
	LTTNG_ASSERT(name_pattern);

	status = lttng_event_rule_user_tracepoint_get_filter(rule, &filter);
	LTTNG_ASSERT(status == LTTNG_EVENT_RULE_STATUS_OK ||
		     status == LTTNG_EVENT_RULE_STATUS_UNSET);

	status = lttng_event_rule_user_tracepoint_get_log_level_rule(rule, &log_level_rule);
	LTTNG_ASSERT(status == LTTNG_EVENT_RULE_STATUS_OK ||
		     status == LTTNG_EVENT_RULE_STATUS_UNSET);

	status = lttng_event_rule_user_tracepoint_get_name_pattern_exclusion_count(
		rule, &exclusion_count);
	LTTNG_ASSERT(status == LTTNG_EVENT_RULE_STATUS_OK);

	/* Open event rule user tracepoint element. */
	ret = mi_lttng_writer_open_element(writer, mi_lttng_element_event_rule_user_tracepoint);
	if (ret) {
		goto mi_error;
	}

	/* Name pattern. */
	ret = mi_lttng_writer_write_element_string(
		writer, mi_lttng_element_event_rule_name_pattern, name_pattern);
	if (ret) {
		goto mi_error;
	}

	/* Filter expression. */
	if (filter != nullptr) {
		ret = mi_lttng_writer_write_element_string(
			writer, mi_lttng_element_event_rule_filter_expression, filter);
		if (ret) {
			goto mi_error;
		}
	}

	/* Log level rule. */
	if (log_level_rule) {
		ret_code = lttng_log_level_rule_mi_serialize(log_level_rule, writer);
		if (ret_code != LTTNG_OK) {
			goto end;
		}
	}

	if (exclusion_count != 0) {
		int i;

		/* Open the exclusion list. */
		ret = mi_lttng_writer_open_element(
			writer,
			mi_lttng_element_event_rule_user_tracepoint_name_pattern_exclusions);
		if (ret) {
			goto mi_error;
		}

		for (i = 0; i < exclusion_count; i++) {
			const char *exclusion;

			status =
				lttng_event_rule_user_tracepoint_get_name_pattern_exclusion_at_index(
					rule, i, &exclusion);
			LTTNG_ASSERT(status == LTTNG_EVENT_RULE_STATUS_OK);

			ret = mi_lttng_writer_write_element_string(
				writer,
				mi_lttng_element_event_rule_user_tracepoint_name_pattern_exclusion,
				exclusion);
			if (ret) {
				goto mi_error;
			}
		}

		/* Close the list. */
		ret = mi_lttng_writer_close_element(writer);
		if (ret) {
			goto mi_error;
		}
	}

	/* Close event rule user tracepoint element. */
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

struct lttng_event_rule *lttng_event_rule_user_tracepoint_create(void)
{
	struct lttng_event_rule *rule = nullptr;
	struct lttng_event_rule_user_tracepoint *tp_rule;
	enum lttng_event_rule_status status;

	tp_rule = zmalloc<lttng_event_rule_user_tracepoint>();
	if (!tp_rule) {
		goto end;
	}

	rule = &tp_rule->parent;
	lttng_event_rule_init(&tp_rule->parent, LTTNG_EVENT_RULE_TYPE_USER_TRACEPOINT);
	tp_rule->parent.validate = lttng_event_rule_user_tracepoint_validate;
	tp_rule->parent.serialize = lttng_event_rule_user_tracepoint_serialize;
	tp_rule->parent.equal = lttng_event_rule_user_tracepoint_is_equal;
	tp_rule->parent.destroy = lttng_event_rule_user_tracepoint_destroy;
	tp_rule->parent.generate_filter_bytecode =
		lttng_event_rule_user_tracepoint_generate_filter_bytecode;
	tp_rule->parent.get_filter = lttng_event_rule_user_tracepoint_get_internal_filter;
	tp_rule->parent.get_filter_bytecode =
		lttng_event_rule_user_tracepoint_get_internal_filter_bytecode;
	tp_rule->parent.generate_exclusions = lttng_event_rule_user_tracepoint_generate_exclusions;
	tp_rule->parent.hash = lttng_event_rule_user_tracepoint_hash;
	tp_rule->parent.mi_serialize = lttng_event_rule_user_tracepoint_mi_serialize;

	/* Not necessary for now. */
	tp_rule->parent.generate_lttng_event = nullptr;

	tp_rule->log_level_rule = nullptr;

	lttng_dynamic_pointer_array_init(&tp_rule->exclusions, destroy_lttng_exclusions_element);

	/* Default pattern is '*'. */
	status = lttng_event_rule_user_tracepoint_set_name_pattern(rule, "*");
	if (status != LTTNG_EVENT_RULE_STATUS_OK) {
		lttng_event_rule_destroy(rule);
		rule = nullptr;
	}

end:
	return rule;
}

ssize_t lttng_event_rule_user_tracepoint_create_from_payload(struct lttng_payload_view *view,
							     struct lttng_event_rule **_event_rule)
{
	ssize_t ret, offset = 0;
	int i;
	enum lttng_event_rule_status status;
	const struct lttng_event_rule_user_tracepoint_comm *tracepoint_comm;
	const char *pattern;
	const char *filter_expression = nullptr;
	const char **exclusions = nullptr;
	const uint32_t *exclusion_len;
	const char *exclusion;
	struct lttng_buffer_view current_buffer_view;
	struct lttng_event_rule *rule = nullptr;
	struct lttng_log_level_rule *log_level_rule = nullptr;

	if (!_event_rule) {
		ret = -1;
		goto end;
	}

	current_buffer_view =
		lttng_buffer_view_from_view(&view->buffer, offset, sizeof(*tracepoint_comm));
	if (!lttng_buffer_view_is_valid(&current_buffer_view)) {
		ERR("Failed to initialize from malformed event rule tracepoint: buffer too short to contain header.");
		ret = -1;
		goto end;
	}

	tracepoint_comm = (typeof(tracepoint_comm)) current_buffer_view.data;

	rule = lttng_event_rule_user_tracepoint_create();
	if (!rule) {
		ERR("Failed to create event rule user tracepoint.");
		ret = -1;
		goto end;
	}

	/* Skip to payload. */
	offset += current_buffer_view.size;

	/* Map the pattern. */
	current_buffer_view =
		lttng_buffer_view_from_view(&view->buffer, offset, tracepoint_comm->pattern_len);

	if (!lttng_buffer_view_is_valid(&current_buffer_view)) {
		ret = -1;
		goto end;
	}

	pattern = current_buffer_view.data;
	if (!lttng_buffer_view_contains_string(
		    &current_buffer_view, pattern, tracepoint_comm->pattern_len)) {
		ret = -1;
		goto end;
	}

	/* Skip after the pattern. */
	offset += tracepoint_comm->pattern_len;

	if (!tracepoint_comm->filter_expression_len) {
		goto skip_filter_expression;
	}

	/* Map the filter_expression. */
	current_buffer_view = lttng_buffer_view_from_view(
		&view->buffer, offset, tracepoint_comm->filter_expression_len);
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
	if (!tracepoint_comm->log_level_rule_len) {
		goto skip_log_level_rule;
	}

	{
		/* Map the log level rule. */
		struct lttng_payload_view current_payload_view = lttng_payload_view_from_view(
			view, offset, tracepoint_comm->log_level_rule_len);

		ret = lttng_log_level_rule_create_from_payload(&current_payload_view,
							       &log_level_rule);
		if (ret < 0) {
			ret = -1;
			goto end;
		}

		LTTNG_ASSERT(ret == tracepoint_comm->log_level_rule_len);
	}

	/* Skip after the log level rule. */
	offset += tracepoint_comm->log_level_rule_len;

skip_log_level_rule:
	for (i = 0; i < tracepoint_comm->exclusions_count; i++) {
		current_buffer_view =
			lttng_buffer_view_from_view(&view->buffer, offset, sizeof(*exclusion_len));
		if (!lttng_buffer_view_is_valid(&current_buffer_view)) {
			ret = -1;
			goto end;
		}

		exclusion_len = (typeof(exclusion_len)) current_buffer_view.data;
		offset += sizeof(*exclusion_len);

		current_buffer_view =
			lttng_buffer_view_from_view(&view->buffer, offset, *exclusion_len);
		if (!lttng_buffer_view_is_valid(&current_buffer_view)) {
			ret = -1;
			goto end;
		}

		exclusion = current_buffer_view.data;
		if (!lttng_buffer_view_contains_string(
			    &current_buffer_view, exclusion, *exclusion_len)) {
			ret = -1;
			goto end;
		}

		status = lttng_event_rule_user_tracepoint_add_name_pattern_exclusion(rule,
										     exclusion);
		if (status != LTTNG_EVENT_RULE_STATUS_OK) {
			ERR("Failed to add event rule user tracepoint exclusion \"%s\".",
			    exclusion);
			ret = -1;
			goto end;
		}

		/* Skip to next exclusion. */
		offset += *exclusion_len;
	}

	status = lttng_event_rule_user_tracepoint_set_name_pattern(rule, pattern);
	if (status != LTTNG_EVENT_RULE_STATUS_OK) {
		ERR("Failed to set event rule user tracepoint pattern.");
		ret = -1;
		goto end;
	}

	if (filter_expression) {
		status = lttng_event_rule_user_tracepoint_set_filter(rule, filter_expression);
		if (status != LTTNG_EVENT_RULE_STATUS_OK) {
			ERR("Failed to set event rule user tracepoint pattern.");
			ret = -1;
			goto end;
		}
	}

	if (log_level_rule) {
		status = lttng_event_rule_user_tracepoint_set_log_level_rule(rule, log_level_rule);
		if (status != LTTNG_EVENT_RULE_STATUS_OK) {
			ERR("Failed to set event rule user tracepoint log level rule.");
			ret = -1;
			goto end;
		}
	}

	*_event_rule = rule;
	rule = nullptr;
	ret = offset;
end:
	free(exclusions);
	lttng_log_level_rule_destroy(log_level_rule);
	lttng_event_rule_destroy(rule);
	return ret;
}

enum lttng_event_rule_status
lttng_event_rule_user_tracepoint_set_name_pattern(struct lttng_event_rule *rule,
						  const char *pattern)
{
	char *pattern_copy = nullptr;
	struct lttng_event_rule_user_tracepoint *tracepoint;
	enum lttng_event_rule_status status = LTTNG_EVENT_RULE_STATUS_OK;

	if (!rule || !IS_USER_TRACEPOINT_EVENT_RULE(rule) || !pattern || strlen(pattern) == 0) {
		status = LTTNG_EVENT_RULE_STATUS_INVALID;
		goto end;
	}

	tracepoint = lttng::utils::container_of(rule, &lttng_event_rule_user_tracepoint::parent);
	pattern_copy = strdup(pattern);
	if (!pattern_copy) {
		status = LTTNG_EVENT_RULE_STATUS_ERROR;
		goto end;
	}

	/* Normalize the pattern. */
	strutils_normalize_star_glob_pattern(pattern_copy);

	free(tracepoint->pattern);

	tracepoint->pattern = pattern_copy;
	pattern_copy = nullptr;
end:
	return status;
}

enum lttng_event_rule_status
lttng_event_rule_user_tracepoint_get_name_pattern(const struct lttng_event_rule *rule,
						  const char **pattern)
{
	struct lttng_event_rule_user_tracepoint *tracepoint;
	enum lttng_event_rule_status status = LTTNG_EVENT_RULE_STATUS_OK;

	if (!rule || !IS_USER_TRACEPOINT_EVENT_RULE(rule) || !pattern) {
		status = LTTNG_EVENT_RULE_STATUS_INVALID;
		goto end;
	}

	tracepoint = lttng::utils::container_of(rule, &lttng_event_rule_user_tracepoint::parent);
	if (!tracepoint->pattern) {
		status = LTTNG_EVENT_RULE_STATUS_UNSET;
		goto end;
	}

	*pattern = tracepoint->pattern;
end:
	return status;
}

enum lttng_event_rule_status
lttng_event_rule_user_tracepoint_set_filter(struct lttng_event_rule *rule, const char *expression)
{
	char *expression_copy = nullptr;
	struct lttng_event_rule_user_tracepoint *tracepoint;
	enum lttng_event_rule_status status = LTTNG_EVENT_RULE_STATUS_OK;

	if (!rule || !IS_USER_TRACEPOINT_EVENT_RULE(rule) || !expression ||
	    strlen(expression) == 0) {
		status = LTTNG_EVENT_RULE_STATUS_INVALID;
		goto end;
	}

	tracepoint = lttng::utils::container_of(rule, &lttng_event_rule_user_tracepoint::parent);
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
	expression_copy = nullptr;
end:
	return status;
}

enum lttng_event_rule_status
lttng_event_rule_user_tracepoint_get_filter(const struct lttng_event_rule *rule,
					    const char **expression)
{
	struct lttng_event_rule_user_tracepoint *tracepoint;
	enum lttng_event_rule_status status = LTTNG_EVENT_RULE_STATUS_OK;

	if (!rule || !IS_USER_TRACEPOINT_EVENT_RULE(rule) || !expression) {
		status = LTTNG_EVENT_RULE_STATUS_INVALID;
		goto end;
	}

	tracepoint = lttng::utils::container_of(rule, &lttng_event_rule_user_tracepoint::parent);
	if (!tracepoint->filter_expression) {
		status = LTTNG_EVENT_RULE_STATUS_UNSET;
		goto end;
	}

	*expression = tracepoint->filter_expression;
end:
	return status;
}

static bool log_level_rule_valid(const struct lttng_log_level_rule *rule)
{
	bool valid = false;
	enum lttng_log_level_rule_status status;
	int level;

	switch (lttng_log_level_rule_get_type(rule)) {
	case LTTNG_LOG_LEVEL_RULE_TYPE_EXACTLY:
		status = lttng_log_level_rule_exactly_get_level(rule, &level);
		break;
	case LTTNG_LOG_LEVEL_RULE_TYPE_AT_LEAST_AS_SEVERE_AS:
		status = lttng_log_level_rule_at_least_as_severe_as_get_level(rule, &level);
		break;
	default:
		abort();
	}

	LTTNG_ASSERT(status == LTTNG_LOG_LEVEL_RULE_STATUS_OK);

	if (level < LTTNG_LOGLEVEL_EMERG) {
		/* Invalid. */
		goto end;
	}
	if (level > LTTNG_LOGLEVEL_DEBUG) {
		/* Invalid. */
		goto end;
	}

	valid = true;

end:
	return valid;
}

enum lttng_event_rule_status lttng_event_rule_user_tracepoint_set_log_level_rule(
	struct lttng_event_rule *rule, const struct lttng_log_level_rule *log_level_rule)
{
	struct lttng_event_rule_user_tracepoint *tracepoint;
	enum lttng_event_rule_status status = LTTNG_EVENT_RULE_STATUS_OK;
	struct lttng_log_level_rule *copy = nullptr;

	if (!rule || !IS_USER_TRACEPOINT_EVENT_RULE(rule)) {
		status = LTTNG_EVENT_RULE_STATUS_INVALID;
		goto end;
	}

	tracepoint = lttng::utils::container_of(rule, &lttng_event_rule_user_tracepoint::parent);

	if (!log_level_rule_valid(log_level_rule)) {
		status = LTTNG_EVENT_RULE_STATUS_INVALID;
		goto end;
	}

	copy = lttng_log_level_rule_copy(log_level_rule);
	if (copy == nullptr) {
		status = LTTNG_EVENT_RULE_STATUS_ERROR;
		goto end;
	}

	if (tracepoint->log_level_rule) {
		lttng_log_level_rule_destroy(tracepoint->log_level_rule);
	}

	tracepoint->log_level_rule = copy;

end:
	return status;
}

enum lttng_event_rule_status lttng_event_rule_user_tracepoint_get_log_level_rule(
	const struct lttng_event_rule *rule, const struct lttng_log_level_rule **log_level_rule)
{
	struct lttng_event_rule_user_tracepoint *tracepoint;
	enum lttng_event_rule_status status = LTTNG_EVENT_RULE_STATUS_OK;

	if (!rule || !IS_USER_TRACEPOINT_EVENT_RULE(rule) || !log_level_rule) {
		status = LTTNG_EVENT_RULE_STATUS_INVALID;
		goto end;
	}

	tracepoint = lttng::utils::container_of(rule, &lttng_event_rule_user_tracepoint::parent);
	if (tracepoint->log_level_rule == nullptr) {
		status = LTTNG_EVENT_RULE_STATUS_UNSET;
		goto end;
	}

	*log_level_rule = tracepoint->log_level_rule;
end:
	return status;
}

enum lttng_event_rule_status
lttng_event_rule_user_tracepoint_add_name_pattern_exclusion(struct lttng_event_rule *rule,
							    const char *exclusion)
{
	int ret;
	char *exclusion_copy = nullptr;
	struct lttng_event_rule_user_tracepoint *tracepoint;
	enum lttng_event_rule_status status = LTTNG_EVENT_RULE_STATUS_OK;

	if (!rule || !IS_USER_TRACEPOINT_EVENT_RULE(rule) || !exclusion) {
		status = LTTNG_EVENT_RULE_STATUS_INVALID;
		goto end;
	}

	tracepoint = lttng::utils::container_of(rule, &lttng_event_rule_user_tracepoint::parent);

	if (strlen(exclusion) >= LTTNG_SYMBOL_NAME_LEN) {
		status = LTTNG_EVENT_RULE_STATUS_INVALID;
		goto end;
	}

	exclusion_copy = strdup(exclusion);
	if (!exclusion_copy) {
		status = LTTNG_EVENT_RULE_STATUS_ERROR;
		goto end;
	}

	ret = lttng_dynamic_pointer_array_add_pointer(&tracepoint->exclusions, exclusion_copy);
	if (ret < 0) {
		status = LTTNG_EVENT_RULE_STATUS_ERROR;
		goto end;
	}

	exclusion_copy = nullptr;
end:
	free(exclusion_copy);
	return status;
}

enum lttng_event_rule_status lttng_event_rule_user_tracepoint_get_name_pattern_exclusion_count(
	const struct lttng_event_rule *rule, unsigned int *count)
{
	struct lttng_event_rule_user_tracepoint *tracepoint;
	enum lttng_event_rule_status status = LTTNG_EVENT_RULE_STATUS_OK;

	if (!rule || !IS_USER_TRACEPOINT_EVENT_RULE(rule) || !count) {
		status = LTTNG_EVENT_RULE_STATUS_INVALID;
		goto end;
	}

	tracepoint = lttng::utils::container_of(rule, &lttng_event_rule_user_tracepoint::parent);
	*count = lttng_dynamic_pointer_array_get_count(&tracepoint->exclusions);
end:
	return status;
}

enum lttng_event_rule_status lttng_event_rule_user_tracepoint_get_name_pattern_exclusion_at_index(
	const struct lttng_event_rule *rule, unsigned int index, const char **exclusion)
{
	unsigned int count;
	struct lttng_event_rule_user_tracepoint *tracepoint;
	enum lttng_event_rule_status status = LTTNG_EVENT_RULE_STATUS_OK;

	if (!rule || !IS_USER_TRACEPOINT_EVENT_RULE(rule) || !exclusion) {
		status = LTTNG_EVENT_RULE_STATUS_INVALID;
		goto end;
	}

	tracepoint = lttng::utils::container_of(rule, &lttng_event_rule_user_tracepoint::parent);
	if (lttng_event_rule_user_tracepoint_get_name_pattern_exclusion_count(rule, &count) !=
	    LTTNG_EVENT_RULE_STATUS_OK) {
		goto end;
	}

	if (index >= count) {
		goto end;
	}

	*exclusion = (const char *) lttng_dynamic_pointer_array_get_pointer(&tracepoint->exclusions,
									    index);
end:
	return status;
}
