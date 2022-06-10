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
#include <common/payload-view.hpp>
#include <common/payload.hpp>
#include <common/runas.hpp>
#include <common/string-utils/string-utils.hpp>
#include <lttng/event-rule/event-rule-internal.hpp>
#include <lttng/event-rule/kernel-syscall-internal.hpp>

#define IS_SYSCALL_EVENT_RULE(rule) \
	(lttng_event_rule_get_type(rule) == LTTNG_EVENT_RULE_TYPE_KERNEL_SYSCALL)

static void lttng_event_rule_kernel_syscall_destroy(struct lttng_event_rule *rule)
{
	struct lttng_event_rule_kernel_syscall *syscall;

	if (rule == NULL) {
		return;
	}

	syscall = lttng::utils::container_of(rule, &lttng_event_rule_kernel_syscall::parent);

	free(syscall->pattern);
	free(syscall->filter_expression);
	free(syscall->internal_filter.filter);
	free(syscall->internal_filter.bytecode);
	free(syscall);
}

static bool lttng_event_rule_kernel_syscall_validate(
		const struct lttng_event_rule *rule)
{
	bool valid = false;
	struct lttng_event_rule_kernel_syscall *syscall;

	if (!rule) {
		goto end;
	}

	syscall = lttng::utils::container_of(rule, &lttng_event_rule_kernel_syscall::parent);

	/* Required field. */
	if (!syscall->pattern) {
		ERR("Invalid syscall event rule: a pattern must be set.");
		goto end;
	}

	valid = true;
end:
	return valid;
}

static int lttng_event_rule_kernel_syscall_serialize(
		const struct lttng_event_rule *rule,
		struct lttng_payload *payload)
{
	int ret;
	size_t pattern_len, filter_expression_len;
	struct lttng_event_rule_kernel_syscall *syscall;
	struct lttng_event_rule_kernel_syscall_comm syscall_comm;

	if (!rule || !IS_SYSCALL_EVENT_RULE(rule)) {
		ret = -1;
		goto end;
	}

	DBG("Serializing syscall event rule");
	syscall = lttng::utils::container_of(rule, &lttng_event_rule_kernel_syscall::parent);

	pattern_len = strlen(syscall->pattern) + 1;

	if (syscall->filter_expression != NULL) {
		filter_expression_len = strlen(syscall->filter_expression) + 1;
	} else {
		filter_expression_len = 0;
	}

	syscall_comm.pattern_len = pattern_len;
	syscall_comm.filter_expression_len = filter_expression_len;
	syscall_comm.emission_site = syscall->emission_site;

	ret = lttng_dynamic_buffer_append(
			&payload->buffer, &syscall_comm, sizeof(syscall_comm));
	if (ret) {
		goto end;
	}

	ret = lttng_dynamic_buffer_append(
			&payload->buffer, syscall->pattern, pattern_len);
	if (ret) {
		goto end;
	}

	ret = lttng_dynamic_buffer_append(&payload->buffer,
			syscall->filter_expression, filter_expression_len);
end:
	return ret;
}

static bool lttng_event_rule_kernel_syscall_is_equal(const struct lttng_event_rule *_a,
		const struct lttng_event_rule *_b)
{
	bool is_equal = false;
	struct lttng_event_rule_kernel_syscall *a, *b;

	a = lttng::utils::container_of(_a, &lttng_event_rule_kernel_syscall::parent);
	b = lttng::utils::container_of(_b, &lttng_event_rule_kernel_syscall::parent);

	if (!!a->filter_expression != !!b->filter_expression) {
		goto end;
	}

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
		/* One is set and not the other. */
		goto end;
	}

	is_equal = true;
end:
	return is_equal;
}

static enum lttng_error_code lttng_event_rule_kernel_syscall_generate_filter_bytecode(
		struct lttng_event_rule *rule,
		const struct lttng_credentials *creds)
{
	int ret;
	enum lttng_error_code ret_code = LTTNG_OK;
	struct lttng_event_rule_kernel_syscall *syscall;
	enum lttng_event_rule_status status;
	const char *filter;
	struct lttng_bytecode *bytecode = NULL;

	LTTNG_ASSERT(rule);

	syscall = lttng::utils::container_of(rule, &lttng_event_rule_kernel_syscall::parent);

	/* Generate the filter bytecode. */
	status = lttng_event_rule_kernel_syscall_get_filter(rule, &filter);
	if (status == LTTNG_EVENT_RULE_STATUS_UNSET) {
		filter = NULL;
	} else if (status != LTTNG_EVENT_RULE_STATUS_OK) {
		ret_code = LTTNG_ERR_FILTER_INVAL;
		goto end;
	}

	if (filter && filter[0] == '\0') {
		ret_code = LTTNG_ERR_FILTER_INVAL;
		goto end;
	}

	if (filter == NULL) {
		/* Nothing to do. */
		ret = LTTNG_OK;
		goto end;
	}

	syscall->internal_filter.filter = strdup(filter);
	if (syscall->internal_filter.filter == NULL) {
		ret_code = LTTNG_ERR_NOMEM;
		goto end;
	}

	ret = run_as_generate_filter_bytecode(
			syscall->internal_filter.filter, creds, &bytecode);
	if (ret) {
		ret_code = LTTNG_ERR_FILTER_INVAL;
	}

	syscall->internal_filter.bytecode = bytecode;
	bytecode = NULL;

end:
	free(bytecode);
	return ret_code;
}

static const char *lttng_event_rule_kernel_syscall_get_internal_filter(
		const struct lttng_event_rule *rule)
{
	struct lttng_event_rule_kernel_syscall *syscall;

	LTTNG_ASSERT(rule);
	syscall = lttng::utils::container_of(rule, &lttng_event_rule_kernel_syscall::parent);

	return syscall->internal_filter.filter;
}

static const struct lttng_bytecode *
lttng_event_rule_kernel_syscall_get_internal_filter_bytecode(
		const struct lttng_event_rule *rule)
{
	struct lttng_event_rule_kernel_syscall *syscall;

	LTTNG_ASSERT(rule);
	syscall = lttng::utils::container_of(rule, &lttng_event_rule_kernel_syscall::parent);

	return syscall->internal_filter.bytecode;
}

static enum lttng_event_rule_generate_exclusions_status
lttng_event_rule_kernel_syscall_generate_exclusions(
		const struct lttng_event_rule *rule __attribute__((unused)),
		struct lttng_event_exclusion **exclusions)
{
	/* Unsupported. */
	*exclusions = NULL;
	return LTTNG_EVENT_RULE_GENERATE_EXCLUSIONS_STATUS_NONE;
}

static unsigned long
lttng_event_rule_kernel_syscall_hash(
		const struct lttng_event_rule *rule)
{
	unsigned long hash;
	struct lttng_event_rule_kernel_syscall *syscall_rule =
			lttng::utils::container_of(rule, &lttng_event_rule_kernel_syscall::parent);

	hash = hash_key_ulong((void *) LTTNG_EVENT_RULE_TYPE_KERNEL_SYSCALL,
			lttng_ht_seed);
	hash ^= hash_key_str(syscall_rule->pattern, lttng_ht_seed);
	if (syscall_rule->filter_expression) {
		hash ^= hash_key_str(syscall_rule->filter_expression,
				lttng_ht_seed);
	}

	return hash;
}

static enum lttng_error_code lttng_event_rule_kernel_syscall_mi_serialize(
		const struct lttng_event_rule *rule, struct mi_writer *writer)
{
	int ret;
	enum lttng_error_code ret_code;
	enum lttng_event_rule_status status;

	enum lttng_event_rule_kernel_syscall_emission_site site_type;
	const char *filter = NULL;
	const char *name_pattern = NULL;
	const char *site_type_str = NULL;

	LTTNG_ASSERT(rule);
	LTTNG_ASSERT(writer);
	LTTNG_ASSERT(IS_SYSCALL_EVENT_RULE(rule));

	status = lttng_event_rule_kernel_syscall_get_name_pattern(
			rule, &name_pattern);
	LTTNG_ASSERT(status == LTTNG_EVENT_RULE_STATUS_OK);
	LTTNG_ASSERT(name_pattern);

	status = lttng_event_rule_kernel_syscall_get_filter(rule, &filter);
	LTTNG_ASSERT(status == LTTNG_EVENT_RULE_STATUS_OK ||
			status == LTTNG_EVENT_RULE_STATUS_UNSET);

	site_type = lttng_event_rule_kernel_syscall_get_emission_site(rule);

	switch (site_type) {
	case LTTNG_EVENT_RULE_KERNEL_SYSCALL_EMISSION_SITE_ENTRY_EXIT:
		site_type_str = mi_lttng_event_rule_kernel_syscall_emission_site_entry_exit;
		break;
	case LTTNG_EVENT_RULE_KERNEL_SYSCALL_EMISSION_SITE_ENTRY:
		site_type_str = mi_lttng_event_rule_kernel_syscall_emission_site_entry;
		break;
	case LTTNG_EVENT_RULE_KERNEL_SYSCALL_EMISSION_SITE_EXIT:
		site_type_str = mi_lttng_event_rule_kernel_syscall_emission_site_exit;
		break;
	default:
		abort();
		break;
	}

	/* Open event rule kernel syscall element. */
	ret = mi_lttng_writer_open_element(
			writer, mi_lttng_element_event_rule_kernel_syscall);
	if (ret) {
		goto mi_error;
	}

	/* Emission site. */
	ret = mi_lttng_writer_write_element_string(writer,
			mi_lttng_element_event_rule_kernel_syscall_emission_site,
			site_type_str);
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

	/* Close event rule kernel syscall. */
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

struct lttng_event_rule *lttng_event_rule_kernel_syscall_create(
		enum lttng_event_rule_kernel_syscall_emission_site
				emission_site)
{
	struct lttng_event_rule *rule = NULL;
	struct lttng_event_rule_kernel_syscall *syscall_rule;
	enum lttng_event_rule_status status;

	/* Validate the emission site type */
	switch (emission_site) {
	case LTTNG_EVENT_RULE_KERNEL_SYSCALL_EMISSION_SITE_ENTRY_EXIT:
	case LTTNG_EVENT_RULE_KERNEL_SYSCALL_EMISSION_SITE_ENTRY:
	case LTTNG_EVENT_RULE_KERNEL_SYSCALL_EMISSION_SITE_EXIT:
		break;
	default:
		/* Invalid emission type */
		goto end;
	}

	syscall_rule = zmalloc<lttng_event_rule_kernel_syscall>();
	if (!syscall_rule) {
		goto end;
	}

	rule = &syscall_rule->parent;
	lttng_event_rule_init(
			&syscall_rule->parent, LTTNG_EVENT_RULE_TYPE_KERNEL_SYSCALL);
	syscall_rule->parent.validate = lttng_event_rule_kernel_syscall_validate;
	syscall_rule->parent.serialize = lttng_event_rule_kernel_syscall_serialize;
	syscall_rule->parent.equal = lttng_event_rule_kernel_syscall_is_equal;
	syscall_rule->parent.destroy = lttng_event_rule_kernel_syscall_destroy;
	syscall_rule->parent.generate_filter_bytecode =
			lttng_event_rule_kernel_syscall_generate_filter_bytecode;
	syscall_rule->parent.get_filter =
			lttng_event_rule_kernel_syscall_get_internal_filter;
	syscall_rule->parent.get_filter_bytecode =
			lttng_event_rule_kernel_syscall_get_internal_filter_bytecode;
	syscall_rule->parent.generate_exclusions =
			lttng_event_rule_kernel_syscall_generate_exclusions;
	syscall_rule->parent.hash = lttng_event_rule_kernel_syscall_hash;
	syscall_rule->parent.mi_serialize = lttng_event_rule_kernel_syscall_mi_serialize;

	/* Default pattern is '*'. */
	status = lttng_event_rule_kernel_syscall_set_name_pattern(rule, "*");
	if (status != LTTNG_EVENT_RULE_STATUS_OK) {
		lttng_event_rule_destroy(rule);
		rule = NULL;
	}

	/* Emission site type */
	syscall_rule->emission_site = emission_site;

end:
	return rule;
}

ssize_t lttng_event_rule_kernel_syscall_create_from_payload(
		struct lttng_payload_view *view,
		struct lttng_event_rule **_event_rule)
{
	ssize_t ret, offset = 0;
	enum lttng_event_rule_status status;
	const struct lttng_event_rule_kernel_syscall_comm *syscall_comm;
	const char *pattern;
	const char *filter_expression = NULL;
	struct lttng_buffer_view current_buffer_view;
	struct lttng_event_rule *rule = NULL;

	if (!_event_rule) {
		ret = -1;
		goto end;
	}

	if (view->buffer.size < sizeof(*syscall_comm)) {
		ERR("Failed to initialize from malformed event rule syscall: buffer too short to contain header");
		ret = -1;
		goto end;
	}

	current_buffer_view = lttng_buffer_view_from_view(
			&view->buffer, offset, sizeof(*syscall_comm));
	if (!lttng_buffer_view_is_valid(&current_buffer_view)) {
		ret = -1;
		goto end;
	}

	syscall_comm = (typeof(syscall_comm)) current_buffer_view.data;
	rule = lttng_event_rule_kernel_syscall_create((lttng_event_rule_kernel_syscall_emission_site) syscall_comm->emission_site);
	if (!rule) {
		ERR("Failed to create event rule syscall");
		ret = -1;
		goto end;
	}

	/* Skip to payload. */
	offset += current_buffer_view.size;

	/* Map the pattern. */
	current_buffer_view = lttng_buffer_view_from_view(
			&view->buffer, offset, syscall_comm->pattern_len);
	if (!lttng_buffer_view_is_valid(&current_buffer_view)) {
		ret = -1;
		goto end;
	}

	pattern = current_buffer_view.data;
	if (!lttng_buffer_view_contains_string(&current_buffer_view, pattern,
			syscall_comm->pattern_len)) {
		ret = -1;
		goto end;
	}

	/* Skip after the pattern. */
	offset += syscall_comm->pattern_len;

	if (!syscall_comm->filter_expression_len) {
		goto skip_filter_expression;
	}

	/* Map the filter_expression. */
	current_buffer_view = lttng_buffer_view_from_view(&view->buffer, offset,
			syscall_comm->filter_expression_len);
	if (!lttng_buffer_view_is_valid(&current_buffer_view)) {
		ret = -1;
		goto end;
	}

	filter_expression = current_buffer_view.data;
	if (!lttng_buffer_view_contains_string(&current_buffer_view,
				filter_expression,
				syscall_comm->filter_expression_len)) {
		ret = -1;
		goto end;
	}

	/* Skip after the pattern. */
	offset += syscall_comm->filter_expression_len;

skip_filter_expression:

	status = lttng_event_rule_kernel_syscall_set_name_pattern(rule, pattern);
	if (status != LTTNG_EVENT_RULE_STATUS_OK) {
		ERR("Failed to set event rule syscall pattern");
		ret = -1;
		goto end;
	}

	if (filter_expression) {
		status = lttng_event_rule_kernel_syscall_set_filter(
				rule, filter_expression);
		if (status != LTTNG_EVENT_RULE_STATUS_OK) {
			ERR("Failed to set event rule syscall pattern");
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

enum lttng_event_rule_status lttng_event_rule_kernel_syscall_set_name_pattern(
		struct lttng_event_rule *rule, const char *pattern)
{
	char *pattern_copy = NULL;
	struct lttng_event_rule_kernel_syscall *syscall;
	enum lttng_event_rule_status status = LTTNG_EVENT_RULE_STATUS_OK;

	if (!rule || !IS_SYSCALL_EVENT_RULE(rule) || !pattern ||
			strlen(pattern) == 0) {
		status = LTTNG_EVENT_RULE_STATUS_INVALID;
		goto end;
	}

	syscall = lttng::utils::container_of(rule, &lttng_event_rule_kernel_syscall::parent);
	pattern_copy = strdup(pattern);
	if (!pattern_copy) {
		status = LTTNG_EVENT_RULE_STATUS_ERROR;
		goto end;
	}

	strutils_normalize_star_glob_pattern(pattern_copy);

	free(syscall->pattern);

	syscall->pattern = pattern_copy;
	pattern_copy = NULL;
end:
	return status;
}

enum lttng_event_rule_status lttng_event_rule_kernel_syscall_get_name_pattern(
		const struct lttng_event_rule *rule, const char **pattern)
{
	struct lttng_event_rule_kernel_syscall *syscall;
	enum lttng_event_rule_status status = LTTNG_EVENT_RULE_STATUS_OK;

	if (!rule || !IS_SYSCALL_EVENT_RULE(rule) || !pattern) {
		status = LTTNG_EVENT_RULE_STATUS_INVALID;
		goto end;
	}

	syscall = lttng::utils::container_of(rule, &lttng_event_rule_kernel_syscall::parent);
	if (!syscall->pattern) {
		status = LTTNG_EVENT_RULE_STATUS_UNSET;
		goto end;
	}

	*pattern = syscall->pattern;
end:
	return status;
}

enum lttng_event_rule_status lttng_event_rule_kernel_syscall_set_filter(
		struct lttng_event_rule *rule, const char *expression)
{
	char *expression_copy = NULL;
	struct lttng_event_rule_kernel_syscall *syscall;
	enum lttng_event_rule_status status = LTTNG_EVENT_RULE_STATUS_OK;

	/* TODO: validate that the passed expression is valid. */

	if (!rule || !IS_SYSCALL_EVENT_RULE(rule) || !expression ||
			strlen(expression) == 0) {
		status = LTTNG_EVENT_RULE_STATUS_INVALID;
		goto end;
	}

	syscall = lttng::utils::container_of(rule, &lttng_event_rule_kernel_syscall::parent);
	expression_copy = strdup(expression);
	if (!expression_copy) {
		status = LTTNG_EVENT_RULE_STATUS_ERROR;
		goto end;
	}

	if (syscall->filter_expression) {
		free(syscall->filter_expression);
	}

	syscall->filter_expression = expression_copy;
	expression_copy = NULL;
end:
	return status;
}

enum lttng_event_rule_status lttng_event_rule_kernel_syscall_get_filter(
		const struct lttng_event_rule *rule, const char **expression)
{
	struct lttng_event_rule_kernel_syscall *syscall;
	enum lttng_event_rule_status status = LTTNG_EVENT_RULE_STATUS_OK;

	if (!rule || !IS_SYSCALL_EVENT_RULE(rule) || !expression) {
		status = LTTNG_EVENT_RULE_STATUS_INVALID;
		goto end;
	}

	syscall = lttng::utils::container_of(rule, &lttng_event_rule_kernel_syscall::parent);
	if (!syscall->filter_expression) {
		status = LTTNG_EVENT_RULE_STATUS_UNSET;
		goto end;
	}

	*expression = syscall->filter_expression;
end:
	return status;
}
extern enum lttng_event_rule_kernel_syscall_emission_site
lttng_event_rule_kernel_syscall_get_emission_site(
		const struct lttng_event_rule *rule)
{
	enum lttng_event_rule_kernel_syscall_emission_site emission_site =
		LTTNG_EVENT_RULE_KERNEL_SYSCALL_EMISSION_SITE_UNKNOWN;
	struct lttng_event_rule_kernel_syscall *syscall;

	if (!rule || !IS_SYSCALL_EVENT_RULE(rule)) {
		goto end;
	}

	syscall = lttng::utils::container_of(rule, &lttng_event_rule_kernel_syscall::parent);
	emission_site = syscall->emission_site;

end:
	return emission_site;
}

const char *lttng_event_rule_kernel_syscall_emission_site_str(
		enum lttng_event_rule_kernel_syscall_emission_site emission_site)
{
	switch (emission_site) {
	case LTTNG_EVENT_RULE_KERNEL_SYSCALL_EMISSION_SITE_ENTRY:
		return "entry";
	case LTTNG_EVENT_RULE_KERNEL_SYSCALL_EMISSION_SITE_ENTRY_EXIT:
		return "entry+exit";
	case LTTNG_EVENT_RULE_KERNEL_SYSCALL_EMISSION_SITE_EXIT:
		return "exit";
	default:
		return "???";
	}
}
