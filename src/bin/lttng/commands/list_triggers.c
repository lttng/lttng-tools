/*
 * Copyright (C) 2021 Simon Marchi <simon.marchi@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include <stdio.h>

#include "../command.h"

#include "common/argpar/argpar.h"
#include "common/dynamic-array.h"
#include "common/mi-lttng.h"
/* For lttng_condition_type_str(). */
#include "lttng/condition/condition-internal.h"
#include "lttng/condition/event-rule-matches.h"
#include "lttng/condition/event-rule-matches-internal.h"
/* For lttng_domain_type_str(). */
#include "lttng/domain-internal.h"
/* For lttng_event_rule_syscall_emission_site_str() */
#include "lttng/event-rule/syscall-internal.h"
#include "../loglevel.h"
#include <lttng/lttng.h>

#ifdef LTTNG_EMBED_HELP
static const char help_msg[] =
#include <lttng-list-triggers.1.h>
;
#endif

enum {
	OPT_HELP,
	OPT_LIST_OPTIONS,
};

static const
struct argpar_opt_descr list_trigger_options[] = {
	{ OPT_HELP, 'h', "help", false },
	{ OPT_LIST_OPTIONS, '\0', "list-options", false },
	ARGPAR_OPT_DESCR_SENTINEL,
};

static void print_condition_session_consumed_size(
		const struct lttng_condition *condition)
{
	enum lttng_condition_status condition_status;
	const char *session_name;
	uint64_t threshold;

	condition_status =
			lttng_condition_session_consumed_size_get_session_name(
					condition, &session_name);
	assert(condition_status == LTTNG_CONDITION_STATUS_OK);

	lttng_condition_session_consumed_size_get_threshold(
			condition, &threshold);
	assert(condition_status == LTTNG_CONDITION_STATUS_OK);

	MSG("    session name: %s", session_name);
	MSG("    threshold: %" PRIu64 " bytes", threshold);
}

static void print_condition_buffer_usage(
		const struct lttng_condition *condition)
{
	enum lttng_condition_status condition_status;
	const char *session_name, *channel_name;
	enum lttng_domain_type domain_type;
	uint64_t threshold;

	condition_status = lttng_condition_buffer_usage_get_session_name(
			condition, &session_name);
	assert(condition_status == LTTNG_CONDITION_STATUS_OK);

	condition_status = lttng_condition_buffer_usage_get_channel_name(
			condition, &channel_name);
	assert(condition_status == LTTNG_CONDITION_STATUS_OK);

	condition_status = lttng_condition_buffer_usage_get_domain_type(
			condition, &domain_type);
	assert(condition_status == LTTNG_CONDITION_STATUS_OK);

	MSG("    session name: %s", session_name);
	MSG("    channel name: %s", channel_name);
	MSG("    domain: %s", lttng_domain_type_str(domain_type));

	condition_status = lttng_condition_buffer_usage_get_threshold(
			condition, &threshold);
	if (condition_status == LTTNG_CONDITION_STATUS_OK) {
		MSG("    threshold (bytes): %" PRIu64, threshold);
	} else {
		double threshold_ratio;

		assert(condition_status == LTTNG_CONDITION_STATUS_UNSET);

		condition_status =
				lttng_condition_buffer_usage_get_threshold_ratio(
						condition, &threshold_ratio);
		assert(condition_status == LTTNG_CONDITION_STATUS_OK);

		MSG("    threshold (ratio): %.2f", threshold_ratio);
	}
}

static void print_condition_session_rotation(
		const struct lttng_condition *condition)
{
	enum lttng_condition_status condition_status;
	const char *session_name;

	condition_status = lttng_condition_session_rotation_get_session_name(
			condition, &session_name);
	assert(condition_status == LTTNG_CONDITION_STATUS_OK);

	MSG("    session name: %s", session_name);
}

/*
 * Returns the human-readable log level name associated with a numerical value
 * if there is one. The Log4j and JUL domains have discontinuous log level
 * values (a value can fall between two labels). In those cases, NULL is
 * returned.
 */
static const char *get_pretty_loglevel_name(
		enum lttng_domain_type domain, int loglevel)
{
	const char *name = NULL;

	switch (domain) {
	case LTTNG_DOMAIN_UST:
		name = loglevel_value_to_name(loglevel);
		break;
	case LTTNG_DOMAIN_LOG4J:
		name = loglevel_log4j_value_to_name(loglevel);
		break;
	case LTTNG_DOMAIN_JUL:
		name = loglevel_jul_value_to_name(loglevel);
		break;
	case LTTNG_DOMAIN_PYTHON:
		name = loglevel_python_value_to_name(loglevel);
		break;
	default:
		break;
	}

	return name;
}

static
void print_event_rule_tracepoint(const struct lttng_event_rule *event_rule)
{
	enum lttng_event_rule_status event_rule_status;
	enum lttng_domain_type domain_type;
	const char *pattern;
	const char *filter;
	int log_level;
	const struct lttng_log_level_rule *log_level_rule = NULL;
	unsigned int exclusions_count;
	int i;

	event_rule_status = lttng_event_rule_tracepoint_get_pattern(
			event_rule, &pattern);
	assert(event_rule_status == LTTNG_EVENT_RULE_STATUS_OK);

	event_rule_status = lttng_event_rule_tracepoint_get_domain_type(
			event_rule, &domain_type);
	assert(event_rule_status == LTTNG_EVENT_RULE_STATUS_OK);

	_MSG("    rule: %s (type: tracepoint, domain: %s", pattern,
			lttng_domain_type_str(domain_type));

	event_rule_status = lttng_event_rule_tracepoint_get_filter(
			event_rule, &filter);
	if (event_rule_status == LTTNG_EVENT_RULE_STATUS_OK) {
		_MSG(", filter: %s", filter);
	} else {
		assert(event_rule_status == LTTNG_EVENT_RULE_STATUS_UNSET);
	}

	event_rule_status = lttng_event_rule_tracepoint_get_log_level_rule(
			event_rule, &log_level_rule);
	if (event_rule_status == LTTNG_EVENT_RULE_STATUS_OK) {
		enum lttng_log_level_rule_status llr_status;
		const char *log_level_op;
		const char *pretty_loglevel_name;

		switch (lttng_log_level_rule_get_type(log_level_rule)) {
		case LTTNG_LOG_LEVEL_RULE_TYPE_EXACTLY:
			log_level_op = "is";
			llr_status = lttng_log_level_rule_exactly_get_level(
					log_level_rule, &log_level);
			break;
		case LTTNG_LOG_LEVEL_RULE_TYPE_AT_LEAST_AS_SEVERE_AS:
			log_level_op = "at least";
			llr_status = lttng_log_level_rule_at_least_as_severe_as_get_level(
					log_level_rule, &log_level);
			break;
		default:
			abort();
		}

		assert(llr_status == LTTNG_LOG_LEVEL_RULE_STATUS_OK);

		pretty_loglevel_name = get_pretty_loglevel_name(
				domain_type, log_level);
		if (pretty_loglevel_name) {
			_MSG(", log level %s %s", log_level_op,
					pretty_loglevel_name);
		} else {
			_MSG(", log level %s %d", log_level_op, log_level);
		}
	} else {
		assert(event_rule_status == LTTNG_EVENT_RULE_STATUS_UNSET);
	}

	event_rule_status = lttng_event_rule_tracepoint_get_exclusions_count(
			event_rule, &exclusions_count);
	assert(event_rule_status == LTTNG_EVENT_RULE_STATUS_OK);
	if (exclusions_count > 0) {
		_MSG(", exclusions: ");
		for (i = 0; i < exclusions_count; i++) {
			const char *exclusion;

			event_rule_status = lttng_event_rule_tracepoint_get_exclusion_at_index(
					event_rule, i, &exclusion);
			assert(event_rule_status == LTTNG_EVENT_RULE_STATUS_OK);

			_MSG("%s%s", i > 0 ? "," : "", exclusion);
		}
	}

	MSG(")");
}

static void print_kernel_probe_location(
		const struct lttng_kernel_probe_location *location)
{
	enum lttng_kernel_probe_location_status status;
	switch (lttng_kernel_probe_location_get_type(location)) {
	case LTTNG_KERNEL_PROBE_LOCATION_TYPE_ADDRESS:
	{
		uint64_t address;

		status = lttng_kernel_probe_location_address_get_address(
				location, &address);
		if (status != LTTNG_KERNEL_PROBE_LOCATION_STATUS_OK) {
			ERR("Getting kernel probe location address failed.");
			goto end;
		}

		_MSG("0x%" PRIx64, address);

		break;
	}
	case LTTNG_KERNEL_PROBE_LOCATION_TYPE_SYMBOL_OFFSET:
	{
		uint64_t offset;
		const char *symbol_name;

		symbol_name = lttng_kernel_probe_location_symbol_get_name(
				location);
		if (!symbol_name) {
			ERR("Getting kernel probe location symbol name failed.");
			goto end;
		}

		status = lttng_kernel_probe_location_symbol_get_offset(
				location, &offset);
		if (status != LTTNG_KERNEL_PROBE_LOCATION_STATUS_OK) {
			ERR("Getting kernel probe location address failed.");
			goto end;
		}

		if (offset == 0) {
			_MSG("%s", symbol_name);
		} else {
			_MSG("%s+0x%" PRIx64, symbol_name, offset);
		}

		break;
	}
	default:
		abort();
	};
end:
	return;
}

static
void print_event_rule_kernel_probe(const struct lttng_event_rule *event_rule)
{
	enum lttng_event_rule_status event_rule_status;
	const char *name;
	const struct lttng_kernel_probe_location *location;

	assert(lttng_event_rule_get_type(event_rule) == LTTNG_EVENT_RULE_TYPE_KERNEL_PROBE);

	event_rule_status = lttng_event_rule_kernel_probe_get_event_name(event_rule, &name);
	if (event_rule_status != LTTNG_EVENT_RULE_STATUS_OK) {
		ERR("Failed to get kprobe event rule's name.");
		goto end;
	}

	event_rule_status = lttng_event_rule_kernel_probe_get_location(
			event_rule, &location);
	if (event_rule_status != LTTNG_EVENT_RULE_STATUS_OK) {
		ERR("Failed to get kprobe event rule's location.");
		goto end;
	}

	_MSG("    rule: %s (type: probe, location: ", name);

	print_kernel_probe_location(location);

	MSG(")");

end:
	return;
}

static
void print_event_rule_userspace_probe(const struct lttng_event_rule *event_rule)
{
	enum lttng_event_rule_status event_rule_status;
	const char *name;
	const struct lttng_userspace_probe_location *location;
	enum lttng_userspace_probe_location_type userspace_probe_location_type;

	assert(lttng_event_rule_get_type(event_rule) == LTTNG_EVENT_RULE_TYPE_USERSPACE_PROBE);

	event_rule_status = lttng_event_rule_userspace_probe_get_event_name(
			event_rule, &name);
	if (event_rule_status != LTTNG_EVENT_RULE_STATUS_OK) {
		ERR("Failed to get uprobe event rule's name.");
		goto end;
	}

	event_rule_status = lttng_event_rule_userspace_probe_get_location(
			event_rule, &location);
	if (event_rule_status != LTTNG_EVENT_RULE_STATUS_OK) {
		ERR("Failed to get uprobe event rule's location.");
		goto end;
	}

	_MSG("    rule: %s (type: userspace probe, ", name);

	userspace_probe_location_type =
			lttng_userspace_probe_location_get_type(location);

	switch (userspace_probe_location_type) {
	case LTTNG_USERSPACE_PROBE_LOCATION_TYPE_FUNCTION:
	{
		const char *binary_path, *function_name;

		binary_path = lttng_userspace_probe_location_function_get_binary_path(
				location);
		function_name = lttng_userspace_probe_location_function_get_function_name(
				location);

		_MSG("location type: ELF, location: %s:%s", binary_path, function_name);
		break;
	}
	case LTTNG_USERSPACE_PROBE_LOCATION_TYPE_TRACEPOINT:
	{
		const char *binary_path, *provider_name, *probe_name;

		binary_path = lttng_userspace_probe_location_tracepoint_get_binary_path(
				location);
		provider_name = lttng_userspace_probe_location_tracepoint_get_provider_name(
				location);
		probe_name = lttng_userspace_probe_location_tracepoint_get_probe_name(
				location);
		_MSG("location type: SDT, location: %s:%s:%s", binary_path, provider_name, probe_name);
		break;
	}
	default:
		abort();
	}

	MSG(")");

end:
	return;
}

static
void print_event_rule_syscall(const struct lttng_event_rule *event_rule)
{
	const char *pattern, *filter;
	enum lttng_event_rule_status event_rule_status;
	enum lttng_event_rule_syscall_emission_site_type emission_site_type;

	assert(lttng_event_rule_get_type(event_rule) == LTTNG_EVENT_RULE_TYPE_SYSCALL);

	emission_site_type =
		lttng_event_rule_syscall_get_emission_site_type(event_rule);

	event_rule_status = lttng_event_rule_syscall_get_pattern(
			event_rule, &pattern);
	assert(event_rule_status == LTTNG_EVENT_RULE_STATUS_OK);

	_MSG("    rule: %s (type: syscall:%s", pattern,
			lttng_event_rule_syscall_emission_site_str(
					emission_site_type));

	event_rule_status = lttng_event_rule_syscall_get_filter(
			event_rule, &filter);
	if (event_rule_status == LTTNG_EVENT_RULE_STATUS_OK) {
		_MSG(", filter: %s", filter);
	} else {
		assert(event_rule_status == LTTNG_EVENT_RULE_STATUS_UNSET);
	}

	MSG(")");
}

static
void print_event_rule(const struct lttng_event_rule *event_rule)
{
	const enum lttng_event_rule_type event_rule_type =
			lttng_event_rule_get_type(event_rule);

	switch (event_rule_type) {
	case LTTNG_EVENT_RULE_TYPE_TRACEPOINT:
		print_event_rule_tracepoint(event_rule);
		break;
	case LTTNG_EVENT_RULE_TYPE_KERNEL_PROBE:
		print_event_rule_kernel_probe(event_rule);
		break;
	case LTTNG_EVENT_RULE_TYPE_USERSPACE_PROBE:
		print_event_rule_userspace_probe(event_rule);
		break;
	case LTTNG_EVENT_RULE_TYPE_SYSCALL:
		print_event_rule_syscall(event_rule);
		break;
	default:
		abort();
	}
}

static
void print_one_event_expr(const struct lttng_event_expr *event_expr)
{
	enum lttng_event_expr_type type;

	type = lttng_event_expr_get_type(event_expr);

	switch (type) {
	case LTTNG_EVENT_EXPR_TYPE_EVENT_PAYLOAD_FIELD:
	{
		const char *name;

		name = lttng_event_expr_event_payload_field_get_name(
				event_expr);
		_MSG("%s", name);

		break;
	}
	case LTTNG_EVENT_EXPR_TYPE_CHANNEL_CONTEXT_FIELD:
	{
		const char *name;

		name = lttng_event_expr_channel_context_field_get_name(
				event_expr);
		_MSG("$ctx.%s", name);

		break;
	}
	case LTTNG_EVENT_EXPR_TYPE_APP_SPECIFIC_CONTEXT_FIELD:
	{
		const char *provider_name;
		const char *type_name;

		provider_name = lttng_event_expr_app_specific_context_field_get_provider_name(
				event_expr);
		type_name = lttng_event_expr_app_specific_context_field_get_type_name(
				event_expr);

		_MSG("$app.%s:%s", provider_name, type_name);

		break;
	}
	case LTTNG_EVENT_EXPR_TYPE_ARRAY_FIELD_ELEMENT:
	{
		unsigned int index;
		const struct lttng_event_expr *parent_expr;
		enum lttng_event_expr_status status;

		parent_expr = lttng_event_expr_array_field_element_get_parent_expr(
				event_expr);
		assert(parent_expr != NULL);

		print_one_event_expr(parent_expr);

		status = lttng_event_expr_array_field_element_get_index(
				event_expr, &index);
		assert(status == LTTNG_EVENT_EXPR_STATUS_OK);

		_MSG("[%u]", index);

		break;
	}
	default:
		abort();
	}
}

static void print_condition_event_rule_matches(
		const struct lttng_condition *condition)
{
	const struct lttng_event_rule *event_rule;
	enum lttng_condition_status condition_status;
	unsigned int cap_desc_count, i;

	condition_status = lttng_condition_event_rule_matches_get_rule(
			condition, &event_rule);
	assert(condition_status == LTTNG_CONDITION_STATUS_OK);

	print_event_rule(event_rule);

	condition_status =
			lttng_condition_event_rule_matches_get_capture_descriptor_count(
					condition, &cap_desc_count);
	assert(condition_status == LTTNG_CONDITION_STATUS_OK);

	if (cap_desc_count > 0) {
		MSG("    captures:");

		for (i = 0; i < cap_desc_count; i++) {
			const struct lttng_event_expr *cap_desc =
					lttng_condition_event_rule_matches_get_capture_descriptor_at_index(
							condition, i);

			_MSG("      - ");
			print_one_event_expr(cap_desc);
			MSG("");
		}
	}
}

static
void print_action_errors(const struct lttng_trigger *trigger,
		const struct lttng_action *action)
{
	unsigned int i, count, printed_errors_count = 0;
	enum lttng_error_code error_query_ret;
	enum lttng_error_query_results_status results_status;
	struct lttng_error_query_results *results = NULL;
	const char *trigger_name;
	uid_t trigger_uid;
	enum lttng_trigger_status trigger_status;
	struct lttng_error_query *query =
			lttng_error_query_action_create(trigger, action);

	assert(query);

	trigger_status = lttng_trigger_get_name(trigger, &trigger_name);
	/*
	 * Anonymous triggers are not listed; this would be an internal error.
	 */
	assert(trigger_status == LTTNG_TRIGGER_STATUS_OK);

	trigger_status = lttng_trigger_get_owner_uid(trigger, &trigger_uid);
	assert(trigger_status == LTTNG_TRIGGER_STATUS_OK);

	error_query_ret = lttng_error_query_execute(
			query, lttng_session_daemon_command_endpoint, &results);
	if (error_query_ret != LTTNG_OK) {
		ERR("Failed to query errors of trigger '%s' (owner uid: %d): %s",
				trigger_name, (int) trigger_uid,
				lttng_strerror(-error_query_ret));
		goto end;
	}

	results_status = lttng_error_query_results_get_count(results, &count);
	assert(results_status == LTTNG_ERROR_QUERY_RESULTS_STATUS_OK);

	_MSG("      errors:");

	for (i = 0; i < count; i++) {
		const struct lttng_error_query_result *result;
		enum lttng_error_query_result_status result_status;
		const char *result_name;
		const char *result_description;
		uint64_t result_value;

		results_status = lttng_error_query_results_get_result(
				results, &result, i);
		assert(results_status == LTTNG_ERROR_QUERY_RESULTS_STATUS_OK);

		result_status = lttng_error_query_result_get_name(
				result, &result_name);
		assert(result_status == LTTNG_ERROR_QUERY_RESULT_STATUS_OK);
		result_status = lttng_error_query_result_get_description(
				result, &result_description);
		assert(result_status == LTTNG_ERROR_QUERY_RESULT_STATUS_OK);

		if (lttng_error_query_result_get_type(result) ==
				LTTNG_ERROR_QUERY_RESULT_TYPE_COUNTER) {
			result_status = lttng_error_query_result_counter_get_value(
					result, &result_value);
			assert(result_status ==
					LTTNG_ERROR_QUERY_RESULT_STATUS_OK);
			if (result_value == 0) {
				continue;
			}

			MSG("");
			_MSG("        %s: %" PRIu64, result_name,
					result_value);
			printed_errors_count++;
		} else {
			_MSG("        Unknown error query result type for result '%s' (%s)",
					result_name, result_description);
			continue;
		}
	}

	if (printed_errors_count == 0) {
		_MSG(" none");
	}

end:
	MSG("");
	lttng_error_query_destroy(query);
	lttng_error_query_results_destroy(results);
}

static
void print_one_action(const struct lttng_trigger *trigger,
		const struct lttng_action *action)
{
	enum lttng_action_type action_type;
	enum lttng_action_status action_status;
	const struct lttng_rate_policy *policy = NULL;
	const char *value;

	action_type = lttng_action_get_type(action);
	assert(action_type != LTTNG_ACTION_TYPE_GROUP);

	switch (action_type) {
	case LTTNG_ACTION_TYPE_NOTIFY:
		_MSG("notify");

		action_status = lttng_action_notify_get_rate_policy(
				action, &policy);
		if (action_status != LTTNG_ACTION_STATUS_OK) {
			ERR("Failed to retrieve rate policy.");
			goto end;
		}
		break;
	case LTTNG_ACTION_TYPE_START_SESSION:
		action_status = lttng_action_start_session_get_session_name(
				action, &value);
		assert(action_status == LTTNG_ACTION_STATUS_OK);
		_MSG("start session `%s`", value);

		action_status = lttng_action_start_session_get_rate_policy(
				action, &policy);
		if (action_status != LTTNG_ACTION_STATUS_OK) {
			ERR("Failed to retrieve rate policy.");
			goto end;
		}
		break;
	case LTTNG_ACTION_TYPE_STOP_SESSION:
		action_status = lttng_action_stop_session_get_session_name(
				action, &value);
		assert(action_status == LTTNG_ACTION_STATUS_OK);
		_MSG("stop session `%s`", value);

		action_status = lttng_action_stop_session_get_rate_policy(
				action, &policy);
		if (action_status != LTTNG_ACTION_STATUS_OK) {
			ERR("Failed to retrieve rate policy.");
			goto end;
		}
		break;
	case LTTNG_ACTION_TYPE_ROTATE_SESSION:
		action_status = lttng_action_rotate_session_get_session_name(
				action, &value);
		assert(action_status == LTTNG_ACTION_STATUS_OK);
		_MSG("rotate session `%s`", value);

		action_status = lttng_action_rotate_session_get_rate_policy(
				action, &policy);
		if (action_status != LTTNG_ACTION_STATUS_OK) {
			ERR("Failed to retrieve rate policy.");
			goto end;
		}
		break;
	case LTTNG_ACTION_TYPE_SNAPSHOT_SESSION:
	{
		const struct lttng_snapshot_output *output;

		action_status = lttng_action_snapshot_session_get_session_name(
				action, &value);
		assert(action_status == LTTNG_ACTION_STATUS_OK);
		_MSG("snapshot session `%s`", value);

		action_status = lttng_action_snapshot_session_get_output(
				action, &output);
		if (action_status == LTTNG_ACTION_STATUS_OK) {
			const char *name;
			uint64_t max_size;
			const char *ctrl_url, *data_url;
			bool starts_with_file, starts_with_net, starts_with_net6;

			ctrl_url = lttng_snapshot_output_get_ctrl_url(output);
			assert(ctrl_url && strlen(ctrl_url) > 0);

			data_url = lttng_snapshot_output_get_data_url(output);
			assert(data_url);

			starts_with_file = strncmp(ctrl_url, "file://", strlen("file://")) == 0;
			starts_with_net = strncmp(ctrl_url, "net://", strlen("net://")) == 0;
			starts_with_net6 = strncmp(ctrl_url, "net6://", strlen("net6://")) == 0;

			if (ctrl_url[0] == '/' || starts_with_file) {
				if (starts_with_file) {
					ctrl_url += strlen("file://");
				}

				_MSG(", path: %s", ctrl_url);
			} else if (starts_with_net || starts_with_net6) {
				_MSG(", url: %s", ctrl_url);
			} else {
				assert(strlen(data_url) > 0);

				_MSG(", control url: %s, data url: %s", ctrl_url, data_url);
			}

			name = lttng_snapshot_output_get_name(output);
			assert(name);
			if (strlen(name) > 0) {
				_MSG(", name: %s", name);
			}

			max_size = lttng_snapshot_output_get_maxsize(output);
			if (max_size != -1ULL) {
				_MSG(", max size: %" PRIu64, max_size);
			}
		}

		action_status = lttng_action_snapshot_session_get_rate_policy(
				action, &policy);
		if (action_status != LTTNG_ACTION_STATUS_OK) {
			ERR("Failed to retrieve rate policy.");
			goto end;
		}
		break;
	}
	default:
		abort();
	}

	if (policy) {
		enum lttng_rate_policy_type policy_type;
		enum lttng_rate_policy_status policy_status;
		uint64_t policy_value = 0;

		policy_type = lttng_rate_policy_get_type(policy);

		switch (policy_type) {
		case LTTNG_RATE_POLICY_TYPE_EVERY_N:
			policy_status = lttng_rate_policy_every_n_get_interval(
					policy, &policy_value);
			if (policy_status != LTTNG_RATE_POLICY_STATUS_OK) {
				ERR("Failed to get action rate policy interval");
				goto end;
			}
			if (policy_value > 1) {
				/* The default is 1 so print only when it is a
				 * special case.
				 */
				_MSG(", rate policy: after every %" PRIu64
				     " occurrences",
						policy_value);
			}
			break;
		case LTTNG_RATE_POLICY_TYPE_ONCE_AFTER_N:
			policy_status = lttng_rate_policy_once_after_n_get_threshold(
					policy, &policy_value);
			if (policy_status != LTTNG_RATE_POLICY_STATUS_OK) {
				ERR("Failed to get action rate policy interval");
				goto end;
			}
			_MSG(", rate policy: once after %" PRIu64
			     " occurrences",
					policy_value);
			break;
		default:
			abort();
		}
	}

	MSG("");
	print_action_errors(trigger, action);

end:
	return;
}

static
void print_trigger_errors(const struct lttng_trigger *trigger)
{
	unsigned int i, count, printed_errors_count = 0;
	enum lttng_error_code error_query_ret;
	enum lttng_error_query_results_status results_status;
	struct lttng_error_query_results *results = NULL;
	enum lttng_trigger_status trigger_status;
	const char *trigger_name;
	uid_t trigger_uid;
	struct lttng_error_query *query =
			lttng_error_query_trigger_create(trigger);

	assert(query);
	/*
	 * Anonymous triggers are not listed; this would be an internal error.
	 */
	trigger_status = lttng_trigger_get_name(trigger, &trigger_name);
	assert(trigger_status == LTTNG_TRIGGER_STATUS_OK);

	trigger_status = lttng_trigger_get_owner_uid(trigger, &trigger_uid);
	assert(trigger_status == LTTNG_TRIGGER_STATUS_OK);

	error_query_ret = lttng_error_query_execute(
			query, lttng_session_daemon_command_endpoint, &results);
	if (error_query_ret != LTTNG_OK) {
		ERR("Failed to query errors of trigger '%s' (owner uid: %d): %s",
				trigger_name, (int) trigger_uid,
				lttng_strerror(-error_query_ret));
		goto end;
	}

	results_status = lttng_error_query_results_get_count(results, &count);
	assert(results_status == LTTNG_ERROR_QUERY_RESULTS_STATUS_OK);

	_MSG("  errors:");

	for (i = 0; i < count; i++) {
		const struct lttng_error_query_result *result;
		enum lttng_error_query_result_status result_status;
		const char *result_name;
		const char *result_description;
		uint64_t result_value;

		results_status = lttng_error_query_results_get_result(
				results, &result, i);
		assert(results_status == LTTNG_ERROR_QUERY_RESULTS_STATUS_OK);

		result_status = lttng_error_query_result_get_name(
				result, &result_name);
		assert(result_status == LTTNG_ERROR_QUERY_RESULT_STATUS_OK);
		result_status = lttng_error_query_result_get_description(
				result, &result_description);
		assert(result_status == LTTNG_ERROR_QUERY_RESULT_STATUS_OK);

		if (lttng_error_query_result_get_type(result) ==
				LTTNG_ERROR_QUERY_RESULT_TYPE_COUNTER) {
			result_status = lttng_error_query_result_counter_get_value(
					result, &result_value);
			assert(result_status ==
					LTTNG_ERROR_QUERY_RESULT_STATUS_OK);
			if (result_value == 0) {
				continue;
			}

			MSG("");
			_MSG("    %s: %" PRIu64, result_name,
					result_value);
			printed_errors_count++;
		} else {
			_MSG("    Unknown error query result type for result '%s' (%s)",
					result_name, result_description);
			continue;
		}
	}

	if (printed_errors_count == 0) {
		_MSG(" none");
	}

end:
	MSG("");
	lttng_error_query_destroy(query);
	lttng_error_query_results_destroy(results);
}

static
void print_one_trigger(const struct lttng_trigger *trigger)
{
	const struct lttng_condition *condition;
	enum lttng_condition_type condition_type;
	const struct lttng_action *action;
	enum lttng_action_type action_type;
	enum lttng_trigger_status trigger_status;
	const char *name;
	uid_t trigger_uid;

	/*
	 * Anonymous triggers are not listed since they can't be specified nor
	 * referenced through the CLI.
	 */
	trigger_status = lttng_trigger_get_name(trigger, &name);
	if (trigger_status == LTTNG_TRIGGER_STATUS_UNSET) {
		goto end;
	}

	assert(trigger_status == LTTNG_TRIGGER_STATUS_OK);

	trigger_status = lttng_trigger_get_owner_uid(trigger, &trigger_uid);
	assert(trigger_status == LTTNG_TRIGGER_STATUS_OK);

	MSG("- name: %s", name);
	MSG("  owner uid: %d", trigger_uid);

	condition = lttng_trigger_get_const_condition(trigger);
	condition_type = lttng_condition_get_type(condition);
	MSG("  condition: %s", lttng_condition_type_str(condition_type));
	switch (condition_type) {
	case LTTNG_CONDITION_TYPE_SESSION_CONSUMED_SIZE:
		print_condition_session_consumed_size(condition);
		break;
	case LTTNG_CONDITION_TYPE_BUFFER_USAGE_HIGH:
	case LTTNG_CONDITION_TYPE_BUFFER_USAGE_LOW:
		print_condition_buffer_usage(condition);
		break;
	case LTTNG_CONDITION_TYPE_SESSION_ROTATION_ONGOING:
	case LTTNG_CONDITION_TYPE_SESSION_ROTATION_COMPLETED:
		print_condition_session_rotation(condition);
		break;
	case LTTNG_CONDITION_TYPE_EVENT_RULE_MATCHES:
		print_condition_event_rule_matches(condition);
		break;
	default:
		abort();
	}

	action = lttng_trigger_get_const_action(trigger);
	action_type = lttng_action_get_type(action);
	if (action_type == LTTNG_ACTION_TYPE_GROUP) {
		unsigned int count, i;
		enum lttng_action_status action_status;

		MSG("  actions:");

		action_status = lttng_action_list_get_count(action, &count);
		assert(action_status == LTTNG_ACTION_STATUS_OK);

		for (i = 0; i < count; i++) {
			const struct lttng_action *subaction =
					lttng_action_list_get_at_index(
							action, i);

			_MSG("    ");
			print_one_action(trigger, subaction);
		}
	} else {
		_MSG(" action:");
		print_one_action(trigger, action);
	}

	print_trigger_errors(trigger);
end:
	return;
}

static
int compare_triggers_by_name(const void *a, const void *b)
{
	const struct lttng_trigger *trigger_a = *((const struct lttng_trigger **) a);
	const struct lttng_trigger *trigger_b = *((const struct lttng_trigger **) b);
	const char *name_a, *name_b;
	enum lttng_trigger_status trigger_status;

	/* Anonymous triggers are not reachable here. */
	trigger_status = lttng_trigger_get_name(trigger_a, &name_a);
	assert(trigger_status == LTTNG_TRIGGER_STATUS_OK);

	trigger_status = lttng_trigger_get_name(trigger_b, &name_b);
	assert(trigger_status == LTTNG_TRIGGER_STATUS_OK);

	return strcmp(name_a, name_b);
}

int cmd_list_triggers(int argc, const char **argv)
{
	int ret;
	struct argpar_parse_ret argpar_parse_ret = {};
	struct lttng_triggers *triggers = NULL;
	int i;
	struct lttng_dynamic_pointer_array sorted_triggers;
	enum lttng_trigger_status trigger_status;
	unsigned int num_triggers;

	lttng_dynamic_pointer_array_init(&sorted_triggers, NULL);

	argpar_parse_ret = argpar_parse(
			argc - 1, argv + 1, list_trigger_options, true);
	if (!argpar_parse_ret.items) {
		ERR("%s", argpar_parse_ret.error);
		goto error;
	}

	for (i = 0; i < argpar_parse_ret.items->n_items; i++) {
		const struct argpar_item *item =
				argpar_parse_ret.items->items[i];

		if (item->type == ARGPAR_ITEM_TYPE_OPT) {
			const struct argpar_item_opt *item_opt =
					(const struct argpar_item_opt *) item;

			switch (item_opt->descr->id) {
			case OPT_HELP:
				SHOW_HELP();
				ret = 0;
				goto end;

			case OPT_LIST_OPTIONS:
				list_cmd_options_argpar(stdout,
					list_trigger_options);
				ret = 0;
				goto end;

			default:
				abort();
			}

		} else {
			const struct argpar_item_non_opt *item_non_opt =
				(const struct argpar_item_non_opt *) item;

			ERR("Unexpected argument: %s", item_non_opt->arg);
		}
	}

	ret = lttng_list_triggers(&triggers);
	if (ret != LTTNG_OK) {
		ERR("Error listing triggers: %s.", lttng_strerror(-ret));
		goto error;
	}

	trigger_status = lttng_triggers_get_count(triggers, &num_triggers);
	if (trigger_status != LTTNG_TRIGGER_STATUS_OK) {
		ERR("Failed to get trigger count.");
		goto error;
	}

	for (i = 0; i < num_triggers; i++) {
		int add_ret;
		const char *unused_name;
		const struct lttng_trigger *trigger =
				lttng_triggers_get_at_index(triggers, i);

		trigger_status = lttng_trigger_get_name(trigger, &unused_name);
		switch (trigger_status) {
		case LTTNG_TRIGGER_STATUS_OK:
			break;
		case LTTNG_TRIGGER_STATUS_UNSET:
			/* Don't list anonymous triggers. */
			continue;
		default:
			abort();
		}

		add_ret = lttng_dynamic_pointer_array_add_pointer(
				&sorted_triggers, (void *) trigger);

		if (add_ret) {
			ERR("Failed to allocate array of struct lttng_trigger *.");
			goto error;
		}
	}

	qsort(sorted_triggers.array.buffer.data, num_triggers,
			sizeof(struct lttng_trigger *),
			compare_triggers_by_name);

	for (i = 0; i < num_triggers; i++) {
		const struct lttng_trigger *trigger_to_print =
				(const struct lttng_trigger *)
				lttng_dynamic_pointer_array_get_pointer(
						&sorted_triggers, i);

		print_one_trigger(trigger_to_print);
	}

	ret = 0;
	goto end;

error:
	ret = 1;

end:
	argpar_parse_ret_fini(&argpar_parse_ret);
	lttng_triggers_destroy(triggers);
	lttng_dynamic_pointer_array_reset(&sorted_triggers);

	return ret;
}
