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
/* For lttng_domain_type_str(). */
#include "lttng/domain-internal.h"

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

static
void print_event_rule_tracepoint(const struct lttng_event_rule *event_rule)
{
	enum lttng_event_rule_status event_rule_status;
	enum lttng_domain_type domain_type;
	const char *pattern;
	const char *filter;
	int log_level;
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

	event_rule_status = lttng_event_rule_tracepoint_get_log_level(
			event_rule, &log_level);
	if (event_rule_status == LTTNG_EVENT_RULE_STATUS_OK) {
		enum lttng_loglevel_type log_level_type;
		const char *log_level_op;

		event_rule_status = lttng_event_rule_tracepoint_get_log_level_type(
				event_rule, &log_level_type);
		assert(event_rule_status == LTTNG_EVENT_RULE_STATUS_OK);
		assert(log_level_type == LTTNG_EVENT_LOGLEVEL_RANGE ||
				log_level_type == LTTNG_EVENT_LOGLEVEL_SINGLE);

		log_level_op = (log_level_type == LTTNG_EVENT_LOGLEVEL_RANGE ? "<=" : "==");

		_MSG(", log level %s %s", log_level_op,
				mi_lttng_loglevel_string(
						log_level, domain_type));
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
void print_event_rule_kprobe(const struct lttng_event_rule *event_rule)
{
	enum lttng_event_rule_status event_rule_status;
	const char *name;
	const struct lttng_kernel_probe_location *location;

	assert(lttng_event_rule_get_type(event_rule) == LTTNG_EVENT_RULE_TYPE_KPROBE);

	event_rule_status = lttng_event_rule_kprobe_get_name(event_rule, &name);
	if (event_rule_status != LTTNG_EVENT_RULE_STATUS_OK) {
		ERR("Failed to get kprobe event rule's name.");
		goto end;
	}

	event_rule_status = lttng_event_rule_kprobe_get_location(
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
void print_event_rule_uprobe(const struct lttng_event_rule *event_rule)
{
	enum lttng_event_rule_status event_rule_status;
	const char *name;
	const struct lttng_userspace_probe_location *location;
	enum lttng_userspace_probe_location_type userspace_probe_location_type;

	assert(lttng_event_rule_get_type(event_rule) == LTTNG_EVENT_RULE_TYPE_UPROBE);

	event_rule_status = lttng_event_rule_uprobe_get_name(event_rule, &name);
	if (event_rule_status != LTTNG_EVENT_RULE_STATUS_OK) {
		ERR("Failed to get uprobe event rule's name.");
		goto end;
	}

	event_rule_status = lttng_event_rule_uprobe_get_location(
			event_rule, &location);
	if (event_rule_status != LTTNG_EVENT_RULE_STATUS_OK) {
		ERR("Failed to get uprobe event rule's location.");
		goto end;
	}

	_MSG("    rule: %s (type: userspace probe, location: ", name);

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

		_MSG("%s:%s", binary_path, function_name);
		break;
	}
	case LTTNG_USERSPACE_PROBE_LOCATION_TYPE_TRACEPOINT:
		_MSG("SDT not implemented yet");
		break;
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

	assert(lttng_event_rule_get_type(event_rule) == LTTNG_EVENT_RULE_TYPE_SYSCALL);

	event_rule_status = lttng_event_rule_syscall_get_pattern(
			event_rule, &pattern);
	assert(event_rule_status == LTTNG_EVENT_RULE_STATUS_OK);

	_MSG("    rule: %s (type: syscall", pattern);

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
	case LTTNG_EVENT_RULE_TYPE_KPROBE:
		print_event_rule_kprobe(event_rule);
		break;
	case LTTNG_EVENT_RULE_TYPE_UPROBE:
		print_event_rule_uprobe(event_rule);
		break;
	case LTTNG_EVENT_RULE_TYPE_SYSCALL:
		print_event_rule_syscall(event_rule);
		break;
	default:
		abort();
	}
}

static
void print_condition_event_rule_hit(const struct lttng_condition *condition)
{
	const struct lttng_event_rule *event_rule;
	enum lttng_condition_status condition_status;

	condition_status =
		lttng_condition_event_rule_get_rule(condition, &event_rule);
	assert(condition_status == LTTNG_CONDITION_STATUS_OK);

	print_event_rule(event_rule);
}

static
void print_one_action(const struct lttng_action *action)
{
	enum lttng_action_type action_type;
	enum lttng_action_status action_status;
	const char *value;

	action_type = lttng_action_get_type(action);
	assert(action_type != LTTNG_ACTION_TYPE_GROUP);

	switch (action_type) {
	case LTTNG_ACTION_TYPE_NOTIFY:
		MSG("notify");
		break;
	case LTTNG_ACTION_TYPE_START_SESSION:
		action_status = lttng_action_start_session_get_session_name(
				action, &value);
		assert(action_status == LTTNG_ACTION_STATUS_OK);
		MSG("start session `%s`", value);
		break;
	case LTTNG_ACTION_TYPE_STOP_SESSION:
		action_status = lttng_action_stop_session_get_session_name(
				action, &value);
		assert(action_status == LTTNG_ACTION_STATUS_OK);
		MSG("stop session `%s`", value);
		break;
	case LTTNG_ACTION_TYPE_ROTATE_SESSION:
		action_status = lttng_action_rotate_session_get_session_name(
				action, &value);
		assert(action_status == LTTNG_ACTION_STATUS_OK);
		MSG("rotate session `%s`", value);
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

		MSG("");
		break;
	}

	default:
		abort();
	}
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
	enum lttng_trigger_firing_policy firing_policy_type;
	uint64_t threshold;
	uid_t trigger_uid;

	trigger_status = lttng_trigger_get_name(trigger, &name);
	assert(trigger_status == LTTNG_TRIGGER_STATUS_OK);

	trigger_status = lttng_trigger_get_owner_uid(trigger, &trigger_uid);
	assert(trigger_status == LTTNG_TRIGGER_STATUS_OK);

	MSG("- id: %s", name);
	MSG("  user id: %d", trigger_uid);

	trigger_status = lttng_trigger_get_firing_policy(
			trigger, &firing_policy_type, &threshold);
	if (trigger_status != LTTNG_TRIGGER_STATUS_OK) {
		ERR("Failed to get trigger's policy.");
		goto end;
	}

	switch (firing_policy_type) {
	case LTTNG_TRIGGER_FIRING_POLICY_EVERY_N:
		if (threshold > 1) {
			MSG("  firing policy: after every %" PRIu64 " occurences", threshold);
		}
		break;
	case LTTNG_TRIGGER_FIRING_POLICY_ONCE_AFTER_N:
		MSG("  firing policy: once after %" PRIu64 " occurences", threshold);
		break;
	default:
		abort();
	}

	condition = lttng_trigger_get_const_condition(trigger);
	condition_type = lttng_condition_get_type(condition);
	MSG("  condition: %s", lttng_condition_type_str(condition_type));
	switch (condition_type) {
	case LTTNG_CONDITION_TYPE_EVENT_RULE_HIT:
		print_condition_event_rule_hit(condition);
		break;
	default:
		MSG("  (condition type not handled in %s)", __func__);
		break;
	}

	action = lttng_trigger_get_const_action(trigger);
	action_type = lttng_action_get_type(action);
	if (action_type == LTTNG_ACTION_TYPE_GROUP) {
		unsigned int count, i;
		enum lttng_action_status action_status;

		MSG("  actions:");

		action_status = lttng_action_group_get_count(action, &count);
		assert(action_status == LTTNG_ACTION_STATUS_OK);

		for (i = 0; i < count; i++) {
			const struct lttng_action *subaction =
					lttng_action_group_get_at_index(
							action, i);

			_MSG("    ");
			print_one_action(subaction);
		}
	} else {
		_MSG(" action:");
		print_one_action(action);
	}

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
		const int add_ret = lttng_dynamic_pointer_array_add_pointer(
				&sorted_triggers,
				(void *) lttng_triggers_get_at_index(triggers, i));

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
