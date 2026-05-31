/*
 * SPDX-FileCopyrightText: 2026 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#define _LGPL_SOURCE
#include "config-internal.hpp"
#include "trigger-config.hpp"

#include <common/config/config-session-abi.hpp>
#include <common/error.hpp>
#include <common/macros.hpp>
#include <common/make-unique-wrapper.hpp>
#include <common/mi-lttng.hpp>

#include <lttng/action/action-internal.hpp>
#include <lttng/action/increment-map-value.h>
#include <lttng/action/key-template.h>
#include <lttng/action/list.h>
#include <lttng/action/notify.h>
#include <lttng/action/rate-policy.h>
#include <lttng/action/rotate-session.h>
#include <lttng/action/snapshot-session.h>
#include <lttng/action/start-session.h>
#include <lttng/action/stop-session.h>
#include <lttng/condition/buffer-usage.h>
#include <lttng/condition/condition-internal.hpp>
#include <lttng/condition/event-rule-matches.h>
#include <lttng/condition/session-consumed-size.h>
#include <lttng/condition/session-rotation.h>
#include <lttng/event-expr.h>
#include <lttng/event-rule/jul-logging.h>
#include <lttng/event-rule/kernel-kprobe.h>
#include <lttng/event-rule/kernel-syscall.h>
#include <lttng/event-rule/kernel-tracepoint.h>
#include <lttng/event-rule/kernel-uprobe.h>
#include <lttng/event-rule/log4j-logging.h>
#include <lttng/event-rule/log4j2-logging.h>
#include <lttng/event-rule/python-logging.h>
#include <lttng/event-rule/user-tracepoint.h>
#include <lttng/kernel-probe.h>
#include <lttng/log-level-rule.h>
#include <lttng/lttng-error.h>
#include <lttng/map/channel-type.h>
#include <lttng/snapshot.h>
#include <lttng/trigger/trigger.h>
#include <lttng/userspace-probe.h>

#include <libxml/tree.h>
#include <limits>
#include <stdexcept>
#include <string.h>
#include <string>
#include <vector>

namespace {

/*
 * This reader is the exact inverse of the no-namespace MI serialization
 * of triggers (see lttng_triggers_mi_serialize() and `mi-lttng-*.xsd`):
 * it matches elements using the same name constants
 * (`mi_lttng_element_*`, `config_element_*`) the MI writers use.
 *
 * The `session.xsd` schema validates the document before this
 * code runs.
 */

/*
 * Exception carrying an LTTNG_ERR code, thrown while parsing and caught at the
 * module boundary so that nothing escapes into the C session-config loader.
 */
class parse_error : public std::runtime_error {
public:
	parse_error(int code, const std::string& msg) : std::runtime_error(msg), _code(code)
	{
	}

	int code() const noexcept
	{
		return _code;
	}

private:
	int _code;
};

/* RAII aliases for the owned lttng objects built during deserialization. */
using condition_uptr =
	decltype(lttng::make_unique_wrapper<lttng_condition, lttng_condition_destroy>());
using action_uptr = decltype(lttng::make_unique_wrapper<lttng_action, lttng_action_destroy>());
using event_rule_uptr =
	decltype(lttng::make_unique_wrapper<lttng_event_rule, lttng_event_rule_destroy>());
using event_expr_uptr =
	decltype(lttng::make_unique_wrapper<lttng_event_expr, lttng_event_expr_destroy>());
using log_level_rule_uptr =
	decltype(lttng::make_unique_wrapper<lttng_log_level_rule, lttng_log_level_rule_destroy>());
using rate_policy_uptr =
	decltype(lttng::make_unique_wrapper<lttng_rate_policy, lttng_rate_policy_destroy>());
using kernel_probe_location_uptr =
	decltype(lttng::make_unique_wrapper<lttng_kernel_probe_location,
					    lttng_kernel_probe_location_destroy>());
using userspace_probe_location_uptr =
	decltype(lttng::make_unique_wrapper<lttng_userspace_probe_location,
					    lttng_userspace_probe_location_destroy>());
using lookup_method_uptr =
	decltype(lttng::make_unique_wrapper<lttng_userspace_probe_location_lookup_method,
					    lttng_userspace_probe_location_lookup_method_destroy>());
using snapshot_output_uptr =
	decltype(lttng::make_unique_wrapper<lttng_snapshot_output, lttng_snapshot_output_destroy>());
using key_template_uptr =
	decltype(lttng::make_unique_wrapper<lttng_key_template, lttng_key_template_destroy>());
using trigger_uptr = decltype(lttng::make_unique_wrapper<lttng_trigger, lttng_trigger_destroy>());

template <typename ObjectType, void (*DeleterFunc)(ObjectType *)>
decltype(lttng::make_unique_wrapper<ObjectType, DeleterFunc>()) wrap(ObjectType *raw)
{
	return lttng::make_unique_wrapper<ObjectType, DeleterFunc>(raw);
}

const char *element_name(xmlNodePtr node) noexcept
{
	return reinterpret_cast<const char *>(node->name);
}

bool is_element(xmlNodePtr node, const char *name) noexcept
{
	return strcmp(element_name(node), name) == 0;
}

/* Return the text content of `node` as a string, throwing on allocation error. */
std::string node_text(xmlNodePtr node)
{
	xmlChar *const content = xmlNodeGetContent(node);

	if (!content) {
		throw parse_error(-LTTNG_ERR_NOMEM, "Failed to read trigger XML node content");
	}

	std::string result(reinterpret_cast<const char *>(content));
	xmlFree(content);
	return result;
}

uint64_t node_uint64(xmlNodePtr node)
{
	const auto value = lttng::config::uint64_from_string(node_text(node).c_str());

	if (!value) {
		throw parse_error(-LTTNG_ERR_LOAD_INVALID_CONFIG,
				  "Invalid unsigned integer in trigger configuration");
	}

	return *value;
}

int node_int(xmlNodePtr node)
{
	const auto value = lttng::config::int64_from_string(node_text(node).c_str());

	if (!value || *value < std::numeric_limits<int>::min() ||
	    *value > std::numeric_limits<int>::max()) {
		throw parse_error(-LTTNG_ERR_LOAD_INVALID_CONFIG,
				  "Invalid integer in trigger configuration");
	}

	return static_cast<int>(*value);
}

double node_double(xmlNodePtr node)
{
	const auto value = lttng::config::double_from_string(node_text(node).c_str());

	if (!value) {
		throw parse_error(-LTTNG_ERR_LOAD_INVALID_CONFIG,
				  "Invalid floating point number in trigger configuration");
	}

	return *value;
}

/* Return the first element child of `node`, or nullptr if it has none. */
xmlNodePtr first_child(xmlNodePtr node) noexcept
{
	return xmlFirstElementChild(node);
}

/* Throw: the configuration contains an unexpected or missing element. */
[[noreturn]] void invalid_config(const std::string& detail)
{
	throw parse_error(-LTTNG_ERR_LOAD_INVALID_CONFIG, detail);
}

enum lttng_domain_type parse_domain_type(const std::string& text)
{
	const auto type = lttng::config::domain_type_from_string(text.c_str());

	if (!type) {
		invalid_config("Unknown trigger condition domain: " + text);
	}

	return *type;
}

/* Forward declarations for the recursive descent. */
event_expr_uptr parse_event_expr(xmlNodePtr event_expr_node);
action_uptr parse_action(xmlNodePtr action_node);

/*
 * rate_policy
 */
rate_policy_uptr parse_rate_policy(xmlNodePtr rate_policy_node)
{
	const auto sub = first_child(rate_policy_node);

	if (!sub) {
		invalid_config("Empty <rate_policy> element");
	}

	lttng_rate_policy *raw = nullptr;

	if (is_element(sub, mi_lttng_element_rate_policy_every_n)) {
		raw = lttng_rate_policy_every_n_create(node_uint64(first_child(sub)));
	} else if (is_element(sub, mi_lttng_element_rate_policy_once_after_n)) {
		raw = lttng_rate_policy_once_after_n_create(node_uint64(first_child(sub)));
	} else {
		invalid_config(std::string("Unknown rate policy: ") + element_name(sub));
	}

	if (!raw) {
		throw parse_error(-LTTNG_ERR_NOMEM, "Failed to create rate policy");
	}

	return wrap<lttng_rate_policy, lttng_rate_policy_destroy>(raw);
}

/* Set the rate policy of `action` from an optional <rate_policy> child. */
void set_action_rate_policy(xmlNodePtr rate_policy_node,
			    enum lttng_action_status (*setter)(struct lttng_action *,
							       const struct lttng_rate_policy *),
			    lttng_action *action)
{
	const auto policy = parse_rate_policy(rate_policy_node);

	/* The setter copies the policy. */
	if (setter(action, policy.get()) != LTTNG_ACTION_STATUS_OK) {
		throw parse_error(-LTTNG_ERR_LOAD_INVALID_CONFIG,
				  "Failed to set action rate policy");
	}
}

/*
 * log_level_rule
 */
log_level_rule_uptr parse_log_level_rule(xmlNodePtr log_level_rule_node)
{
	const auto sub = first_child(log_level_rule_node);

	if (!sub) {
		invalid_config("Empty <log_level_rule> element");
	}

	const auto level = node_int(first_child(sub));
	lttng_log_level_rule *raw = nullptr;

	if (is_element(sub, mi_lttng_element_log_level_rule_exactly)) {
		raw = lttng_log_level_rule_exactly_create(level);
	} else if (is_element(sub, mi_lttng_element_log_level_rule_at_least_as_severe_as)) {
		raw = lttng_log_level_rule_at_least_as_severe_as_create(level);
	} else {
		invalid_config(std::string("Unknown log level rule: ") + element_name(sub));
	}

	if (!raw) {
		throw parse_error(-LTTNG_ERR_NOMEM, "Failed to create log level rule");
	}

	return wrap<lttng_log_level_rule, lttng_log_level_rule_destroy>(raw);
}

/*
 * kernel_probe_location
 */
kernel_probe_location_uptr parse_kernel_probe_location(xmlNodePtr location_node)
{
	const auto sub = first_child(location_node);

	if (!sub) {
		invalid_config("Empty <kernel_probe_location> element");
	}

	lttng_kernel_probe_location *raw = nullptr;

	if (is_element(sub, mi_lttng_element_kernel_probe_location_address)) {
		raw = lttng_kernel_probe_location_address_create(node_uint64(first_child(sub)));
	} else if (is_element(sub, mi_lttng_element_kernel_probe_location_symbol_offset)) {
		std::string name;
		uint64_t offset = 0;

		for (auto child = first_child(sub); child; child = xmlNextElementSibling(child)) {
			if (is_element(child,
				       mi_lttng_element_kernel_probe_location_symbol_offset_name)) {
				name = node_text(child);
			} else if (
				is_element(
					child,
					mi_lttng_element_kernel_probe_location_symbol_offset_offset)) {
				offset = node_uint64(child);
			}
		}

		raw = lttng_kernel_probe_location_symbol_create(name.c_str(), offset);
	} else {
		invalid_config(std::string("Unknown kernel probe location: ") + element_name(sub));
	}

	if (!raw) {
		throw parse_error(-LTTNG_ERR_NOMEM, "Failed to create kernel probe location");
	}

	return wrap<lttng_kernel_probe_location, lttng_kernel_probe_location_destroy>(raw);
}

/*
 * userspace_probe_location
 */
lookup_method_uptr parse_userspace_probe_lookup_method(xmlNodePtr lookup_method_node)
{
	const auto sub = first_child(lookup_method_node);

	if (!sub) {
		invalid_config("Empty <userspace_probe_location_lookup_method> element");
	}

	lttng_userspace_probe_location_lookup_method *raw = nullptr;

	/*
	 * There is no public constructor for the "function default" lookup
	 * method; it resolves to an ELF lookup in practice, so map both to the
	 * ELF constructor.
	 */
	if (is_element(sub,
		       mi_lttng_element_userspace_probe_location_lookup_method_function_default) ||
	    is_element(sub, mi_lttng_element_userspace_probe_location_lookup_method_function_elf)) {
		raw = lttng_userspace_probe_location_lookup_method_function_elf_create();
	} else if (is_element(
			   sub,
			   mi_lttng_element_userspace_probe_location_lookup_method_tracepoint_sdt)) {
		raw = lttng_userspace_probe_location_lookup_method_tracepoint_sdt_create();
	} else {
		invalid_config(std::string("Unknown user space probe location lookup method: ") +
			       element_name(sub));
	}

	if (!raw) {
		throw parse_error(-LTTNG_ERR_NOMEM,
				  "Failed to create user space probe location lookup method");
	}

	return wrap<lttng_userspace_probe_location_lookup_method,
		    lttng_userspace_probe_location_lookup_method_destroy>(raw);
}

userspace_probe_location_uptr parse_userspace_probe_location(xmlNodePtr location_node)
{
	const auto sub = first_child(location_node);

	if (!sub) {
		invalid_config("Empty <userspace_probe_location> element");
	}

	std::string binary_path;
	std::string function_name;
	std::string probe_name;
	std::string provider_name;
	lookup_method_uptr lookup_method;

	for (auto child = first_child(sub); child; child = xmlNextElementSibling(child)) {
		if (is_element(child, mi_lttng_element_userspace_probe_location_function_name)) {
			function_name = node_text(child);
		} else if (is_element(child,
				      mi_lttng_element_userspace_probe_location_binary_path)) {
			binary_path = node_text(child);
		} else if (is_element(
				   child,
				   mi_lttng_element_userspace_probe_location_tracepoint_probe_name)) {
			probe_name = node_text(child);
		} else if (is_element(
				   child,
				   mi_lttng_element_userspace_probe_location_tracepoint_provider_name)) {
			provider_name = node_text(child);
		} else if (is_element(child,
				      mi_lttng_element_userspace_probe_location_lookup_method)) {
			lookup_method = parse_userspace_probe_lookup_method(child);
		}
		/* instrumentation_type is implied (ENTRY) and ignored. */
	}

	if (!lookup_method) {
		invalid_config("Missing user space probe location lookup method");
	}

	lttng_userspace_probe_location *raw = nullptr;

	if (is_element(sub, mi_lttng_element_userspace_probe_location_function)) {
		/* The location takes ownership of the lookup method. */
		raw = lttng_userspace_probe_location_function_create(
			binary_path.c_str(), function_name.c_str(), lookup_method.release());
	} else if (is_element(sub, mi_lttng_element_userspace_probe_location_tracepoint)) {
		raw = lttng_userspace_probe_location_tracepoint_create(binary_path.c_str(),
								       probe_name.c_str(),
								       provider_name.c_str(),
								       lookup_method.release());
	} else {
		invalid_config(std::string("Unknown user space probe location: ") +
			       element_name(sub));
	}

	if (!raw) {
		throw parse_error(-LTTNG_ERR_NOMEM, "Failed to create user space probe location");
	}

	return wrap<lttng_userspace_probe_location, lttng_userspace_probe_location_destroy>(raw);
}

/*
 * event_rule
 */
void set_event_rule_name_pattern_and_filter(
	xmlNodePtr rule_sub_node,
	event_rule_uptr& rule,
	enum lttng_event_rule_status (*set_pattern)(struct lttng_event_rule *, const char *),
	enum lttng_event_rule_status (*set_filter)(struct lttng_event_rule *, const char *))
{
	for (auto child = first_child(rule_sub_node); child; child = xmlNextElementSibling(child)) {
		if (is_element(child, mi_lttng_element_event_rule_name_pattern)) {
			if (set_pattern(rule.get(), node_text(child).c_str()) !=
			    LTTNG_EVENT_RULE_STATUS_OK) {
				invalid_config("Failed to set event rule name pattern");
			}
		} else if (is_element(child, mi_lttng_element_event_rule_filter_expression)) {
			if (set_filter(rule.get(), node_text(child).c_str()) !=
			    LTTNG_EVENT_RULE_STATUS_OK) {
				invalid_config("Failed to set event rule filter expression");
			}
		}
	}
}

void set_event_rule_log_level_rule(
	xmlNodePtr rule_sub_node,
	event_rule_uptr& rule,
	enum lttng_event_rule_status (*set_log_level_rule)(struct lttng_event_rule *,
							   const struct lttng_log_level_rule *))
{
	for (auto child = first_child(rule_sub_node); child; child = xmlNextElementSibling(child)) {
		if (is_element(child, mi_lttng_element_log_level_rule)) {
			const auto log_level_rule = parse_log_level_rule(child);

			/* The setter copies the log level rule. */
			if (set_log_level_rule(rule.get(), log_level_rule.get()) !=
			    LTTNG_EVENT_RULE_STATUS_OK) {
				invalid_config("Failed to set event rule log level rule");
			}
		}
	}
}

event_rule_uptr parse_event_rule_user_tracepoint(xmlNodePtr rule_sub_node)
{
	auto rule = wrap<lttng_event_rule, lttng_event_rule_destroy>(
		lttng_event_rule_user_tracepoint_create());

	if (!rule) {
		throw parse_error(-LTTNG_ERR_NOMEM, "Failed to create user tracepoint event rule");
	}

	set_event_rule_name_pattern_and_filter(rule_sub_node,
					       rule,
					       lttng_event_rule_user_tracepoint_set_name_pattern,
					       lttng_event_rule_user_tracepoint_set_filter);
	set_event_rule_log_level_rule(
		rule_sub_node, rule, lttng_event_rule_user_tracepoint_set_log_level_rule);

	/* Name pattern exclusions. */
	for (auto child = first_child(rule_sub_node); child; child = xmlNextElementSibling(child)) {
		if (!is_element(
			    child,
			    mi_lttng_element_event_rule_user_tracepoint_name_pattern_exclusions)) {
			continue;
		}

		for (auto exclusion = first_child(child); exclusion;
		     exclusion = xmlNextElementSibling(exclusion)) {
			if (lttng_event_rule_user_tracepoint_add_name_pattern_exclusion(
				    rule.get(), node_text(exclusion).c_str()) !=
			    LTTNG_EVENT_RULE_STATUS_OK) {
				invalid_config(
					"Failed to add user tracepoint name pattern exclusion");
			}
		}
	}

	return rule;
}

event_rule_uptr parse_event_rule_logging(
	xmlNodePtr rule_sub_node,
	struct lttng_event_rule *(*create)(void),
	enum lttng_event_rule_status (*set_pattern)(struct lttng_event_rule *, const char *),
	enum lttng_event_rule_status (*set_filter)(struct lttng_event_rule *, const char *),
	enum lttng_event_rule_status (*set_log_level_rule)(struct lttng_event_rule *,
							   const struct lttng_log_level_rule *))
{
	auto rule = wrap<lttng_event_rule, lttng_event_rule_destroy>(create());

	if (!rule) {
		throw parse_error(-LTTNG_ERR_NOMEM, "Failed to create logging event rule");
	}

	set_event_rule_name_pattern_and_filter(rule_sub_node, rule, set_pattern, set_filter);
	set_event_rule_log_level_rule(rule_sub_node, rule, set_log_level_rule);
	return rule;
}

event_rule_uptr parse_event_rule_kernel_tracepoint(xmlNodePtr rule_sub_node)
{
	auto rule = wrap<lttng_event_rule, lttng_event_rule_destroy>(
		lttng_event_rule_kernel_tracepoint_create());

	if (!rule) {
		throw parse_error(-LTTNG_ERR_NOMEM,
				  "Failed to create kernel tracepoint event rule");
	}

	set_event_rule_name_pattern_and_filter(rule_sub_node,
					       rule,
					       lttng_event_rule_kernel_tracepoint_set_name_pattern,
					       lttng_event_rule_kernel_tracepoint_set_filter);
	return rule;
}

event_rule_uptr parse_event_rule_kernel_syscall(xmlNodePtr rule_sub_node)
{
	auto emission_site = LTTNG_EVENT_RULE_KERNEL_SYSCALL_EMISSION_SITE_ENTRY_EXIT;

	for (auto child = first_child(rule_sub_node); child; child = xmlNextElementSibling(child)) {
		if (!is_element(child, mi_lttng_element_event_rule_kernel_syscall_emission_site)) {
			continue;
		}

		const auto text = node_text(child);
		if (text == "entry+exit") {
			emission_site = LTTNG_EVENT_RULE_KERNEL_SYSCALL_EMISSION_SITE_ENTRY_EXIT;
		} else if (text == "entry") {
			emission_site = LTTNG_EVENT_RULE_KERNEL_SYSCALL_EMISSION_SITE_ENTRY;
		} else if (text == "exit") {
			emission_site = LTTNG_EVENT_RULE_KERNEL_SYSCALL_EMISSION_SITE_EXIT;
		} else {
			invalid_config("Unknown kernel syscall emission site: " + text);
		}
	}

	auto rule = wrap<lttng_event_rule, lttng_event_rule_destroy>(
		lttng_event_rule_kernel_syscall_create(emission_site));

	if (!rule) {
		throw parse_error(-LTTNG_ERR_NOMEM, "Failed to create kernel syscall event rule");
	}

	set_event_rule_name_pattern_and_filter(rule_sub_node,
					       rule,
					       lttng_event_rule_kernel_syscall_set_name_pattern,
					       lttng_event_rule_kernel_syscall_set_filter);
	return rule;
}

event_rule_uptr parse_event_rule_kernel_kprobe(xmlNodePtr rule_sub_node)
{
	std::string event_name;
	kernel_probe_location_uptr location;

	for (auto child = first_child(rule_sub_node); child; child = xmlNextElementSibling(child)) {
		if (is_element(child, mi_lttng_element_event_rule_event_name)) {
			event_name = node_text(child);
		} else if (is_element(child, mi_lttng_element_kernel_probe_location)) {
			location = parse_kernel_probe_location(child);
		}
	}

	if (!location) {
		invalid_config("Missing kernel probe location in kprobe event rule");
	}

	/* The event rule copies the location. */
	auto rule = wrap<lttng_event_rule, lttng_event_rule_destroy>(
		lttng_event_rule_kernel_kprobe_create(location.get()));

	if (!rule) {
		throw parse_error(-LTTNG_ERR_NOMEM, "Failed to create kprobe event rule");
	}

	if (lttng_event_rule_kernel_kprobe_set_event_name(rule.get(), event_name.c_str()) !=
	    LTTNG_EVENT_RULE_STATUS_OK) {
		invalid_config("Failed to set kprobe event rule event name");
	}

	return rule;
}

event_rule_uptr parse_event_rule_kernel_uprobe(xmlNodePtr rule_sub_node)
{
	std::string event_name;
	userspace_probe_location_uptr location;

	for (auto child = first_child(rule_sub_node); child; child = xmlNextElementSibling(child)) {
		if (is_element(child, mi_lttng_element_event_rule_event_name)) {
			event_name = node_text(child);
		} else if (is_element(child, mi_lttng_element_userspace_probe_location)) {
			location = parse_userspace_probe_location(child);
		}
	}

	if (!location) {
		invalid_config("Missing user space probe location in uprobe event rule");
	}

	/* The event rule copies the location. */
	auto rule = wrap<lttng_event_rule, lttng_event_rule_destroy>(
		lttng_event_rule_kernel_uprobe_create(location.get()));

	if (!rule) {
		throw parse_error(-LTTNG_ERR_NOMEM, "Failed to create uprobe event rule");
	}

	if (lttng_event_rule_kernel_uprobe_set_event_name(rule.get(), event_name.c_str()) !=
	    LTTNG_EVENT_RULE_STATUS_OK) {
		invalid_config("Failed to set uprobe event rule event name");
	}

	return rule;
}

event_rule_uptr parse_event_rule(xmlNodePtr event_rule_node)
{
	const auto sub = first_child(event_rule_node);

	if (!sub) {
		invalid_config("Empty <event_rule> element");
	}

	if (is_element(sub, mi_lttng_element_event_rule_user_tracepoint)) {
		return parse_event_rule_user_tracepoint(sub);
	} else if (is_element(sub, mi_lttng_element_event_rule_kernel_tracepoint)) {
		return parse_event_rule_kernel_tracepoint(sub);
	} else if (is_element(sub, mi_lttng_element_event_rule_kernel_syscall)) {
		return parse_event_rule_kernel_syscall(sub);
	} else if (is_element(sub, mi_lttng_element_event_rule_kernel_kprobe)) {
		return parse_event_rule_kernel_kprobe(sub);
	} else if (is_element(sub, mi_lttng_element_event_rule_kernel_uprobe)) {
		return parse_event_rule_kernel_uprobe(sub);
	} else if (is_element(sub, mi_lttng_element_event_rule_jul_logging)) {
		return parse_event_rule_logging(sub,
						lttng_event_rule_jul_logging_create,
						lttng_event_rule_jul_logging_set_name_pattern,
						lttng_event_rule_jul_logging_set_filter,
						lttng_event_rule_jul_logging_set_log_level_rule);
	} else if (is_element(sub, mi_lttng_element_event_rule_log4j_logging)) {
		return parse_event_rule_logging(sub,
						lttng_event_rule_log4j_logging_create,
						lttng_event_rule_log4j_logging_set_name_pattern,
						lttng_event_rule_log4j_logging_set_filter,
						lttng_event_rule_log4j_logging_set_log_level_rule);
	} else if (is_element(sub, mi_lttng_element_event_rule_log4j2_logging)) {
		return parse_event_rule_logging(sub,
						lttng_event_rule_log4j2_logging_create,
						lttng_event_rule_log4j2_logging_set_name_pattern,
						lttng_event_rule_log4j2_logging_set_filter,
						lttng_event_rule_log4j2_logging_set_log_level_rule);
	} else if (is_element(sub, mi_lttng_element_event_rule_python_logging)) {
		return parse_event_rule_logging(sub,
						lttng_event_rule_python_logging_create,
						lttng_event_rule_python_logging_set_name_pattern,
						lttng_event_rule_python_logging_set_filter,
						lttng_event_rule_python_logging_set_log_level_rule);
	}

	invalid_config(std::string("Unknown event rule: ") + element_name(sub));
}

/*
 * event_expr (capture descriptor)
 */
event_expr_uptr parse_event_expr(xmlNodePtr event_expr_node)
{
	const auto sub = first_child(event_expr_node);

	if (!sub) {
		invalid_config("Empty <event_expr> element");
	}

	lttng_event_expr *raw = nullptr;

	if (is_element(sub, mi_lttng_element_event_expr_payload_field)) {
		raw = lttng_event_expr_event_payload_field_create(
			node_text(first_child(sub)).c_str());
	} else if (is_element(sub, mi_lttng_element_event_expr_channel_context_field)) {
		raw = lttng_event_expr_channel_context_field_create(
			node_text(first_child(sub)).c_str());
	} else if (is_element(sub, mi_lttng_element_event_expr_app_specific_context_field)) {
		std::string provider_name;
		std::string type_name;

		for (auto child = first_child(sub); child; child = xmlNextElementSibling(child)) {
			if (is_element(child, mi_lttng_element_event_expr_provider_name)) {
				provider_name = node_text(child);
			} else if (is_element(child, mi_lttng_element_event_expr_type_name)) {
				type_name = node_text(child);
			}
		}

		raw = lttng_event_expr_app_specific_context_field_create(provider_name.c_str(),
									 type_name.c_str());
	} else if (is_element(sub, mi_lttng_element_event_expr_array_field_element)) {
		uint64_t index = 0;
		event_expr_uptr parent;

		for (auto child = first_child(sub); child; child = xmlNextElementSibling(child)) {
			if (is_element(child, mi_lttng_element_event_expr_index)) {
				index = node_uint64(child);
			} else if (is_element(child, mi_lttng_element_event_expr)) {
				parent = parse_event_expr(child);
			}
		}

		if (!parent) {
			invalid_config("Missing parent expression in array field element");
		}

		/* The array field element takes ownership of the parent expression. */
		raw = lttng_event_expr_array_field_element_create(parent.release(),
								  static_cast<unsigned int>(index));
	} else {
		invalid_config(std::string("Unknown event expression: ") + element_name(sub));
	}

	if (!raw) {
		throw parse_error(-LTTNG_ERR_NOMEM, "Failed to create event expression");
	}

	return wrap<lttng_event_expr, lttng_event_expr_destroy>(raw);
}

/*
 * condition
 */
condition_uptr parse_condition_event_rule_matches(xmlNodePtr condition_sub_node)
{
	xmlNodePtr event_rule_node = nullptr;
	xmlNodePtr capture_descriptors_node = nullptr;

	for (auto child = first_child(condition_sub_node); child;
	     child = xmlNextElementSibling(child)) {
		if (is_element(child, mi_lttng_element_event_rule)) {
			event_rule_node = child;
		} else if (is_element(child, mi_lttng_element_capture_descriptors)) {
			capture_descriptors_node = child;
		}
	}

	if (!event_rule_node) {
		invalid_config("Missing event rule in event-rule-matches condition");
	}

	const auto rule = parse_event_rule(event_rule_node);

	/* The condition takes a reference to the rule. */
	auto condition = wrap<lttng_condition, lttng_condition_destroy>(
		lttng_condition_event_rule_matches_create(rule.get()));

	if (!condition) {
		throw parse_error(-LTTNG_ERR_NOMEM,
				  "Failed to create event-rule-matches condition");
	}

	if (capture_descriptors_node) {
		for (auto child = first_child(capture_descriptors_node); child;
		     child = xmlNextElementSibling(child)) {
			if (!is_element(child, mi_lttng_element_event_expr)) {
				continue;
			}

			auto expr = parse_event_expr(child);

			/* On success, the capture descriptor takes ownership of the expr. */
			if (lttng_condition_event_rule_matches_append_capture_descriptor(
				    condition.get(), expr.get()) != LTTNG_CONDITION_STATUS_OK) {
				invalid_config("Failed to append capture descriptor");
			}

			expr.release();
		}
	}

	return condition;
}

condition_uptr parse_condition_buffer_usage(xmlNodePtr condition_sub_node, bool high)
{
	auto condition = wrap<lttng_condition, lttng_condition_destroy>(
		high ? lttng_condition_buffer_usage_high_create() :
		       lttng_condition_buffer_usage_low_create());

	if (!condition) {
		throw parse_error(-LTTNG_ERR_NOMEM, "Failed to create buffer usage condition");
	}

	for (auto child = first_child(condition_sub_node); child;
	     child = xmlNextElementSibling(child)) {
		if (is_element(child, mi_lttng_element_session_name)) {
			if (lttng_condition_buffer_usage_set_session_name(
				    condition.get(), node_text(child).c_str()) !=
			    LTTNG_CONDITION_STATUS_OK) {
				invalid_config("Failed to set buffer usage session name");
			}
		} else if (is_element(child, mi_lttng_element_condition_channel_name)) {
			if (lttng_condition_buffer_usage_set_channel_name(
				    condition.get(), node_text(child).c_str()) !=
			    LTTNG_CONDITION_STATUS_OK) {
				invalid_config("Failed to set buffer usage channel name");
			}
		} else if (is_element(child, config_element_domain)) {
			if (lttng_condition_buffer_usage_set_domain_type(
				    condition.get(), parse_domain_type(node_text(child))) !=
			    LTTNG_CONDITION_STATUS_OK) {
				invalid_config("Failed to set buffer usage domain");
			}
		} else if (is_element(child, mi_lttng_element_condition_threshold_bytes)) {
			if (lttng_condition_buffer_usage_set_threshold(condition.get(),
								       node_uint64(child)) !=
			    LTTNG_CONDITION_STATUS_OK) {
				invalid_config("Failed to set buffer usage byte threshold");
			}
		} else if (is_element(child, mi_lttng_element_condition_threshold_ratio)) {
			if (lttng_condition_buffer_usage_set_threshold_ratio(condition.get(),
									     node_double(child)) !=
			    LTTNG_CONDITION_STATUS_OK) {
				invalid_config("Failed to set buffer usage ratio threshold");
			}
		}
	}

	return condition;
}

condition_uptr parse_condition_session_consumed_size(xmlNodePtr condition_sub_node)
{
	auto condition = wrap<lttng_condition, lttng_condition_destroy>(
		lttng_condition_session_consumed_size_create());

	if (!condition) {
		throw parse_error(-LTTNG_ERR_NOMEM,
				  "Failed to create session consumed size condition");
	}

	for (auto child = first_child(condition_sub_node); child;
	     child = xmlNextElementSibling(child)) {
		if (is_element(child, mi_lttng_element_session_name)) {
			if (lttng_condition_session_consumed_size_set_session_name(
				    condition.get(), node_text(child).c_str()) !=
			    LTTNG_CONDITION_STATUS_OK) {
				invalid_config("Failed to set session consumed size session name");
			}
		} else if (is_element(child, mi_lttng_element_condition_threshold_bytes)) {
			if (lttng_condition_session_consumed_size_set_threshold(
				    condition.get(), node_uint64(child)) !=
			    LTTNG_CONDITION_STATUS_OK) {
				invalid_config("Failed to set session consumed size threshold");
			}
		}
	}

	return condition;
}

condition_uptr parse_condition_session_rotation(xmlNodePtr condition_sub_node, bool completed)
{
	auto condition = wrap<lttng_condition, lttng_condition_destroy>(
		completed ? lttng_condition_session_rotation_completed_create() :
			    lttng_condition_session_rotation_ongoing_create());

	if (!condition) {
		throw parse_error(-LTTNG_ERR_NOMEM, "Failed to create session rotation condition");
	}

	for (auto child = first_child(condition_sub_node); child;
	     child = xmlNextElementSibling(child)) {
		if (is_element(child, mi_lttng_element_session_name)) {
			if (lttng_condition_session_rotation_set_session_name(
				    condition.get(), node_text(child).c_str()) !=
			    LTTNG_CONDITION_STATUS_OK) {
				invalid_config("Failed to set session rotation session name");
			}
		}
	}

	return condition;
}

condition_uptr parse_condition(xmlNodePtr condition_node)
{
	const auto sub = first_child(condition_node);

	if (!sub) {
		invalid_config("Empty <condition> element");
	}

	if (is_element(sub, mi_lttng_element_condition_event_rule_matches)) {
		return parse_condition_event_rule_matches(sub);
	} else if (is_element(sub, mi_lttng_element_condition_buffer_usage_high)) {
		return parse_condition_buffer_usage(sub, true);
	} else if (is_element(sub, mi_lttng_element_condition_buffer_usage_low)) {
		return parse_condition_buffer_usage(sub, false);
	} else if (is_element(sub, mi_lttng_element_condition_session_consumed_size)) {
		return parse_condition_session_consumed_size(sub);
	} else if (is_element(sub, mi_lttng_element_condition_session_rotation_completed)) {
		return parse_condition_session_rotation(sub, true);
	} else if (is_element(sub, mi_lttng_element_condition_session_rotation_ongoing)) {
		return parse_condition_session_rotation(sub, false);
	}

	invalid_config(std::string("Unknown condition: ") + element_name(sub));
}

/*
 * action
 */
void set_action_session_name(xmlNodePtr action_sub_node,
			     enum lttng_action_status (*setter)(struct lttng_action *,
								const char *),
			     lttng_action *action)
{
	for (auto child = first_child(action_sub_node); child;
	     child = xmlNextElementSibling(child)) {
		if (is_element(child, mi_lttng_element_session_name)) {
			if (setter(action, node_text(child).c_str()) != LTTNG_ACTION_STATUS_OK) {
				invalid_config("Failed to set action session name");
			}
		}
	}
}

xmlNodePtr find_child(xmlNodePtr parent, const char *name)
{
	for (auto child = first_child(parent); child; child = xmlNextElementSibling(child)) {
		if (is_element(child, name)) {
			return child;
		}
	}

	return nullptr;
}

action_uptr parse_action_notify(xmlNodePtr action_sub_node)
{
	auto action = wrap<lttng_action, lttng_action_destroy>(lttng_action_notify_create());

	if (!action) {
		throw parse_error(-LTTNG_ERR_NOMEM, "Failed to create notify action");
	}

	const auto rate_policy_node = find_child(action_sub_node, mi_lttng_element_rate_policy);
	if (rate_policy_node) {
		set_action_rate_policy(
			rate_policy_node, lttng_action_notify_set_rate_policy, action.get());
	}

	return action;
}

action_uptr parse_action_start_session(xmlNodePtr action_sub_node)
{
	auto action = wrap<lttng_action, lttng_action_destroy>(lttng_action_start_session_create());

	if (!action) {
		throw parse_error(-LTTNG_ERR_NOMEM, "Failed to create start-session action");
	}

	set_action_session_name(
		action_sub_node, lttng_action_start_session_set_session_name, action.get());

	const auto rate_policy_node = find_child(action_sub_node, mi_lttng_element_rate_policy);
	if (rate_policy_node) {
		set_action_rate_policy(
			rate_policy_node, lttng_action_start_session_set_rate_policy, action.get());
	}

	return action;
}

action_uptr parse_action_stop_session(xmlNodePtr action_sub_node)
{
	auto action = wrap<lttng_action, lttng_action_destroy>(lttng_action_stop_session_create());

	if (!action) {
		throw parse_error(-LTTNG_ERR_NOMEM, "Failed to create stop-session action");
	}

	set_action_session_name(
		action_sub_node, lttng_action_stop_session_set_session_name, action.get());

	const auto rate_policy_node = find_child(action_sub_node, mi_lttng_element_rate_policy);
	if (rate_policy_node) {
		set_action_rate_policy(
			rate_policy_node, lttng_action_stop_session_set_rate_policy, action.get());
	}

	return action;
}

action_uptr parse_action_rotate_session(xmlNodePtr action_sub_node)
{
	auto action =
		wrap<lttng_action, lttng_action_destroy>(lttng_action_rotate_session_create());

	if (!action) {
		throw parse_error(-LTTNG_ERR_NOMEM, "Failed to create rotate-session action");
	}

	set_action_session_name(
		action_sub_node, lttng_action_rotate_session_set_session_name, action.get());

	const auto rate_policy_node = find_child(action_sub_node, mi_lttng_element_rate_policy);
	if (rate_policy_node) {
		set_action_rate_policy(rate_policy_node,
				       lttng_action_rotate_session_set_rate_policy,
				       action.get());
	}

	return action;
}

snapshot_output_uptr parse_snapshot_output(xmlNodePtr output_node)
{
	auto output = wrap<lttng_snapshot_output, lttng_snapshot_output_destroy>(
		lttng_snapshot_output_create());

	if (!output) {
		throw parse_error(-LTTNG_ERR_NOMEM, "Failed to create snapshot output");
	}

	for (auto child = first_child(output_node); child; child = xmlNextElementSibling(child)) {
		if (is_element(child, mi_lttng_element_snapshot_max_size)) {
			if (lttng_snapshot_output_set_size(node_uint64(child), output.get()) != 0) {
				invalid_config("Failed to set snapshot output maximum size");
			}
		} else if (is_element(child, config_element_name)) {
			if (lttng_snapshot_output_set_name(node_text(child).c_str(),
							   output.get()) != 0) {
				invalid_config("Failed to set snapshot output name");
			}
		} else if (is_element(child, mi_lttng_element_snapshot_ctrl_url)) {
			if (lttng_snapshot_output_set_ctrl_url(node_text(child).c_str(),
							       output.get()) != 0) {
				invalid_config("Failed to set snapshot output control URL");
			}
		} else if (is_element(child, mi_lttng_element_snapshot_data_url)) {
			if (lttng_snapshot_output_set_data_url(node_text(child).c_str(),
							       output.get()) != 0) {
				invalid_config("Failed to set snapshot output data URL");
			}
		}
		/* The redundant session_name child is ignored. */
	}

	return output;
}

action_uptr parse_action_snapshot_session(xmlNodePtr action_sub_node)
{
	auto action =
		wrap<lttng_action, lttng_action_destroy>(lttng_action_snapshot_session_create());

	if (!action) {
		throw parse_error(-LTTNG_ERR_NOMEM, "Failed to create snapshot-session action");
	}

	set_action_session_name(
		action_sub_node, lttng_action_snapshot_session_set_session_name, action.get());

	const auto output_node =
		find_child(action_sub_node, mi_lttng_element_action_snapshot_session_output);
	if (output_node) {
		auto output = parse_snapshot_output(output_node);

		/* The action takes ownership of the output. */
		if (lttng_action_snapshot_session_set_output(action.get(), output.get()) !=
		    LTTNG_ACTION_STATUS_OK) {
			invalid_config("Failed to set snapshot-session action output");
		}

		output.release();
	}

	const auto rate_policy_node = find_child(action_sub_node, mi_lttng_element_rate_policy);
	if (rate_policy_node) {
		set_action_rate_policy(rate_policy_node,
				       lttng_action_snapshot_session_set_rate_policy,
				       action.get());
	}

	return action;
}

action_uptr parse_action_increment_map_value(xmlNodePtr action_sub_node)
{
	auto action =
		wrap<lttng_action, lttng_action_destroy>(lttng_action_increment_map_value_create());

	if (!action) {
		throw parse_error(-LTTNG_ERR_NOMEM, "Failed to create increment-map-value action");
	}

	for (auto child = first_child(action_sub_node); child;
	     child = xmlNextElementSibling(child)) {
		if (is_element(child, mi_lttng_element_session_name)) {
			if (lttng_action_increment_map_value_set_target_session_name(
				    action.get(), node_text(child).c_str()) !=
			    LTTNG_ACTION_STATUS_OK) {
				invalid_config("Failed to set increment-map-value session name");
			}
		} else if (is_element(child,
				      mi_lttng_element_action_increment_map_value_channel_name)) {
			if (lttng_action_increment_map_value_set_target_channel_name(
				    action.get(), node_text(child).c_str()) !=
			    LTTNG_ACTION_STATUS_OK) {
				invalid_config("Failed to set increment-map-value channel name");
			}
		} else if (is_element(child,
				      mi_lttng_element_action_increment_map_value_channel_type)) {
			const auto text = node_text(child);
			lttng_map_channel_type type;

			if (text == "kernel") {
				type = LTTNG_MAP_CHANNEL_TYPE_KERNEL;
			} else if (text == "user") {
				type = LTTNG_MAP_CHANNEL_TYPE_USER;
			} else {
				invalid_config("Unknown increment-map-value channel type: " + text);
			}

			if (lttng_action_increment_map_value_set_target_channel_type(
				    action.get(), type) != LTTNG_ACTION_STATUS_OK) {
				invalid_config("Failed to set increment-map-value channel type");
			}
		} else if (is_element(child,
				      mi_lttng_element_action_increment_map_value_key_template)) {
			auto key_template = wrap<lttng_key_template, lttng_key_template_destroy>(
				lttng_key_template_create_from_string(node_text(child).c_str()));

			if (!key_template) {
				invalid_config("Invalid increment-map-value key template");
			}

			/* The setter copies the key template. */
			if (lttng_action_increment_map_value_set_key_template(
				    action.get(), key_template.get()) != LTTNG_ACTION_STATUS_OK) {
				invalid_config("Failed to set increment-map-value key template");
			}
		}
		/* This action type has no rate policy. */
	}

	return action;
}

action_uptr parse_action_list(xmlNodePtr action_sub_node)
{
	auto list = wrap<lttng_action, lttng_action_destroy>(lttng_action_list_create());

	if (!list) {
		throw parse_error(-LTTNG_ERR_NOMEM, "Failed to create action list");
	}

	for (auto child = first_child(action_sub_node); child;
	     child = xmlNextElementSibling(child)) {
		if (!is_element(child, mi_lttng_element_action)) {
			continue;
		}

		const auto member = parse_action(child);

		/* The list takes a reference to the action. */
		if (lttng_action_list_add_action(list.get(), member.get()) !=
		    LTTNG_ACTION_STATUS_OK) {
			invalid_config("Failed to add action to action list");
		}
	}

	return list;
}

action_uptr parse_action(xmlNodePtr action_node)
{
	const auto sub = first_child(action_node);

	if (!sub) {
		invalid_config("Empty <action> element");
	}

	if (is_element(sub, mi_lttng_element_action_notify)) {
		return parse_action_notify(sub);
	} else if (is_element(sub, mi_lttng_element_action_start_session)) {
		return parse_action_start_session(sub);
	} else if (is_element(sub, mi_lttng_element_action_stop_session)) {
		return parse_action_stop_session(sub);
	} else if (is_element(sub, mi_lttng_element_action_rotate_session)) {
		return parse_action_rotate_session(sub);
	} else if (is_element(sub, mi_lttng_element_action_snapshot_session)) {
		return parse_action_snapshot_session(sub);
	} else if (is_element(sub, mi_lttng_element_action_increment_map_value)) {
		return parse_action_increment_map_value(sub);
	} else if (is_element(sub, mi_lttng_element_action_list)) {
		return parse_action_list(sub);
	}

	invalid_config(std::string("Unknown action: ") + element_name(sub));
}

/*
 * trigger
 */
struct parsed_trigger {
	std::string name;
	trigger_uptr trigger;
};

parsed_trigger parse_trigger(xmlNodePtr trigger_node)
{
	condition_uptr condition;
	action_uptr action;
	std::string name;

	for (auto child = first_child(trigger_node); child; child = xmlNextElementSibling(child)) {
		if (is_element(child, mi_lttng_element_condition)) {
			condition = parse_condition(child);
		} else if (is_element(child, mi_lttng_element_action)) {
			action = parse_action(child);
		} else if (is_element(child, config_element_name)) {
			name = node_text(child);
		}

		/*
		 * `owner_uid` is deliberately ignored: the trigger is
		 * registered with the credentials of the loading user, exactly
		 * as if its actions were requested right now.
		 */
	}

	if (!condition || !action) {
		invalid_config("Trigger missing its condition or action");
	}

	if (name.empty()) {
		invalid_config("Trigger missing its name");
	}

	/* The trigger takes references to the condition and action. */
	auto trigger = wrap<lttng_trigger, lttng_trigger_destroy>(
		lttng_trigger_create(condition.get(), action.get()));

	if (!trigger) {
		throw parse_error(-LTTNG_ERR_NOMEM, "Failed to create trigger");
	}

	return parsed_trigger{ std::move(name), std::move(trigger) };
}

bool triggers_have_same_condition_and_action(const struct lttng_trigger *a,
					     const struct lttng_trigger *b) noexcept
{
	return lttng_condition_is_equal(lttng_trigger_get_const_condition(a),
					lttng_trigger_get_const_condition(b)) &&
		lttng_action_is_equal(lttng_trigger_get_const_action(a),
				      lttng_trigger_get_const_action(b));
}

const char *trigger_name(const struct lttng_trigger *trigger) noexcept
{
	const char *name = nullptr;

	(void) lttng_trigger_get_name(trigger, &name);
	return name;
}

} /* namespace */

struct trigger_load_state {
	/* Snapshot of the session daemon's triggers, fetched lazily. */
	struct lttng_triggers *existing = nullptr;
	bool existing_fetched = false;
	/* New triggers to register once the sessions are loaded. */
	std::vector<parsed_trigger> to_register;
};

struct trigger_load_state *trigger_load_state_create(void)
{
	try {
		return new trigger_load_state();
	} catch (const std::bad_alloc&) {
		return nullptr;
	}
}

void trigger_load_state_destroy(struct trigger_load_state *state)
{
	if (!state) {
		return;
	}

	lttng_triggers_destroy(state->existing);
	delete state;
}

namespace {

/*
 * Find an existing (already-registered) trigger with the given name, or return
 * nullptr.
 */
const struct lttng_trigger *find_existing_trigger(const struct lttng_triggers *existing,
						  const std::string& name)
{
	unsigned int count = 0;

	if (!existing || lttng_triggers_get_count(existing, &count) != LTTNG_TRIGGER_STATUS_OK) {
		return nullptr;
	}

	for (unsigned int i = 0; i < count; i++) {
		const auto trigger = lttng_triggers_get_at_index(existing, i);
		const auto candidate_name = trigger ? trigger_name(trigger) : nullptr;

		if (candidate_name && name == candidate_name) {
			return trigger;
		}
	}

	return nullptr;
}

int process_triggers_node(struct trigger_load_state *state, xmlNodePtr triggers_node)
{
	/* Fetch the existing triggers once, on the first call. */
	if (!state->existing_fetched) {
		const auto list_ret = lttng_list_triggers(&state->existing);

		if (list_ret != LTTNG_OK) {
			return -list_ret;
		}

		state->existing_fetched = true;
	}

	for (auto trigger_node = first_child(triggers_node); trigger_node;
	     trigger_node = xmlNextElementSibling(trigger_node)) {
		if (!is_element(trigger_node, mi_lttng_element_trigger)) {
			continue;
		}

		auto parsed = parse_trigger(trigger_node);

		/*
		 * Deduplicate against triggers already queued from other
		 * files, applying the same conflict policy as for the existing
		 * session daemon triggers below: a same-name trigger with a
		 * different condition or action aborts the whole load.
		 */
		bool already_queued = false;
		for (const auto& pending : state->to_register) {
			if (pending.name != parsed.name) {
				continue;
			}

			if (!triggers_have_same_condition_and_action(parsed.trigger.get(),
								     pending.trigger.get())) {
				ERR("Cannot load trigger \"%s\": another configuration file defines a trigger with the same name but a different condition or action",
				    parsed.name.c_str());
				return -LTTNG_ERR_LOAD_INVALID_CONFIG;
			}

			already_queued = true;
			break;
		}

		if (already_queued) {
			continue;
		}

		/* Conflict check against the existing session daemon triggers. */
		const auto existing = find_existing_trigger(state->existing, parsed.name);
		if (existing) {
			if (!triggers_have_same_condition_and_action(parsed.trigger.get(),
								     existing)) {
				ERR("Cannot load trigger \"%s\": a trigger with the same name but a different condition or action already exists",
				    parsed.name.c_str());
				return -LTTNG_ERR_LOAD_INVALID_CONFIG;
			}

			/* Identical trigger already registered: nothing to do. */
			continue;
		}

		state->to_register.push_back(std::move(parsed));
	}

	return 0;
}

} /* namespace */

int trigger_load_state_process_node(struct trigger_load_state *state, xmlNodePtr triggers_node)
{
	LTTNG_ASSERT(state);
	LTTNG_ASSERT(triggers_node);

	try {
		return process_triggers_node(state, triggers_node);
	} catch (const parse_error& ex) {
		ERR("Failed to load trigger configuration: %s", ex.what());
		return ex.code();
	} catch (const std::bad_alloc&) {
		return -LTTNG_ERR_NOMEM;
	}
}

int trigger_load_state_register(struct trigger_load_state *state)
{
	LTTNG_ASSERT(state);

	for (const auto& pending : state->to_register) {
		const auto register_ret = lttng_register_trigger_with_name(pending.trigger.get(),
									   pending.name.c_str());

		if (register_ret != LTTNG_OK) {
			ERR("Failed to register loaded trigger \"%s\"", pending.name.c_str());
			return -register_ret;
		}
	}

	return 0;
}
