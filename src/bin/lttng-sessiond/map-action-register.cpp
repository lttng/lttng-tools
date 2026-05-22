/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "domain-orchestrator.hpp"
#include "domain.hpp"
#include "map-action-register.hpp"
#include "map-channel-configuration.hpp"
#include "trigger-utils.hpp"

#include <common/domain.hpp>
#include <common/error.hpp>
#include <common/exception.hpp>
#include <common/format.hpp>
#include <common/string-utils/c-string-view.hpp>

#include <lttng/action/action.h>
#include <lttng/action/increment-map-value.h>
#include <lttng/action/list-internal.hpp>
#include <lttng/condition/condition.h>
#include <lttng/condition/event-rule-matches.h>
#include <lttng/domain.h>
#include <lttng/trigger/trigger.h>

namespace lsm = lttng::sessiond::map;

namespace {
enum class binding_operation {
	REGISTER,
	UNREGISTER,
};

const char *operation_str(binding_operation operation) noexcept
{
	return operation == binding_operation::REGISTER ? "register" : "unregister";
}

void visit_increment_map_value_actions(const lttng_action& action,
				       const std::function<void(const lttng_action&)>& visitor)
{
	switch (lttng_action_get_type(&action)) {
	case LTTNG_ACTION_TYPE_INCREMENT_MAP_VALUE:
		visitor(action);
		break;
	case LTTNG_ACTION_TYPE_LIST:
		for (const auto *const inner_action : lttng::ctl::const_action_list_view(&action)) {
			visit_increment_map_value_actions(*inner_action, visitor);
		}
		break;
	default:
		break;
	}
}

/*
 * Apply one register/unregister operation on action's target map channel.
 * The session is already locked. Permission denials and missing channels skip.
 */
void apply_to_locked_session(const lttng_trigger& trigger,
			     const ltt_session::locked_ref& session,
			     const lttng_action& action,
			     binding_operation operation)
{
	if (!lttng::sessiond::is_trigger_allowed_for_session(&trigger, session)) {
		/* is_trigger_allowed_for_session already logged the denial. */
		return;
	}

	const char *const channel_name =
		lttng_action_increment_map_value_get_target_channel_name(&action);
	if (!channel_name || channel_name[0] == '\0') {
		LTTNG_THROW_INVALID_ARGUMENT_ERROR(
			"Increment-map-value action target channel name is unset");
	}

	lttng_domain_type target_domain = LTTNG_DOMAIN_NONE;
	const auto domain_status =
		lttng_action_increment_map_value_get_target_domain(&action, &target_domain);
	if (domain_status != LTTNG_ACTION_STATUS_OK) {
		LTTNG_THROW_INVALID_ARGUMENT_ERROR(lttng::format(
			"Increment-map-value action target domain is unset or invalid: status={}",
			static_cast<int>(domain_status)));
	}

	/* The trigger condition carries the event rule to bind. */
	const auto *const condition = lttng_trigger_get_const_condition(&trigger);
	LTTNG_ASSERT(lttng_condition_get_type(condition) ==
		     LTTNG_CONDITION_TYPE_EVENT_RULE_MATCHES);

	const lttng_event_rule *event_rule = nullptr;
	const auto rule_status =
		lttng_condition_event_rule_matches_get_rule(condition, &event_rule);
	LTTNG_ASSERT(rule_status == LTTNG_CONDITION_STATUS_OK);

	const auto domain_class = lttng::get_domain_class_from_lttng_domain_type(target_domain);

	/* Resolve channel configuration before touching the orchestrator. */
	const lttng::sessiond::config::map_channel_configuration *channel_config = nullptr;
	try {
		channel_config = &session->get_domain(domain_class).get_map_channel(channel_name);
	} catch (const lttng::sessiond::config::exceptions::map_channel_not_found_error&) {
		DBG_FMT("No map channel `{}` on the target domain; skipping incr-map-value {}: session_name=`{}`",
			channel_name,
			operation_str(operation),
			session->name);
		return;
	}

	if (operation == binding_operation::REGISTER) {
		if (target_domain == LTTNG_DOMAIN_KERNEL) {
			session->get_kernel_orchestrator().add_map_channel_event_rule(
				*channel_config, *event_rule, action);
		} else {
			session->get_ust_orchestrator().add_map_channel_event_rule(
				*channel_config, *event_rule, action);
		}
	} else {
		if (target_domain == LTTNG_DOMAIN_KERNEL) {
			session->get_kernel_orchestrator().remove_map_channel_event_rule(
				*channel_config, *event_rule, action);
		} else {
			session->get_ust_orchestrator().remove_map_channel_event_rule(
				*channel_config, *event_rule, action);
		}
	}
}

/* Resolve the target session by name, then apply operation. */
void lookup_session_and_apply(const lttng_trigger& trigger,
			      const lttng_action& action,
			      binding_operation operation)
{
	const char *const session_name =
		lttng_action_increment_map_value_get_target_session_name(&action);
	const char *const channel_name =
		lttng_action_increment_map_value_get_target_channel_name(&action);
	if (!session_name || session_name[0] == '\0') {
		LTTNG_THROW_INVALID_ARGUMENT_ERROR(
			"Increment-map-value action target session name is unset");
	}

	if (!channel_name || channel_name[0] == '\0') {
		LTTNG_THROW_INVALID_ARGUMENT_ERROR(
			"Increment-map-value action target channel name is unset");
	}

	/*
	 * The list lock is declared before the session reference: releasing a
	 * session reference may unpublish the session from the list, so the
	 * reference must drop while the list lock is still held.
	 */
	const auto list_lock = lttng::sessiond::lock_session_list();
	try {
		const auto session =
			ltt_session::find_locked_session(lttng::c_string_view(session_name));
		apply_to_locked_session(trigger, session, action, operation);
	} catch (const lttng::sessiond::exceptions::session_not_found_error&) {
		DBG_FMT("Target session `{}` not found; skipping incr-map-value {}",
			session_name,
			operation_str(operation));
	}
}
} /* namespace */

void lsm::attempt_register(const lttng_trigger& trigger, const lttng_action& incr_map_value_action)
{
	lookup_session_and_apply(trigger, incr_map_value_action, binding_operation::REGISTER);
}

void lsm::attempt_register(const lttng_trigger& trigger,
			   const ltt_session::locked_ref& target_session,
			   const lttng_action& incr_map_value_action)
{
	const char *const session_name =
		lttng_action_increment_map_value_get_target_session_name(&incr_map_value_action);
	const char *const channel_name =
		lttng_action_increment_map_value_get_target_channel_name(&incr_map_value_action);
	if (!session_name || session_name[0] == '\0') {
		LTTNG_THROW_INVALID_ARGUMENT_ERROR(
			"Increment-map-value action target session name is unset");
	}

	if (!channel_name || channel_name[0] == '\0') {
		LTTNG_THROW_INVALID_ARGUMENT_ERROR(
			"Increment-map-value action target channel name is unset");
	}

	/* Apply only if the action targets the caller-provided session. */
	if (lttng::c_string_view(target_session->name) != lttng::c_string_view(session_name)) {
		return;
	}

	apply_to_locked_session(
		trigger, target_session, incr_map_value_action, binding_operation::REGISTER);
}

void lsm::attempt_unregister(const lttng_trigger& trigger,
			     const lttng_action& incr_map_value_action)
{
	lookup_session_and_apply(trigger, incr_map_value_action, binding_operation::UNREGISTER);
}

void lsm::for_each_increment_map_value_action(
	const lttng_trigger& trigger, const std::function<void(const lttng_action&)>& visitor)
{
	visit_increment_map_value_actions(*lttng_trigger_get_const_action(&trigger), visitor);
}
