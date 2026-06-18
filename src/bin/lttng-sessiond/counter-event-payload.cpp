/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "counter-event-payload.hpp"
#include "event.hpp"
#include "kernel.hpp"

#include <common/error.hpp>
#include <common/exception.hpp>
#include <common/format.hpp>
#include <common/lttng-kernel.hpp>
#include <common/macros.hpp>

#include <lttng/action/increment-map-value.h>
#include <lttng/action/key-template-internal.hpp>
#include <lttng/event-rule/event-rule-internal.hpp>
#include <lttng/event-rule/event-rule.h>
#include <lttng/event-rule/user-tracepoint.h>
#include <lttng/log-level-rule.h>
#ifdef HAVE_LIBLTTNG_UST_CTL
#include <lttng/ust-ctl.h>
#endif

#include <cstddef>
#include <cstdint>
#include <string>

namespace lttng {
namespace sessiond {
namespace map {
namespace details {

namespace {
struct counter_event_payload_intermediate {
	struct token {
		enum class kind {
			LITERAL,
			EVENT_NAME,
			PROVIDER_NAME,
		};

		kind type;
		std::string literal_text;
	};

	const lttng_event_rule *event_rule;
	std::vector<token> key_tokens;
	std::uint64_t user_token;
};

void append_bytes(std::vector<char>& buffer, const void *data, std::size_t size)
{
	const auto *const bytes = static_cast<const char *>(data);

	buffer.insert(buffer.end(), bytes, bytes + size);
}

/*
 * Serialize a counter-event payload shared by UST and kernel ABIs.
 * The layout is fixed; only concrete types and enum values vary.
 */
template <typename CounterEventType,
	  typename EmbeddedEventType,
	  typename DimensionTokensType,
	  typename KeyTokenType,
	  typename KeyTokenStringType>
std::vector<char>
serialize_counter_event(const EmbeddedEventType& embedded_event,
			const std::vector<counter_event_payload_intermediate::token>& tokens,
			std::uint32_t increment_action,
			std::uint32_t key_type_tokens,
			std::uint32_t token_type_string,
			std::uint32_t token_type_event_name,
			std::uint32_t token_type_provider_name)
{
	using token = counter_event_payload_intermediate::token;

	/* Compute and reserve final size to avoid growth reallocations. */
	std::size_t total_size = sizeof(CounterEventType) + sizeof(DimensionTokensType);
	for (const auto& key_token : tokens) {
		total_size += key_token.type == token::kind::LITERAL ?
			sizeof(KeyTokenStringType) + key_token.literal_text.size() + 1 :
			sizeof(KeyTokenType);
	}

	std::vector<char> buffer;
	buffer.reserve(total_size);

	CounterEventType counter_event = {};
	counter_event.len = sizeof(CounterEventType);
	counter_event.action = increment_action;
	counter_event.event = embedded_event;
	counter_event.number_key_dimensions = 1;
	append_bytes(buffer, &counter_event, sizeof(counter_event));

	DimensionTokensType dimension = {};
	dimension.parent.len = sizeof(DimensionTokensType);
	dimension.parent.key_type = key_type_tokens;
	dimension.nr_key_tokens = static_cast<std::uint32_t>(tokens.size());
	append_bytes(buffer, &dimension, sizeof(dimension));

	for (const auto& key_token : tokens) {
		switch (key_token.type) {
		case token::kind::LITERAL:
		{
			KeyTokenStringType token_string = {};
			token_string.parent.len = sizeof(KeyTokenStringType);
			token_string.parent.type = token_type_string;
			/* string_len includes the trailing NUL. */
			token_string.string_len =
				static_cast<std::uint32_t>(key_token.literal_text.size() + 1);
			append_bytes(buffer, &token_string, sizeof(token_string));
			append_bytes(buffer,
				     key_token.literal_text.c_str(),
				     key_token.literal_text.size() + 1);
			break;
		}
		case token::kind::EVENT_NAME:
		case token::kind::PROVIDER_NAME:
		{
			KeyTokenType token_header = {};
			token_header.len = sizeof(KeyTokenType);
			token_header.type = key_token.type == token::kind::EVENT_NAME ?
				token_type_event_name :
				token_type_provider_name;
			append_bytes(buffer, &token_header, sizeof(token_header));
			break;
		}
		}
	}

	LTTNG_ASSERT(buffer.size() == total_size);
	return buffer;
}

#ifdef HAVE_LIBLTTNG_UST_CTL
/* Build the UST embedded event, mirroring event-notifier rule lowering. */
lttng_ust_abi_event build_ust_embedded_event(const lttng_event_rule& rule, std::uint64_t user_token)
{
	lttng_ust_abi_event event = {};
	auto loglevel_type = LTTNG_UST_ABI_LOGLEVEL_ALL;
	int loglevel = -1;
	const char *pattern = nullptr;

	if (lttng_event_rule_targets_agent_domain(&rule)) {
		pattern = event_get_default_agent_ust_name(lttng_event_rule_get_domain_type(&rule));
		loglevel = 0;
		loglevel_type = LTTNG_UST_ABI_LOGLEVEL_ALL;
	} else {
		LTTNG_ASSERT(lttng_event_rule_get_type(&rule) ==
			     LTTNG_EVENT_RULE_TYPE_USER_TRACEPOINT);

		if (lttng_event_rule_user_tracepoint_get_name_pattern(&rule, &pattern) !=
		    LTTNG_EVENT_RULE_STATUS_OK) {
			LTTNG_THROW_ERROR(
				"Failed to get name pattern of user-tracepoint event rule "
				"for UST counter-event");
		}

		const lttng_log_level_rule *log_level_rule = nullptr;
		const auto log_level_status =
			lttng_event_rule_user_tracepoint_get_log_level_rule(&rule, &log_level_rule);
		if (log_level_status == LTTNG_EVENT_RULE_STATUS_UNSET) {
			loglevel_type = LTTNG_UST_ABI_LOGLEVEL_ALL;
		} else if (log_level_status == LTTNG_EVENT_RULE_STATUS_OK) {
			switch (lttng_log_level_rule_get_type(log_level_rule)) {
			case LTTNG_LOG_LEVEL_RULE_TYPE_EXACTLY:
			{
				loglevel_type = LTTNG_UST_ABI_LOGLEVEL_SINGLE;
				const auto get_level_status =
					lttng_log_level_rule_exactly_get_level(log_level_rule,
									       &loglevel);
				LTTNG_ASSERT(get_level_status == LTTNG_LOG_LEVEL_RULE_STATUS_OK);
				break;
			}
			case LTTNG_LOG_LEVEL_RULE_TYPE_AT_LEAST_AS_SEVERE_AS:
			{
				loglevel_type = LTTNG_UST_ABI_LOGLEVEL_RANGE;
				const auto get_level_status =
					lttng_log_level_rule_at_least_as_severe_as_get_level(
						log_level_rule, &loglevel);
				LTTNG_ASSERT(get_level_status == LTTNG_LOG_LEVEL_RULE_STATUS_OK);
				break;
			}
			default:
				LTTNG_THROW_ERROR(
					"Unknown log-level rule type for UST counter-event");
			}
		} else {
			LTTNG_THROW_ERROR(
				"Failed to get log-level rule of user-tracepoint event rule "
				"for UST counter-event");
		}
	}

	event.instrumentation = LTTNG_UST_ABI_TRACEPOINT;
	if (lttng_strncpy(event.name, pattern, sizeof(event.name))) {
		LTTNG_THROW_ERROR(lttng::format(
			"Event name too long for UST counter-event: name=`{}`", pattern));
	}

	event.loglevel_type = loglevel_type;
	event.loglevel = loglevel;
	event.token = user_token;
	return event;
}
#endif /* HAVE_LIBLTTNG_UST_CTL */

void append_token(std::vector<counter_event_payload_intermediate::token>& key_tokens,
		  const counter_event_payload_intermediate::token::kind kind,
		  std::string literal_text = {})
{
	counter_event_payload_intermediate::token key_token;

	key_token.type = kind;
	key_token.literal_text = std::move(literal_text);
	key_tokens.push_back(std::move(key_token));
}

counter_event_payload_intermediate
build_intermediate(const lttng_event_rule& event_rule,
		   const lttng_action& incr_map_value_action,
		   std::uint64_t user_token,
		   const bool qualify_ust_event_name_with_provider)
{
	counter_event_payload_intermediate intermediate;

	intermediate.event_rule = &event_rule;
	intermediate.user_token = user_token;

	const auto *const key_template =
		lttng_action_increment_map_value_get_key_template(&incr_map_value_action);
	LTTNG_ASSERT(key_template);

	for (const auto& segment : key_template->segments) {
		switch (segment->type) {
		case lttng::action::details::key_template_segment_type::LITERAL:
			append_token(
				intermediate.key_tokens,
				counter_event_payload_intermediate::token::kind::LITERAL,
				static_cast<
					const lttng::action::details::key_template_literal_segment&>(
					*segment)
					.text);
			break;
		case lttng::action::details::key_template_segment_type::EVENT_NAME:
			/*
			 * For LTTng-UST, the
			 * `LTTNG_KEY_TOKEN_EVENT_NAME` token only
			 * expands to the bare tracepoint name, while
			 * the full event name, as found in a metadata
			 * stream, is `provider_name:tracepoint_name`.
			 *
			 * The `EVENT_NAME` template segment is
			 * documented as the full event class name,
			 * therefore expand it to the equivalent
			 * `LTTNG_KEY_TOKEN_PROVIDER_NAME` +
			 * `LTTNG_KEY_TOKEN_STRING` (`:`) +
			 * `LTTNG_KEY_TOKEN_EVENT_NAME` token sequence.
			 *
			 * The kernel `LTTNG_KEY_TOKEN_EVENT_NAME` token
			 * already expands to the full event name, so
			 * leave it as a single token.
			 */
			if (qualify_ust_event_name_with_provider) {
				append_token(intermediate.key_tokens,
					     counter_event_payload_intermediate::token::kind::
						     PROVIDER_NAME);
				append_token(
					intermediate.key_tokens,
					counter_event_payload_intermediate::token::kind::LITERAL,
					":");
			}

			append_token(intermediate.key_tokens,
				     counter_event_payload_intermediate::token::kind::EVENT_NAME);
			break;
		case lttng::action::details::key_template_segment_type::PROVIDER_NAME:
			append_token(
				intermediate.key_tokens,
				counter_event_payload_intermediate::token::kind::PROVIDER_NAME);
			break;
		}
	}

	return intermediate;
}
} /* namespace */

#ifdef HAVE_LIBLTTNG_UST_CTL
std::vector<char> serialize_for_ust(const lttng_event_rule& event_rule,
				    const lttng_action& incr_map_value_action,
				    std::uint64_t user_token)
{
	const auto intermediate =
		build_intermediate(event_rule, incr_map_value_action, user_token, true);

	LTTNG_ASSERT(!intermediate.key_tokens.empty());

	const auto embedded_event =
		build_ust_embedded_event(*intermediate.event_rule, intermediate.user_token);

	return serialize_counter_event<lttng_ust_abi_counter_event,
				       lttng_ust_abi_event,
				       lttng_ust_abi_counter_key_dimension_tokens,
				       lttng_ust_abi_key_token,
				       lttng_ust_abi_key_token_string>(
		embedded_event,
		intermediate.key_tokens,
		LTTNG_UST_ABI_COUNTER_ACTION_INCREMENT,
		LTTNG_UST_ABI_KEY_TYPE_TOKENS,
		LTTNG_UST_ABI_KEY_TOKEN_STRING,
		LTTNG_UST_ABI_KEY_TOKEN_EVENT_NAME,
		LTTNG_UST_ABI_KEY_TOKEN_PROVIDER_NAME);
}
#endif /* HAVE_LIBLTTNG_UST_CTL */

std::vector<char> serialize_for_modules(const lttng_event_rule& event_rule,
					const lttng_action& incr_map_value_action,
					std::uint64_t user_token)
{
	const auto intermediate =
		build_intermediate(event_rule, incr_map_value_action, user_token, false);

	LTTNG_ASSERT(!intermediate.key_tokens.empty());

	auto embedded_event =
		modules::make_kernel_abi_event_from_event_rule(intermediate.event_rule);
	embedded_event.token = intermediate.user_token;

	return serialize_counter_event<lttng_kernel_abi_counter_event,
				       lttng_kernel_abi_event,
				       lttng_kernel_abi_counter_key_dimension_tokens,
				       lttng_kernel_abi_key_token,
				       lttng_kernel_abi_key_token_string>(
		embedded_event,
		intermediate.key_tokens,
		LTTNG_KERNEL_ABI_COUNTER_ACTION_INCREMENT,
		LTTNG_KERNEL_ABI_KEY_TYPE_TOKENS,
		LTTNG_KERNEL_ABI_KEY_TOKEN_STRING,
		LTTNG_KERNEL_ABI_KEY_TOKEN_EVENT_NAME,
		LTTNG_KERNEL_ABI_KEY_TOKEN_PROVIDER_NAME);
}

} /* namespace details */
} /* namespace map */
} /* namespace sessiond */
} /* namespace lttng */
