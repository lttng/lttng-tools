/*
 * SPDX-FileCopyrightText: 2021 Simon Marchi <simon.marchi@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "../command.hpp"
#include "../loglevel.hpp"
#include "../uprobe.hpp"
#include "common/argpar-utils/argpar-utils.hpp"
#include "common/ctl/format.hpp"
#include "common/dynamic-array.hpp"
#include "common/mi-lttng.hpp"
#include "common/string-utils/string-utils.hpp"
#include "common/utils.hpp"
#include "vendor/argpar/argpar.h"

#include <lttng/domain-internal.hpp>

#include <ctype.h>
#include <exception>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
/* For lttng_event_rule_type_str(). */
#include "common/dynamic-array.hpp"
#include "common/filter/filter-ast.hpp"
#include "common/filter/filter-ir.hpp"

#include <lttng/condition/condition-internal.hpp>
#include <lttng/event-rule/event-rule-internal.hpp>
#include <lttng/lttng.h>

#if (LTTNG_SYMBOL_NAME_LEN == 256)
#define LTTNG_SYMBOL_NAME_LEN_SCANF_IS_A_BROKEN_API "255"
#endif

#ifdef LTTNG_EMBED_HELP
static const char help_msg[] =
#include <lttng-add-trigger.1.h>
	;
#endif

enum {
	OPT_HELP,
	OPT_LIST_OPTIONS,

	OPT_CONDITION,
	OPT_ACTION,
	OPT_ID,
	OPT_OWNER_UID,
	OPT_RATE_POLICY,

	OPT_NAME,
	OPT_FILTER,
	OPT_EXCLUDE_NAME,
	OPT_EVENT_NAME,
	OPT_LOG_LEVEL,

	OPT_TYPE,
	OPT_LOCATION,

	OPT_MAX_SIZE,
	OPT_DATA_URL,
	OPT_CTRL_URL,
	OPT_URL,
	OPT_PATH,

	OPT_CAPTURE,

	OPT_SESSION_NAME,
	OPT_THRESHOLD_SIZE,

	OPT_CHANNEL_NAME,
	OPT_DOMAIN,
	OPT_DOMAIN_UST,
	OPT_DOMAIN_KERNEL,
	OPT_THRESHOLD_RATIO,
};

static const struct argpar_opt_descr buffer_usage_opt_descriptions[] = {
	{ OPT_SESSION_NAME, 's', "session", true },
	{ OPT_CHANNEL_NAME, 'c', "channel", true },
	{ OPT_DOMAIN, 'd', "domain", true },
	{ OPT_DOMAIN_UST, 'u', "userspace", false },
	{ OPT_DOMAIN_KERNEL, 'k', "kernel", false },
	{ OPT_THRESHOLD_SIZE, 't', "threshold-size", true },
	{ OPT_THRESHOLD_RATIO, 'r', "threshold-ratio", true },
	ARGPAR_OPT_DESCR_SENTINEL
};

static const struct argpar_opt_descr event_rule_opt_descrs[] = {
	{ OPT_FILTER, 'f', "filter", true },
	{ OPT_NAME, 'n', "name", true },
	{ OPT_EXCLUDE_NAME, 'x', "exclude-name", true },
	{ OPT_LOG_LEVEL, 'l', "log-level", true },
	{ OPT_EVENT_NAME, 'E', "event-name", true },

	{ OPT_TYPE, 't', "type", true },
	{ OPT_LOCATION, 'L', "location", true },

	/* Capture descriptor */
	{ OPT_CAPTURE, '\0', "capture", true },

	ARGPAR_OPT_DESCR_SENTINEL
};

static const struct argpar_opt_descr session_consumed_size_opt_descriptions[] = {
	{ OPT_SESSION_NAME, 's', "session", true },
	{ OPT_THRESHOLD_SIZE, 't', "threshold-size", true },
	ARGPAR_OPT_DESCR_SENTINEL,
};

static const struct argpar_opt_descr session_rotation_opt_descriptions[] = {
	{ OPT_SESSION_NAME, 's', "session", true },
	ARGPAR_OPT_DESCR_SENTINEL,
};

static bool has_syscall_prefix(const char *arg)
{
	bool matches = false;
	const char kernel_syscall_type_opt_prefix[] = "kernel:syscall";
	const size_t kernel_syscall_type_opt_prefix_len =
		sizeof(kernel_syscall_type_opt_prefix) - 1;
	const char syscall_type_opt_prefix[] = "syscall";
	const size_t syscall_type_opt_prefix_len = sizeof(syscall_type_opt_prefix) - 1;

	if (strncmp(arg, syscall_type_opt_prefix, syscall_type_opt_prefix_len) == 0) {
		matches = true;
	} else if (strncmp(arg,
			   kernel_syscall_type_opt_prefix,
			   kernel_syscall_type_opt_prefix_len) == 0) {
		matches = true;
	} else {
		matches = false;
	}

	return matches;
}

static bool assign_event_rule_type(enum lttng_event_rule_type *dest, const char *arg)
{
	bool ret;

	if (*dest != LTTNG_EVENT_RULE_TYPE_UNKNOWN) {
		ERR("More than one `--type` was specified.");
		goto error;
	}

	if (strcmp(arg, "user") == 0 || strcmp(arg, "user:tracepoint") == 0) {
		*dest = LTTNG_EVENT_RULE_TYPE_USER_TRACEPOINT;
	} else if (strcmp(arg, "kernel") == 0 || strcmp(arg, "kernel:tracepoint") == 0) {
		*dest = LTTNG_EVENT_RULE_TYPE_KERNEL_TRACEPOINT;
	} else if (strcmp(arg, "jul") == 0 || strcmp(arg, "jul:logging") == 0) {
		*dest = LTTNG_EVENT_RULE_TYPE_JUL_LOGGING;
	} else if (strcmp(arg, "log4j") == 0 || strcmp(arg, "log4j:logging") == 0) {
		*dest = LTTNG_EVENT_RULE_TYPE_LOG4J_LOGGING;
	} else if (strcmp(arg, "log4j2") == 0 || strcmp(arg, "log4j2:logging") == 0) {
		*dest = LTTNG_EVENT_RULE_TYPE_LOG4J2_LOGGING;
	} else if (strcmp(arg, "python") == 0 || strcmp(arg, "python:logging") == 0) {
		*dest = LTTNG_EVENT_RULE_TYPE_PYTHON_LOGGING;
	} else if (strcmp(arg, "kprobe") == 0 || strcmp(arg, "kernel:kprobe") == 0) {
		*dest = LTTNG_EVENT_RULE_TYPE_KERNEL_KPROBE;
	} else if (strcmp(arg, "kernel:uprobe") == 0) {
		*dest = LTTNG_EVENT_RULE_TYPE_KERNEL_UPROBE;
	} else if (has_syscall_prefix(arg)) {
		/*
		 * Matches the following:
		 *   - syscall
		 *   - syscall:entry
		 *   - syscall:exit
		 *   - syscall:entry+exit
		 *   - syscall:*
		 *   - kernel:syscall
		 *   - kernel:syscall:entry
		 *   - kernel:syscall:exit
		 *   - kernel:syscall:entry+exit
		 *   - kernel:syscall:*
		 *
		 * Validation for the right side is left to further usage sites.
		 */
		*dest = LTTNG_EVENT_RULE_TYPE_KERNEL_SYSCALL;
	} else {
		ERR("Invalid `--type` value: %s", arg);
		goto error;
	}

	ret = true;
	goto end;

error:
	ret = false;

end:
	return ret;
}

static bool assign_string(char **dest, const char *src, const char *opt_name)
{
	bool ret;

	if (*dest) {
		ERR("Duplicate '%s' given.", opt_name);
		goto error;
	}

	*dest = strdup(src);
	if (!*dest) {
		PERROR("Failed to allocate string '%s'.", opt_name);
		goto error;
	}

	ret = true;
	goto end;

error:
	ret = false;

end:
	return ret;
}

static bool
parse_syscall_emission_site_from_type(const char *str,
				      enum lttng_event_rule_kernel_syscall_emission_site *type)
{
	bool ret = false;
	const char kernel_prefix[] = "kernel:";
	const size_t kernel_prefix_len = sizeof(kernel_prefix) - 1;

	/*
	 * If the passed string is of the form "kernel:syscall*", move the
	 * pointer passed "kernel:".
	 */
	if (strncmp(str, kernel_prefix, kernel_prefix_len) == 0) {
		str = &str[kernel_prefix_len];
	}

	if (strcmp(str, "syscall") == 0 || strcmp(str, "syscall:entry+exit") == 0) {
		*type = LTTNG_EVENT_RULE_KERNEL_SYSCALL_EMISSION_SITE_ENTRY_EXIT;
	} else if (strcmp(str, "syscall:entry") == 0) {
		*type = LTTNG_EVENT_RULE_KERNEL_SYSCALL_EMISSION_SITE_ENTRY;
	} else if (strcmp(str, "syscall:exit") == 0) {
		*type = LTTNG_EVENT_RULE_KERNEL_SYSCALL_EMISSION_SITE_EXIT;
	} else {
		goto error;
	}

	ret = true;

error:
	return ret;
}

/*
 * Parse `str` as a log level against the passed event rule type.
 *
 * Return the log level in `*log_level`.  Return true in `*log_level_only` if
 * the string specifies exactly this log level, false if it specifies at least
 * this log level.
 *
 * Return true if the string was successfully parsed as a log level string.
 */
static bool parse_log_level_string(const char *str,
				   enum lttng_event_rule_type event_rule_type,
				   int *log_level,
				   bool *log_level_only)
{
	bool ret;

	switch (event_rule_type) {
	case LTTNG_EVENT_RULE_TYPE_USER_TRACEPOINT:
	{
		enum lttng_loglevel log_level_least_severe, log_level_most_severe;
		if (!loglevel_parse_range_string(
			    str, &log_level_least_severe, &log_level_most_severe)) {
			goto error;
		}

		/* Only support VAL and VAL.. for now. */
		if (log_level_least_severe != log_level_most_severe &&
		    log_level_most_severe != LTTNG_LOGLEVEL_EMERG) {
			goto error;
		}

		*log_level = (int) log_level_least_severe;
		*log_level_only = log_level_least_severe == log_level_most_severe;
		break;
	}
	case LTTNG_EVENT_RULE_TYPE_LOG4J_LOGGING:
	{
		enum lttng_loglevel_log4j log_level_least_severe, log_level_most_severe;
		if (!loglevel_log4j_parse_range_string(
			    str, &log_level_least_severe, &log_level_most_severe)) {
			goto error;
		}

		/* Only support VAL and VAL.. for now. */
		if (log_level_least_severe != log_level_most_severe &&
		    log_level_most_severe != LTTNG_LOGLEVEL_LOG4J_FATAL) {
			goto error;
		}

		*log_level = (int) log_level_least_severe;
		*log_level_only = log_level_least_severe == log_level_most_severe;
		break;
	}
	case LTTNG_EVENT_RULE_TYPE_LOG4J2_LOGGING:
	{
		enum lttng_loglevel_log4j2 log_level_least_severe, log_level_most_severe;
		if (!loglevel_log4j2_parse_range_string(
			    str, &log_level_least_severe, &log_level_most_severe)) {
			goto error;
		}

		/* Only support VAL and VAL.. for now. */
		if (log_level_least_severe != log_level_most_severe &&
		    log_level_most_severe != LTTNG_LOGLEVEL_LOG4J2_FATAL) {
			goto error;
		}

		*log_level = (int) log_level_least_severe;
		*log_level_only = log_level_least_severe == log_level_most_severe;
		break;
	}
	case LTTNG_EVENT_RULE_TYPE_JUL_LOGGING:
	{
		enum lttng_loglevel_jul log_level_least_severe, log_level_most_severe;
		if (!loglevel_jul_parse_range_string(
			    str, &log_level_least_severe, &log_level_most_severe)) {
			goto error;
		}

		/* Only support VAL and VAL.. for now. */
		if (log_level_least_severe != log_level_most_severe &&
		    log_level_most_severe != LTTNG_LOGLEVEL_JUL_SEVERE) {
			goto error;
		}

		*log_level = (int) log_level_least_severe;
		*log_level_only = log_level_least_severe == log_level_most_severe;
		break;
	}
	case LTTNG_EVENT_RULE_TYPE_PYTHON_LOGGING:
	{
		enum lttng_loglevel_python log_level_least_severe, log_level_most_severe;
		if (!loglevel_python_parse_range_string(
			    str, &log_level_least_severe, &log_level_most_severe)) {
			goto error;
		}

		/* Only support VAL and VAL.. for now. */
		if (log_level_least_severe != log_level_most_severe &&
		    log_level_most_severe != LTTNG_LOGLEVEL_PYTHON_CRITICAL) {
			goto error;
		}

		*log_level = (int) log_level_least_severe;
		*log_level_only = log_level_least_severe == log_level_most_severe;
		break;
	}
	default:
		/* Invalid domain type. */
		abort();
	}

	ret = true;
	goto end;

error:
	ret = false;

end:
	return ret;
}

static int parse_kernel_probe_opts(const char *source,
				   struct lttng_kernel_probe_location **location)
{
	int ret = 0;
	int match;
	char s_hex[19];
	char name[LTTNG_SYMBOL_NAME_LEN];
	char *symbol_name = nullptr;
	uint64_t offset;

	/* Check for symbol+offset. */
	match = sscanf(
		source, "%" LTTNG_SYMBOL_NAME_LEN_SCANF_IS_A_BROKEN_API "[^'+']+%18s", name, s_hex);
	if (match == 2) {
		if (*s_hex == '\0') {
			ERR("Kernel probe symbol offset is missing.");
			goto error;
		}

		symbol_name = strndup(name, LTTNG_SYMBOL_NAME_LEN);
		if (!symbol_name) {
			PERROR("Failed to copy kernel probe location symbol name.");
			goto error;
		}
		offset = strtoull(s_hex, nullptr, 0);

		*location = lttng_kernel_probe_location_symbol_create(symbol_name, offset);
		if (!*location) {
			ERR("Failed to create symbol kernel probe location.");
			goto error;
		}

		goto end;
	}

	/* Check for symbol. */
	if (isalpha(name[0]) || name[0] == '_') {
		match = sscanf(source, "%" LTTNG_SYMBOL_NAME_LEN_SCANF_IS_A_BROKEN_API "s", name);
		if (match == 1) {
			symbol_name = strndup(name, LTTNG_SYMBOL_NAME_LEN);
			if (!symbol_name) {
				ERR("Failed to copy kernel probe location symbol name.");
				goto error;
			}

			*location = lttng_kernel_probe_location_symbol_create(symbol_name, 0);
			if (!*location) {
				ERR("Failed to create symbol kernel probe location.");
				goto error;
			}

			goto end;
		}
	}

	/* Check for address. */
	match = sscanf(source, "%18s", s_hex);
	if (match > 0) {
		uint64_t address;

		if (*s_hex == '\0') {
			ERR("Invalid kernel probe location address.");
			goto error;
		}

		address = strtoull(s_hex, nullptr, 0);
		*location = lttng_kernel_probe_location_address_create(address);
		if (!*location) {
			ERR("Failed to create symbol kernel probe location.");
			goto error;
		}

		goto end;
	}

error:
	/* No match */
	ret = -1;
	*location = nullptr;

end:
	free(symbol_name);
	return ret;
}

static struct lttng_event_expr *
ir_op_load_expr_to_event_expr(const struct ir_load_expression *load_expr, const char *capture_str)
{
	char *provider_name = nullptr;
	struct lttng_event_expr *event_expr = nullptr;
	const struct ir_load_expression_op *load_expr_op = load_expr->child;
	const enum ir_load_expression_type load_expr_child_type = load_expr_op->type;

	switch (load_expr_child_type) {
	case IR_LOAD_EXPRESSION_GET_PAYLOAD_ROOT:
	case IR_LOAD_EXPRESSION_GET_CONTEXT_ROOT:
	{
		const char *field_name;

		load_expr_op = load_expr_op->next;
		LTTNG_ASSERT(load_expr_op);
		LTTNG_ASSERT(load_expr_op->type == IR_LOAD_EXPRESSION_GET_SYMBOL);
		field_name = load_expr_op->u.symbol;
		LTTNG_ASSERT(field_name);

		event_expr = load_expr_child_type == IR_LOAD_EXPRESSION_GET_PAYLOAD_ROOT ?
			lttng_event_expr_event_payload_field_create(field_name) :
			lttng_event_expr_channel_context_field_create(field_name);
		if (!event_expr) {
			ERR("Failed to create %s event expression: field name = `%s`.",
			    load_expr_child_type == IR_LOAD_EXPRESSION_GET_PAYLOAD_ROOT ?
				    "payload field" :
				    "channel context",
			    field_name);
			goto error;
		}

		break;
	}
	case IR_LOAD_EXPRESSION_GET_APP_CONTEXT_ROOT:
	{
		const char *colon;
		const char *type_name;
		const char *field_name;

		load_expr_op = load_expr_op->next;
		LTTNG_ASSERT(load_expr_op);
		LTTNG_ASSERT(load_expr_op->type == IR_LOAD_EXPRESSION_GET_SYMBOL);
		field_name = load_expr_op->u.symbol;
		LTTNG_ASSERT(field_name);

		/*
		 * The field name needs to be of the form PROVIDER:TYPE. We
		 * split it here.
		 */
		colon = strchr(field_name, ':');
		if (!colon) {
			ERR("Invalid app-specific context field name: missing colon in `%s`.",
			    field_name);
			goto error;
		}

		type_name = colon + 1;
		if (*type_name == '\0') {
			ERR("Invalid app-specific context field name: missing type name after colon in `%s`.",
			    field_name);
			goto error;
		}

		provider_name = strndup(field_name, colon - field_name);
		if (!provider_name) {
			PERROR("Failed to allocate field name string");
			goto error;
		}

		event_expr = lttng_event_expr_app_specific_context_field_create(provider_name,
										type_name);
		if (!event_expr) {
			ERR("Failed to create app-specific context field event expression: provider name = `%s`, type name = `%s`",
			    provider_name,
			    type_name);
			goto error;
		}

		break;
	}
	default:
		ERR("%s: unexpected load expr type %d.", __func__, load_expr_op->type);
		abort();
	}

	load_expr_op = load_expr_op->next;

	/* There may be a single array index after that. */
	if (load_expr_op->type == IR_LOAD_EXPRESSION_GET_INDEX) {
		struct lttng_event_expr *index_event_expr;
		const uint64_t index = load_expr_op->u.index;

		index_event_expr = lttng_event_expr_array_field_element_create(event_expr, index);
		if (!index_event_expr) {
			ERR("Failed to create array field element event expression.");
			goto error;
		}

		event_expr = index_event_expr;
		load_expr_op = load_expr_op->next;
	}

	switch (load_expr_op->type) {
	case IR_LOAD_EXPRESSION_LOAD_FIELD:
		/*
		 * This is what we expect, IR_LOAD_EXPRESSION_LOAD_FIELD is
		 * always found at the end of the chain.
		 */
		break;
	case IR_LOAD_EXPRESSION_GET_SYMBOL:
		ERR("While parsing expression `%s`: Capturing subfields is not supported.",
		    capture_str);
		goto error;

	default:
		ERR("%s: unexpected load expression operator %s.",
		    __func__,
		    ir_load_expression_type_str(load_expr_op->type));
		abort();
	}

	goto end;

error:
	lttng_event_expr_destroy(event_expr);
	event_expr = nullptr;

end:
	free(provider_name);

	return event_expr;
}

static struct lttng_event_expr *ir_op_load_to_event_expr(const struct ir_op *ir,
							 const char *capture_str)
{
	struct lttng_event_expr *event_expr = nullptr;

	LTTNG_ASSERT(ir->op == IR_OP_LOAD);

	switch (ir->data_type) {
	case IR_DATA_EXPRESSION:
	{
		const struct ir_load_expression *ir_load_expr = ir->u.load.u.expression;

		event_expr = ir_op_load_expr_to_event_expr(ir_load_expr, capture_str);
		break;
	}
	default:
		ERR("%s: unexpected data type: %s.", __func__, ir_data_type_str(ir->data_type));
		abort();
	}

	return event_expr;
}

static const char *ir_operator_type_human_str(enum ir_op_type op)
{
	const char *name;

	switch (op) {
	case IR_OP_BINARY:
		name = "Binary";
		break;
	case IR_OP_UNARY:
		name = "Unary";
		break;
	case IR_OP_LOGICAL:
		name = "Logical";
		break;
	default:
		abort();
	}

	return name;
}

static struct lttng_event_expr *ir_op_root_to_event_expr(const struct ir_op *ir,
							 const char *capture_str)
{
	struct lttng_event_expr *event_expr = nullptr;

	LTTNG_ASSERT(ir->op == IR_OP_ROOT);
	ir = ir->u.root.child;

	switch (ir->op) {
	case IR_OP_LOAD:
		event_expr = ir_op_load_to_event_expr(ir, capture_str);
		break;
	case IR_OP_BINARY:
	case IR_OP_UNARY:
	case IR_OP_LOGICAL:
		ERR("While parsing expression `%s`: %s operators are not allowed in capture expressions.",
		    capture_str,
		    ir_operator_type_human_str(ir->op));
		break;
	default:
		ERR("%s: unexpected IR op type: %s.", __func__, ir_op_type_str(ir->op));
		abort();
	}

	return event_expr;
}

static void destroy_event_expr(void *ptr)
{
	lttng_event_expr_destroy((lttng_event_expr *) ptr);
}

namespace {
struct parse_event_rule_res {
	/* Owned by this. */
	struct lttng_event_rule *er;

	/* Array of `struct lttng_event_expr *` */
	struct lttng_dynamic_pointer_array capture_descriptors;
};
struct parse_session_consumed_size_res {
	bool success = false;
	std::string session_name;
	uint64_t threshold_size_bytes = 0;
};
struct parse_buffer_usage_res {
	bool success = false;
	std::string session_name;
	std::string channel_name;
	enum lttng_domain_type domain_type = LTTNG_DOMAIN_NONE;
	double threshold_ratio = 0.0;
	uint64_t threshold_bytes = 0;
	bool is_threshold_bytes = false;
};
struct parse_session_rotation_res {
	bool success;
	std::string session_name;
};
} /* namespace */

static struct parse_buffer_usage_res
parse_buffer_usage(int *argc, const char ***argv, int argc_offset, const char *condition_cli_name)
{
	bool error = false, has_threshold_bytes = false, has_threshold_ratio = false;
	parse_buffer_usage_res res;
	std::string prefix;
	auto argpar_iter = lttng::make_unique_wrapper<struct argpar_iter, argpar_iter_destroy>(
		argpar_iter_create(*argc, *argv, buffer_usage_opt_descriptions));
	auto argpar_item =
		lttng::make_unique_wrapper<const struct argpar_item, argpar_item_destroy>(
			(const struct argpar_item *) nullptr);

	try {
		prefix = fmt::format("While parsing condition `{}`: ", condition_cli_name);
	} catch (const std::exception& e) {
		ERR_FMT("Failed to format prefix string for `{}`: {}",
			condition_cli_name,
			e.what());
		return res;
	}

	if (!argpar_iter) {
		ERR_FMT("{}failed to create argpar-iter", prefix);
		return res;
	}

	while (true) {
		const struct argpar_item *temp = nullptr;
		parse_next_item_status status = parse_next_item(
			argpar_iter.get(), &temp, argc_offset, *argv, false, nullptr, nullptr);

		argpar_item.reset(temp);
		if (status == PARSE_NEXT_ITEM_STATUS_ERROR ||
		    status == PARSE_NEXT_ITEM_STATUS_ERROR_MEMORY) {
			error = true;
			ERR_FMT("{}parse_next_item error {}", prefix, status);
			break;
		} else if (status == PARSE_NEXT_ITEM_STATUS_END) {
			break;
		}

		LTTNG_ASSERT(status == PARSE_NEXT_ITEM_STATUS_OK);
		if (argpar_item_type(argpar_item.get()) == ARGPAR_ITEM_TYPE_OPT) {
			const auto *descr = argpar_item_opt_descr(argpar_item.get());
			const auto *arg = argpar_item_opt_arg(argpar_item.get());

			switch (descr->id) {
			case OPT_SESSION_NAME:
				try {
					res.session_name = arg;
				} catch (const std::exception& e) {
					error = true;
					ERR_FMT("{}Failed to assign session_name: {}",
						prefix,
						e.what());
				}

				break;
			case OPT_CHANNEL_NAME:
				try {
					res.channel_name = arg;
				} catch (const std::exception& e) {
					error = true;
					ERR_FMT("{}Failed to assign channel_name: {}",
						prefix,
						e.what());
				}

				break;
			case OPT_DOMAIN:
			case OPT_DOMAIN_UST:
			case OPT_DOMAIN_KERNEL:
				if (res.domain_type != LTTNG_DOMAIN_NONE) {
					error = true;
					ERR_FMT("{}domain type already set. Only one of `-d/--domain`, `-u/--userspace`, and `-k/--kernel` may be given.",
						prefix);
					break;
				}

				if (descr->id == OPT_DOMAIN_UST) {
					res.domain_type = LTTNG_DOMAIN_UST;
				} else if (descr->id == OPT_DOMAIN_KERNEL) {
					res.domain_type = LTTNG_DOMAIN_KERNEL;
				} else {
					if (lttng_domain_type_parse(arg, &res.domain_type) !=
					    LTTNG_OK) {
						error = true;
						res.domain_type = LTTNG_DOMAIN_NONE;
						ERR_FMT("{}Unable to parse `{}` into LTTng domain type",
							prefix,
							arg);
						break;
					}
				}

				break;
			case OPT_THRESHOLD_SIZE:
				if (has_threshold_ratio || has_threshold_bytes) {
					error = true;
					ERR_FMT("{}only one of `-r/--threshold-ratio` and `-t/--threshold-size` may be given",
						prefix);
					break;
				}

				if (utils_parse_size_suffix(arg, &res.threshold_bytes) < 0) {
					error = true;
					ERR_FMT("{}wrong value in `-t/--threshold-size` parameter: `{}`",
						prefix,
						arg);
					break;
				}

				res.is_threshold_bytes = true;
				has_threshold_bytes = true;
				break;
			case OPT_THRESHOLD_RATIO:
				if (has_threshold_ratio or has_threshold_bytes) {
					error = true;
					ERR_FMT("{}only one of `-r/--threshold-ratio` and `-t/--threshold-size` may be given",
						prefix);
					break;
				}

				try {
					res.threshold_ratio = std::stod(arg);
				} catch (const std::exception& e) {
					error = true;
					ERR_FMT("Failed to convert `{}` to double: {}",
						arg,
						e.what());
					break;
				}

				has_threshold_ratio = true;
				res.is_threshold_bytes = false;
				break;
			default:
				abort();
			}
		} else {
			const auto *arg = argpar_item_non_opt_arg(argpar_item.get());
			error = true;
			ERR_FMT("{}unexpected argument '{}'", prefix, arg);
			break;
		}
	}

	const auto consumed_args = argpar_iter_ingested_orig_args(argpar_iter.get());
	LTTNG_ASSERT(consumed_args >= 0);
	*argc -= consumed_args;
	*argv += consumed_args;
	if (res.session_name.empty()) {
		error = true;
		ERR_FMT("{}`-s/--session` is required", prefix);
	}

	if (res.channel_name.empty()) {
		error = true;
		ERR_FMT("{}`-c/--channel` is required", prefix);
	}

	if (res.domain_type == LTTNG_DOMAIN_NONE) {
		error = true;
		ERR_FMT("{}One of `-u/--userspace`, `-k/--kernel`, or `-d/--domain` must be given",
			prefix);
	}

	if (!has_threshold_ratio && !has_threshold_bytes) {
		error = true;
		ERR_FMT("{}One of `-r/--threshold-ratio` or `-t/--threshold-size` is required",
			prefix);
	}

	res.success = !error;
	return res;
}

static struct lttng_condition *
_handle_condition_buffer_usage(int *argc,
			       const char ***argv,
			       int argc_offset,
			       enum lttng_condition_type condition_type,
			       const char *condition_cli_name)
{
	enum lttng_condition_status status;
	const auto result = parse_buffer_usage(argc, argv, argc_offset, condition_cli_name);
	if (!result.success) {
		ERR("Failed to parse buffer-usage arguments");
		return nullptr;
	}

	auto condition = [condition_type]() {
		struct lttng_condition *raw_condition = nullptr;
		switch (condition_type) {
		case LTTNG_CONDITION_TYPE_BUFFER_USAGE_LOW:
			raw_condition = lttng_condition_buffer_usage_low_create();
			break;
		case LTTNG_CONDITION_TYPE_BUFFER_USAGE_HIGH:
			raw_condition = lttng_condition_buffer_usage_high_create();
			break;
		default:
			break;
		}

		return lttng::make_unique_wrapper<struct lttng_condition, lttng_condition_destroy>(
			raw_condition);
	}();
	if (!condition) {
		ERR("Failed to create lttng_condition");
		return nullptr;
	}

	if (result.is_threshold_bytes) {
		status = lttng_condition_buffer_usage_set_threshold(condition.get(),
								    result.threshold_bytes);
		if (status != LTTNG_CONDITION_STATUS_OK) {
			ERR_FMT("Failed to set buffer-usage condition threshold bytes: {}", status);
			return nullptr;
		}
	} else {
		status = lttng_condition_buffer_usage_set_threshold_ratio(condition.get(),
									  result.threshold_ratio);
		if (status != LTTNG_CONDITION_STATUS_OK) {
			ERR_FMT("Failed to set buffer-usage condition threshold ratio: {}", status);
			return nullptr;
		}
	}

	status = lttng_condition_buffer_usage_set_session_name(condition.get(),
							       result.session_name.c_str());
	if (status != LTTNG_CONDITION_STATUS_OK) {
		ERR_FMT("Failed to set buffer-usage condition session name: {}", status);
		return nullptr;
	}

	status = lttng_condition_buffer_usage_set_channel_name(condition.get(),
							       result.channel_name.c_str());
	if (status != LTTNG_CONDITION_STATUS_OK) {
		ERR_FMT("Failed to set buffer-usage condition channel name: {}", status);
		return nullptr;
	}

	status = lttng_condition_buffer_usage_set_domain_type(condition.get(), result.domain_type);
	if (status != LTTNG_CONDITION_STATUS_OK) {
		ERR_FMT("Failed to set buffer-usage condition domain type: {}", status);
		return nullptr;
	}

	if (!lttng_condition_validate(condition.get())) {
		ERR("Failed to validate condition");
		return nullptr;
	}

	return condition.release();
}

static struct lttng_condition *
handle_condition_buffer_usage_ge(int *argc, const char ***argv, int argc_offset)
{
	return _handle_condition_buffer_usage(argc,
					      argv,
					      argc_offset,
					      LTTNG_CONDITION_TYPE_BUFFER_USAGE_HIGH,
					      "condition-buffer-usage-ge");
}

static struct lttng_condition *
handle_condition_buffer_usage_le(int *argc, const char ***argv, int argc_offset)
{
	return _handle_condition_buffer_usage(argc,
					      argv,
					      argc_offset,
					      LTTNG_CONDITION_TYPE_BUFFER_USAGE_LOW,
					      "condition-buffer-usage-le");
}

static struct parse_event_rule_res parse_event_rule(int *argc, const char ***argv, int argc_offset)
{
	enum lttng_event_rule_type event_rule_type = LTTNG_EVENT_RULE_TYPE_UNKNOWN;
	struct argpar_iter *argpar_iter = nullptr;
	const struct argpar_item *argpar_item = nullptr;
	int consumed_args = -1;
	struct lttng_kernel_probe_location *kernel_probe_location = nullptr;
	struct lttng_userspace_probe_location *userspace_probe_location = nullptr;
	struct parse_event_rule_res res = {};
	struct lttng_event_expr *event_expr = nullptr;
	struct filter_parser_ctx *parser_ctx = nullptr;
	struct lttng_log_level_rule *log_level_rule = nullptr;

	/* Event rule type option */
	char *event_rule_type_str = nullptr;

	/* Tracepoint and syscall options. */
	char *name = nullptr;
	/* Array of strings. */
	struct lttng_dynamic_pointer_array exclude_names;

	/* For userspace / kernel probe and function. */
	char *location = nullptr;
	char *event_name = nullptr;

	/* Filter. */
	char *filter = nullptr;

	/* Log level. */
	char *log_level_str = nullptr;

	lttng_dynamic_pointer_array_init(&res.capture_descriptors, destroy_event_expr);

	lttng_dynamic_pointer_array_init(&exclude_names, free);

	argpar_iter = argpar_iter_create(*argc, *argv, event_rule_opt_descrs);
	if (!argpar_iter) {
		ERR("Failed to allocate an argpar iter.");
		goto error;
	}

	while (true) {
		enum parse_next_item_status status;

		status = parse_next_item(
			argpar_iter, &argpar_item, argc_offset, *argv, false, nullptr, nullptr);
		if (status == PARSE_NEXT_ITEM_STATUS_ERROR ||
		    status == PARSE_NEXT_ITEM_STATUS_ERROR_MEMORY) {
			goto error;
		} else if (status == PARSE_NEXT_ITEM_STATUS_END) {
			break;
		}

		LTTNG_ASSERT(status == PARSE_NEXT_ITEM_STATUS_OK);

		if (argpar_item_type(argpar_item) == ARGPAR_ITEM_TYPE_OPT) {
			const struct argpar_opt_descr *descr = argpar_item_opt_descr(argpar_item);
			const char *arg = argpar_item_opt_arg(argpar_item);

			switch (descr->id) {
			case OPT_TYPE:
				if (!assign_event_rule_type(&event_rule_type, arg)) {
					goto error;
				}

				/* Save the string for later use. */
				if (!assign_string(&event_rule_type_str, arg, "--type/-t")) {
					goto error;
				}

				break;
			case OPT_LOCATION:
				if (!assign_string(&location, arg, "--location/-L")) {
					goto error;
				}

				break;
			case OPT_EVENT_NAME:
				if (!assign_string(&event_name, arg, "--event-name/-E")) {
					goto error;
				}

				break;
			case OPT_FILTER:
				if (!assign_string(&filter, arg, "--filter/-f")) {
					goto error;
				}

				break;
			case OPT_NAME:
				if (!assign_string(&name, arg, "--name/-n")) {
					goto error;
				}

				break;
			case OPT_EXCLUDE_NAME:
			{
				int ret;

				ret = lttng_dynamic_pointer_array_add_pointer(&exclude_names,
									      strdup(arg));
				if (ret != 0) {
					ERR("Failed to add pointer to dynamic pointer array.");
					goto error;
				}

				break;
			}
			case OPT_LOG_LEVEL:
				if (!assign_string(&log_level_str, arg, "--log-level/-l")) {
					goto error;
				}

				break;
			case OPT_CAPTURE:
			{
				int ret;

				ret = filter_parser_ctx_create_from_filter_expression(arg,
										      &parser_ctx);
				if (ret) {
					ERR("Failed to parse capture expression `%s`.", arg);
					goto error;
				}

				event_expr = ir_op_root_to_event_expr(parser_ctx->ir_root, arg);
				filter_parser_ctx_free(parser_ctx);
				parser_ctx = nullptr;
				if (!event_expr) {
					/*
					 * ir_op_root_to_event_expr has printed
					 * an error message.
					 */
					goto error;
				}

				ret = lttng_dynamic_pointer_array_add_pointer(
					&res.capture_descriptors, event_expr);
				if (ret) {
					goto error;
				}

				/*
				 * The ownership of event expression was
				 * transferred to the dynamic array.
				 */
				event_expr = nullptr;

				break;
			}
			default:
				abort();
			}
		} else {
			const char *arg = argpar_item_non_opt_arg(argpar_item);

			/* Don't accept non-option arguments. */
			ERR("Unexpected argument '%s'", arg);
			goto error;
		}
	}

	if (event_rule_type == LTTNG_EVENT_RULE_TYPE_UNKNOWN) {
		ERR("Event rule requires a --type.");
		goto error;
	}

	/*
	 * Option --name is applicable to event rules of type kernel, user, jul,
	 * log4j, log4j2, python and syscall.  If --name is omitted, it is
	 * implicitly "*".
	 */
	switch (event_rule_type) {
	case LTTNG_EVENT_RULE_TYPE_USER_TRACEPOINT:
	case LTTNG_EVENT_RULE_TYPE_KERNEL_TRACEPOINT:
	case LTTNG_EVENT_RULE_TYPE_JUL_LOGGING:
	case LTTNG_EVENT_RULE_TYPE_LOG4J_LOGGING:
	case LTTNG_EVENT_RULE_TYPE_LOG4J2_LOGGING:
	case LTTNG_EVENT_RULE_TYPE_PYTHON_LOGGING:
	case LTTNG_EVENT_RULE_TYPE_KERNEL_SYSCALL:
		if (!name) {
			name = strdup("*");
		}
		break;

	default:
		if (name) {
			ERR("Can't use --name with %s event rules.",
			    lttng_event_rule_type_str(event_rule_type));
			goto error;
		}

		if (lttng_dynamic_pointer_array_get_count(&exclude_names) > 0) {
			ERR("Can't use --exclude-name/-x with %s event rules.",
			    lttng_event_rule_type_str(event_rule_type));
			goto error;
		}
	}

	/*
	 * Option --location is only applicable to (and mandatory for) event
	 * rules of type {k,u}probe and function.
	 *
	 * Option --event-name is only applicable to event rules of type probe.
	 * If omitted, it defaults to the location.
	 */
	switch (event_rule_type) {
	case LTTNG_EVENT_RULE_TYPE_KERNEL_KPROBE:
	case LTTNG_EVENT_RULE_TYPE_KERNEL_UPROBE:
		if (!location) {
			ERR("Event rule of type %s requires a --location.",
			    lttng_event_rule_type_str(event_rule_type));
			goto error;
		}

		if (!event_name) {
			event_name = strdup(location);
		}

		break;

	default:
		if (location) {
			ERR("Can't use --location with %s event rules.",
			    lttng_event_rule_type_str(event_rule_type));
			goto error;
		}

		if (event_name) {
			ERR("Can't use --event-name with %s event rules.",
			    lttng_event_rule_type_str(event_rule_type));
			goto error;
		}
	}

	/*
	 * Update *argc and *argv so our caller can keep parsing what follows.
	 */
	consumed_args = argpar_iter_ingested_orig_args(argpar_iter);
	LTTNG_ASSERT(consumed_args >= 0);
	*argc -= consumed_args;
	*argv += consumed_args;

	/*
	 * Adding a filter to a probe, function or userspace-probe would be
	 * denied by the kernel tracer as it's not supported at the moment. We
	 * do an early check here to warn the user.
	 */
	if (filter) {
		switch (event_rule_type) {
		case LTTNG_EVENT_RULE_TYPE_USER_TRACEPOINT:
		case LTTNG_EVENT_RULE_TYPE_KERNEL_TRACEPOINT:
		case LTTNG_EVENT_RULE_TYPE_JUL_LOGGING:
		case LTTNG_EVENT_RULE_TYPE_LOG4J_LOGGING:
		case LTTNG_EVENT_RULE_TYPE_LOG4J2_LOGGING:
		case LTTNG_EVENT_RULE_TYPE_PYTHON_LOGGING:
		case LTTNG_EVENT_RULE_TYPE_KERNEL_SYSCALL:
			break;
		default:
			ERR("Filter expressions are not supported for %s event rules.",
			    lttng_event_rule_type_str(event_rule_type));
			goto error;
		}
	}

	/*
	 * If --exclude-name/-x was passed, split it into an exclusion list.
	 * Exclusions are only supported by
	 * LTTNG_EVENT_RULE_TYPE_USER_TRACEPOINT for now.
	 */
	if (lttng_dynamic_pointer_array_get_count(&exclude_names) > 0) {
		if (event_rule_type != LTTNG_EVENT_RULE_TYPE_USER_TRACEPOINT) {
			ERR("Event name exclusions are not yet implemented for %s event rules.",
			    lttng_event_rule_type_str(event_rule_type));
			goto error;
		}

		if (validate_exclusion_list(name, &exclude_names) != 0) {
			/*
			 * Assume validate_exclusion_list already prints an
			 * error message.
			 */
			goto error;
		}
	}

	if (log_level_str) {
		switch (event_rule_type) {
		case LTTNG_EVENT_RULE_TYPE_USER_TRACEPOINT:
		case LTTNG_EVENT_RULE_TYPE_JUL_LOGGING:
		case LTTNG_EVENT_RULE_TYPE_LOG4J_LOGGING:
		case LTTNG_EVENT_RULE_TYPE_LOG4J2_LOGGING:
		case LTTNG_EVENT_RULE_TYPE_PYTHON_LOGGING:
		{
			int log_level;
			bool log_level_only;

			if (strcmp(log_level_str, "..") == 0) {
				/*
				 * ".." is the same as passing no log level
				 * option and correspond to the "ANY" case.
				 */
				break;
			}

			if (!parse_log_level_string(
				    log_level_str, event_rule_type, &log_level, &log_level_only)) {
				ERR("Failed to parse log level string `%s`.", log_level_str);
				goto error;
			}

			if (log_level_only) {
				log_level_rule = lttng_log_level_rule_exactly_create(log_level);
			} else {
				log_level_rule = lttng_log_level_rule_at_least_as_severe_as_create(
					log_level);
			}

			if (log_level_rule == nullptr) {
				ERR("Failed to create log level rule object.");
				goto error;
			}
			break;
		}
		default:
			ERR("Log levels are not supported for %s event rules.",
			    lttng_event_rule_type_str(event_rule_type));
			goto error;
		}
	}

	/* Finally, create the event rule object. */
	switch (event_rule_type) {
	case LTTNG_EVENT_RULE_TYPE_USER_TRACEPOINT:
	{
		enum lttng_event_rule_status event_rule_status;

		res.er = lttng_event_rule_user_tracepoint_create();
		if (!res.er) {
			ERR("Failed to create user_tracepoint event rule.");
			goto error;
		}

		/* Set pattern. */
		event_rule_status = lttng_event_rule_user_tracepoint_set_name_pattern(res.er, name);
		if (event_rule_status != LTTNG_EVENT_RULE_STATUS_OK) {
			ERR("Failed to set user_tracepoint event rule's pattern to '%s'.", name);
			goto error;
		}

		/* Set filter. */
		if (filter) {
			event_rule_status =
				lttng_event_rule_user_tracepoint_set_filter(res.er, filter);
			if (event_rule_status != LTTNG_EVENT_RULE_STATUS_OK) {
				ERR("Failed to set user_tracepoint event rule's filter to '%s'.",
				    filter);
				goto error;
			}
		}

		/* Set exclusion list. */
		if (lttng_dynamic_pointer_array_get_count(&exclude_names) > 0) {
			int n;
			const int count = lttng_dynamic_pointer_array_get_count(&exclude_names);

			for (n = 0; n < count; n++) {
				const char *exclude_name =
					(const char *) lttng_dynamic_pointer_array_get_pointer(
						&exclude_names, n);

				event_rule_status =
					lttng_event_rule_user_tracepoint_add_name_pattern_exclusion(
						res.er, exclude_name);
				if (event_rule_status != LTTNG_EVENT_RULE_STATUS_OK) {
					ERR("Failed to set user_tracepoint exclusion list element '%s'",
					    exclude_name);
					goto error;
				}
			}
		}

		if (log_level_rule) {
			event_rule_status = lttng_event_rule_user_tracepoint_set_log_level_rule(
				res.er, log_level_rule);

			if (event_rule_status != LTTNG_EVENT_RULE_STATUS_OK) {
				ERR("Failed to set log level on event fule.");
				goto error;
			}
		}

		break;
	}
	case LTTNG_EVENT_RULE_TYPE_KERNEL_TRACEPOINT:
	{
		enum lttng_event_rule_status event_rule_status;

		res.er = lttng_event_rule_kernel_tracepoint_create();
		if (!res.er) {
			ERR("Failed to create kernel_tracepoint event rule.");
			goto error;
		}

		/* Set pattern. */
		event_rule_status =
			lttng_event_rule_kernel_tracepoint_set_name_pattern(res.er, name);
		if (event_rule_status != LTTNG_EVENT_RULE_STATUS_OK) {
			ERR("Failed to set kernel_tracepoint event rule's pattern to '%s'.", name);
			goto error;
		}

		/* Set filter. */
		if (filter) {
			event_rule_status =
				lttng_event_rule_kernel_tracepoint_set_filter(res.er, filter);
			if (event_rule_status != LTTNG_EVENT_RULE_STATUS_OK) {
				ERR("Failed to set kernel_tracepoint event rule's filter to '%s'.",
				    filter);
				goto error;
			}
		}
		break;
	}
	case LTTNG_EVENT_RULE_TYPE_JUL_LOGGING:
	{
		enum lttng_event_rule_status event_rule_status;

		res.er = lttng_event_rule_jul_logging_create();
		if (!res.er) {
			ERR("Failed to create jul_logging event rule.");
			goto error;
		}

		/* Set pattern. */
		event_rule_status = lttng_event_rule_jul_logging_set_name_pattern(res.er, name);
		if (event_rule_status != LTTNG_EVENT_RULE_STATUS_OK) {
			ERR("Failed to set jul_logging event rule's pattern to '%s'.", name);
			goto error;
		}

		/* Set filter. */
		if (filter) {
			event_rule_status = lttng_event_rule_jul_logging_set_filter(res.er, filter);
			if (event_rule_status != LTTNG_EVENT_RULE_STATUS_OK) {
				ERR("Failed to set jul_logging event rule's filter to '%s'.",
				    filter);
				goto error;
			}
		}

		if (log_level_rule) {
			event_rule_status = lttng_event_rule_jul_logging_set_log_level_rule(
				res.er, log_level_rule);

			if (event_rule_status != LTTNG_EVENT_RULE_STATUS_OK) {
				ERR("Failed to set log level on event fule.");
				goto error;
			}
		}
		break;
	}
	case LTTNG_EVENT_RULE_TYPE_LOG4J_LOGGING:
	{
		enum lttng_event_rule_status event_rule_status;

		res.er = lttng_event_rule_log4j_logging_create();
		if (!res.er) {
			ERR("Failed to create jul_logging event rule.");
			goto error;
		}

		/* Set pattern. */
		event_rule_status = lttng_event_rule_log4j_logging_set_name_pattern(res.er, name);
		if (event_rule_status != LTTNG_EVENT_RULE_STATUS_OK) {
			ERR("Failed to set jul_logging event rule's pattern to '%s'.", name);
			goto error;
		}

		/* Set filter. */
		if (filter) {
			event_rule_status =
				lttng_event_rule_log4j_logging_set_filter(res.er, filter);
			if (event_rule_status != LTTNG_EVENT_RULE_STATUS_OK) {
				ERR("Failed to set jul_logging event rule's filter to '%s'.",
				    filter);
				goto error;
			}
		}

		if (log_level_rule) {
			event_rule_status = lttng_event_rule_log4j_logging_set_log_level_rule(
				res.er, log_level_rule);

			if (event_rule_status != LTTNG_EVENT_RULE_STATUS_OK) {
				ERR("Failed to set log level on event fule.");
				goto error;
			}
		}
		break;
	}
	case LTTNG_EVENT_RULE_TYPE_LOG4J2_LOGGING:
	{
		enum lttng_event_rule_status event_rule_status;

		res.er = lttng_event_rule_log4j2_logging_create();
		if (!res.er) {
			ERR("Failed to create log4j2_logging event rule.");
			goto error;
		}

		/* Set pattern. */
		event_rule_status = lttng_event_rule_log4j2_logging_set_name_pattern(res.er, name);
		if (event_rule_status != LTTNG_EVENT_RULE_STATUS_OK) {
			ERR("Failed to set log4j2_logging event rule's pattern to '%s'.", name);
			goto error;
		}

		/* Set filter. */
		if (filter) {
			event_rule_status =
				lttng_event_rule_log4j2_logging_set_filter(res.er, filter);
			if (event_rule_status != LTTNG_EVENT_RULE_STATUS_OK) {
				ERR("Failed to set log4j2_logging event rule's filter to '%s'.",
				    filter);
				goto error;
			}
		}

		if (log_level_rule) {
			event_rule_status = lttng_event_rule_log4j2_logging_set_log_level_rule(
				res.er, log_level_rule);

			if (event_rule_status != LTTNG_EVENT_RULE_STATUS_OK) {
				ERR("Failed to set log level on event fule.");
				goto error;
			}
		}
		break;
	}
	case LTTNG_EVENT_RULE_TYPE_PYTHON_LOGGING:
	{
		enum lttng_event_rule_status event_rule_status;

		res.er = lttng_event_rule_python_logging_create();
		if (!res.er) {
			ERR("Failed to create jul_logging event rule.");
			goto error;
		}

		/* Set pattern. */
		event_rule_status = lttng_event_rule_python_logging_set_name_pattern(res.er, name);
		if (event_rule_status != LTTNG_EVENT_RULE_STATUS_OK) {
			ERR("Failed to set jul_logging event rule's pattern to '%s'.", name);
			goto error;
		}

		/* Set filter. */
		if (filter) {
			event_rule_status =
				lttng_event_rule_python_logging_set_filter(res.er, filter);
			if (event_rule_status != LTTNG_EVENT_RULE_STATUS_OK) {
				ERR("Failed to set jul_logging event rule's filter to '%s'.",
				    filter);
				goto error;
			}
		}

		if (log_level_rule) {
			event_rule_status = lttng_event_rule_python_logging_set_log_level_rule(
				res.er, log_level_rule);

			if (event_rule_status != LTTNG_EVENT_RULE_STATUS_OK) {
				ERR("Failed to set log level on event fule.");
				goto error;
			}
		}
		break;
	}
	case LTTNG_EVENT_RULE_TYPE_KERNEL_KPROBE:
	{
		int ret;
		enum lttng_event_rule_status event_rule_status;

		ret = parse_kernel_probe_opts(location, &kernel_probe_location);
		if (ret) {
			ERR("Failed to parse kernel probe location.");
			goto error;
		}

		LTTNG_ASSERT(kernel_probe_location);
		res.er = lttng_event_rule_kernel_kprobe_create(kernel_probe_location);
		if (!res.er) {
			ERR("Failed to create kprobe event rule.");
			goto error;
		}

		event_rule_status =
			lttng_event_rule_kernel_kprobe_set_event_name(res.er, event_name);
		if (event_rule_status != LTTNG_EVENT_RULE_STATUS_OK) {
			ERR("Failed to set kprobe event rule's name to '%s'.", event_name);
			goto error;
		}

		break;
	}
	case LTTNG_EVENT_RULE_TYPE_KERNEL_UPROBE:
	{
		int ret;
		enum lttng_event_rule_status event_rule_status;

		ret = parse_userspace_probe_opts(location, &userspace_probe_location);
		if (ret) {
			ERR("Failed to parse user space probe location.");
			goto error;
		}

		res.er = lttng_event_rule_kernel_uprobe_create(userspace_probe_location);
		if (!res.er) {
			ERR("Failed to create userspace probe event rule.");
			goto error;
		}

		event_rule_status =
			lttng_event_rule_kernel_uprobe_set_event_name(res.er, event_name);
		if (event_rule_status != LTTNG_EVENT_RULE_STATUS_OK) {
			ERR("Failed to set user space probe event rule's name to '%s'.",
			    event_name);
			goto error;
		}

		break;
	}
	case LTTNG_EVENT_RULE_TYPE_KERNEL_SYSCALL:
	{
		enum lttng_event_rule_status event_rule_status;
		enum lttng_event_rule_kernel_syscall_emission_site emission_site;

		if (!parse_syscall_emission_site_from_type(event_rule_type_str, &emission_site)) {
			ERR("Failed to parse syscall type '%s'.", event_rule_type_str);
			goto error;
		}

		res.er = lttng_event_rule_kernel_syscall_create(emission_site);
		if (!res.er) {
			ERR("Failed to create syscall event rule.");
			goto error;
		}

		event_rule_status = lttng_event_rule_kernel_syscall_set_name_pattern(res.er, name);
		if (event_rule_status != LTTNG_EVENT_RULE_STATUS_OK) {
			ERR("Failed to set syscall event rule's pattern to '%s'.", name);
			goto error;
		}

		if (filter) {
			event_rule_status =
				lttng_event_rule_kernel_syscall_set_filter(res.er, filter);
			if (event_rule_status != LTTNG_EVENT_RULE_STATUS_OK) {
				ERR("Failed to set syscall event rule's filter to '%s'.", filter);
				goto error;
			}
		}

		break;
	}
	default:
		abort();
		goto error;
	}

	goto end;

error:
	lttng_event_rule_destroy(res.er);
	res.er = nullptr;
	lttng_dynamic_pointer_array_reset(&res.capture_descriptors);

end:
	if (parser_ctx) {
		filter_parser_ctx_free(parser_ctx);
	}

	lttng_event_expr_destroy(event_expr);
	argpar_item_destroy(argpar_item);
	argpar_iter_destroy(argpar_iter);
	free(filter);
	free(name);
	lttng_dynamic_pointer_array_reset(&exclude_names);
	free(log_level_str);
	free(location);
	free(event_name);
	free(event_rule_type_str);

	lttng_kernel_probe_location_destroy(kernel_probe_location);
	lttng_userspace_probe_location_destroy(userspace_probe_location);
	lttng_log_level_rule_destroy(log_level_rule);
	return res;
}

static struct lttng_condition *
handle_condition_event(int *argc, const char ***argv, int argc_offset)
{
	struct parse_event_rule_res res;
	struct lttng_condition *c;
	size_t i;

	res = parse_event_rule(argc, argv, argc_offset);
	if (!res.er) {
		c = nullptr;
		goto error;
	}

	c = lttng_condition_event_rule_matches_create(res.er);
	lttng_event_rule_destroy(res.er);
	res.er = nullptr;
	if (!c) {
		goto error;
	}

	for (i = 0; i < lttng_dynamic_pointer_array_get_count(&res.capture_descriptors); i++) {
		enum lttng_condition_status status;
		struct lttng_event_expr **expr =
			(lttng_event_expr **) lttng_dynamic_array_get_element(
				&res.capture_descriptors.array, i);

		LTTNG_ASSERT(expr);
		LTTNG_ASSERT(*expr);
		status = lttng_condition_event_rule_matches_append_capture_descriptor(c, *expr);
		if (status != LTTNG_CONDITION_STATUS_OK) {
			if (status == LTTNG_CONDITION_STATUS_UNSUPPORTED) {
				ERR("The capture feature is unsupported by the event-rule condition type");
			}

			goto error;
		}

		/* Ownership of event expression moved to `c` */
		*expr = nullptr;
	}

	goto end;

error:
	lttng_condition_destroy(c);
	c = nullptr;

end:
	lttng_dynamic_pointer_array_reset(&res.capture_descriptors);
	lttng_event_rule_destroy(res.er);
	return c;
}

static struct parse_session_consumed_size_res
parse_session_consumed_size(int *argc, const char ***argv, int argc_offset)
{
	const char *prefix = "While parsing condition `session-consumed-size-ge`: ";
	bool has_session_name = false, has_threshold_size = false;
	struct parse_session_consumed_size_res res;
	auto argpar_iter = lttng::make_unique_wrapper<struct argpar_iter, argpar_iter_destroy>(
		argpar_iter_create(*argc, *argv, session_consumed_size_opt_descriptions));
	auto argpar_item =
		lttng::make_unique_wrapper<const struct argpar_item, argpar_item_destroy>(
			(const struct argpar_item *) nullptr);

	if (!argpar_iter) {
		ERR_FMT("{}failed to create argpar_iter", prefix);
		return res;
	}

	while (true) {
		const struct argpar_item *temp = nullptr;

		const auto status = parse_next_item(
			argpar_iter.get(), &temp, argc_offset, *argv, false, nullptr, nullptr);
		argpar_item.reset(temp);
		if (status == PARSE_NEXT_ITEM_STATUS_ERROR ||
		    status == PARSE_NEXT_ITEM_STATUS_ERROR_MEMORY) {
			ERR_FMT("{}parse_next_item error {}", prefix, status);
			break;
		} else if (status == PARSE_NEXT_ITEM_STATUS_END) {
			break;
		}

		LTTNG_ASSERT(status == PARSE_NEXT_ITEM_STATUS_OK);
		if (argpar_item_type(argpar_item.get()) == ARGPAR_ITEM_TYPE_OPT) {
			const struct argpar_opt_descr *descr =
				argpar_item_opt_descr(argpar_item.get());
			const char *arg = argpar_item_opt_arg(argpar_item.get());

			switch (descr->id) {
			case OPT_SESSION_NAME:
				try {
					res.session_name = arg;
				} catch (const std::bad_alloc&) {
					ERR_FMT("{}failed to allocate memory for session name",
						prefix);
					break;
				}

				has_session_name = true;
				break;
			case OPT_THRESHOLD_SIZE:
				if (utils_parse_size_suffix(arg, &res.threshold_size_bytes) < 0) {
					ERR_FMT("{}wrong value in `-t/--threshold-size` parameter: `{}`",
						prefix,
						arg);
				} else {
					has_threshold_size = true;
				}
				break;
			default:
				abort();
			}
		} else {
			const char *arg = argpar_item_non_opt_arg(argpar_item.get());
			ERR_FMT("{}unexpected argument `{}`", prefix, arg);
			break;
		}
	}

	const auto consumed_args = argpar_iter_ingested_orig_args(argpar_iter.get());
	LTTNG_ASSERT(consumed_args >= 0);
	*argc -= consumed_args;
	*argv += consumed_args;
	res.success = has_threshold_size && has_session_name;
	if (!has_threshold_size) {
		ERR_FMT("{}Missing or invalid argument for `-t/--threshold-size`", prefix);
	}

	if (!has_session_name) {
		ERR_FMT("{}Missing or invalid argument for `-s/--session`", prefix);
	}

	return res;
}

static lttng_condition *
handle_condition_session_consumed_size(int *argc, const char ***argv, int argc_offset)
{
	auto condition = []() {
		lttng_condition *raw_condition = lttng_condition_session_consumed_size_create();

		return lttng::make_unique_wrapper<lttng_condition, lttng_condition_destroy>(
			raw_condition);
	}();

	if (!condition || !condition.get()) {
		ERR("Failed to create lttng_condition structure");
		return nullptr;
	}

	auto result = parse_session_consumed_size(argc, argv, argc_offset);
	if (!result.success) {
		ERR("Failed to parse session-consumed-size-ge arguments");
		return nullptr;
	}

	auto status = lttng_condition_session_consumed_size_set_session_name(
		condition.get(), result.session_name.c_str());
	if (status != LTTNG_CONDITION_STATUS_OK) {
		ERR_FMT("Failed to set condition's session name: {}", status);
		return nullptr;
	}

	status = lttng_condition_session_consumed_size_set_threshold(condition.get(),
								     result.threshold_size_bytes);
	if (status != LTTNG_CONDITION_STATUS_OK) {
		ERR_FMT("Failed to set condition's threshold: {}", status);
		return nullptr;
	}

	if (!lttng_condition_validate(condition.get())) {
		ERR("Failed to validate condition");
		return nullptr;
	}

	return condition.release();
}

static struct parse_session_rotation_res parse_session_rotation(int *argc,
								const char ***argv,
								int argc_offset,
								const char *condition_cli_name)
{
	parse_session_rotation_res res;
	bool error = false;
	std::string prefix;
	auto argpar_iter = lttng::make_unique_wrapper<struct argpar_iter, argpar_iter_destroy>(
		argpar_iter_create(*argc, *argv, session_rotation_opt_descriptions));
	auto argpar_item =
		lttng::make_unique_wrapper<const struct argpar_item, argpar_item_destroy>(
			(const struct argpar_item *) nullptr);

	try {
		prefix = fmt::format("While parsing condition `{}`: ", condition_cli_name);
	} catch (const std::bad_alloc&) {
		ERR_FMT("Failed to allocate memory for prefix string for `{}`", condition_cli_name);
		return res;
	}

	if (!argpar_iter) {
		ERR_FMT("{}failed to create argpar-iter", prefix);
		return res;
	}

	while (true) {
		const struct argpar_item *temp = nullptr;
		auto status = parse_next_item(
			argpar_iter.get(), &temp, argc_offset, *argv, false, nullptr, nullptr);

		argpar_item.reset(temp);
		if (status == PARSE_NEXT_ITEM_STATUS_ERROR ||
		    status == PARSE_NEXT_ITEM_STATUS_ERROR_MEMORY) {
			error = true;
			ERR_FMT("{}parse_next_item error {}", prefix, status);
			break;
		} else if (status == PARSE_NEXT_ITEM_STATUS_END) {
			break;
		}

		LTTNG_ASSERT(status == PARSE_NEXT_ITEM_STATUS_OK);
		if (argpar_item_type(argpar_item.get()) == ARGPAR_ITEM_TYPE_OPT) {
			const struct argpar_opt_descr *descr =
				argpar_item_opt_descr(argpar_item.get());
			const char *arg = argpar_item_opt_arg(argpar_item.get());

			switch (descr->id) {
			case OPT_SESSION_NAME:
				try {
					res.session_name = arg;
				} catch (const std::exception& e) {
					error = true;
					ERR_FMT("{}Failed to assign session name: {}",
						prefix,
						e.what());
				}

				break;
			default:
				ERR_FMT("Unknown description id: {}, arg `{}`",
					(int) descr->id,
					arg);
				abort();
			}
		} else {
			const auto *arg = argpar_item_non_opt_arg(argpar_item.get());
			error = true;
			ERR_FMT("{}unexpected argument `{}`", prefix, arg);
			break;
		}
	}

	const auto consumed_args = argpar_iter_ingested_orig_args(argpar_iter.get());
	LTTNG_ASSERT(consumed_args >= 0);
	*argc -= consumed_args;
	*argv += consumed_args;

	if (res.session_name.empty()) {
		error = true;
		ERR_FMT("{}`-s/--session` is required", prefix);
	}

	res.success = !error;
	return res;
}

static struct lttng_condition *
_handle_condition_session_rotation(int *argc,
				   const char ***argv,
				   int argc_offset,
				   enum lttng_condition_type condition_type,
				   const char *condition_cli_name)
{
	const auto result = parse_session_rotation(argc, argv, argc_offset, condition_cli_name);

	if (!result.success) {
		ERR_FMT("Failed to parse {} arguments", condition_cli_name);
		return nullptr;
	}

	auto condition = [condition_type]() {
		struct lttng_condition *raw_condition = nullptr;
		switch (condition_type) {
		case LTTNG_CONDITION_TYPE_SESSION_ROTATION_COMPLETED:
			raw_condition = lttng_condition_session_rotation_completed_create();
			break;
		case LTTNG_CONDITION_TYPE_SESSION_ROTATION_ONGOING:
			raw_condition = lttng_condition_session_rotation_ongoing_create();
			break;
		default:
			break;
		}
		return lttng::make_unique_wrapper<struct lttng_condition, lttng_condition_destroy>(
			raw_condition);
	}();

	if (!condition) {
		ERR("Failed to create lttng_condition");
		return nullptr;
	}

	const auto status = lttng_condition_session_rotation_set_session_name(
		condition.get(), result.session_name.c_str());
	if (status != LTTNG_CONDITION_STATUS_OK) {
		ERR_FMT("Failed to set session rotation condition session name: {}", status);
		return nullptr;
	}

	if (!lttng_condition_validate(condition.get())) {
		ERR("Failed to validate condition");
		return nullptr;
	}

	return condition.release();
}

static struct lttng_condition *
handle_condition_session_rotation_starts(int *argc, const char ***argv, int argc_offset)
{
	return _handle_condition_session_rotation(argc,
						  argv,
						  argc_offset,
						  LTTNG_CONDITION_TYPE_SESSION_ROTATION_ONGOING,
						  "session-rotation-starts");
}

static struct lttng_condition *
handle_condition_session_rotation_finishes(int *argc, const char ***argv, int argc_offset)
{
	return _handle_condition_session_rotation(argc,
						  argv,
						  argc_offset,
						  LTTNG_CONDITION_TYPE_SESSION_ROTATION_COMPLETED,
						  "session-rotation-finishes");
}

namespace {
struct condition_descr {
	const char *name;
	struct lttng_condition *(*handler)(int *argc, const char ***argv, int argc_offset);
};
} /* namespace */

static const struct condition_descr condition_descrs[] = {
	{ "channel-buffer-usage-ge", handle_condition_buffer_usage_ge },
	{ "channel-buffer-usage-le", handle_condition_buffer_usage_le },
	{ "event-rule-matches", handle_condition_event },
	{ "session-consumed-size-ge", handle_condition_session_consumed_size },
	{ "session-rotation-finishes", handle_condition_session_rotation_finishes },
	{ "session-rotation-starts", handle_condition_session_rotation_starts },
};

static void print_valid_condition_names()
{
	unsigned int i;

	ERR("Valid condition names are:");

	for (i = 0; i < ARRAY_SIZE(condition_descrs); ++i) {
		ERR("  %s", condition_descrs[i].name);
	}
}

static struct lttng_condition *parse_condition(const char *condition_name,
					       int *argc,
					       const char ***argv,
					       int argc_offset,
					       int orig_arg_index,
					       const char *orig_arg)
{
	int i;
	struct lttng_condition *cond;
	const struct condition_descr *descr = nullptr;

	for (i = 0; i < ARRAY_SIZE(condition_descrs); i++) {
		if (strcmp(condition_name, condition_descrs[i].name) == 0) {
			descr = &condition_descrs[i];
			break;
		}
	}

	if (!descr) {
		ERR(WHILE_PARSING_ARG_N_ARG_FMT "Unknown condition name '%s'",
		    orig_arg_index + 1,
		    orig_arg,
		    condition_name);
		print_valid_condition_names();
		goto error;
	}

	cond = descr->handler(argc, argv, argc_offset);
	if (!cond) {
		/* The handler has already printed an error message. */
		goto error;
	}

	goto end;
error:
	cond = nullptr;
end:
	return cond;
}

static struct lttng_rate_policy *parse_rate_policy(const char *policy_str)
{
	int ret;
	size_t num_token = 0;
	struct lttng_dynamic_pointer_array tokens;
	struct lttng_rate_policy *policy = nullptr;
	enum lttng_rate_policy_type policy_type;
	unsigned long long value;
	char *policy_type_str;
	char *policy_value_str;

	LTTNG_ASSERT(policy_str);
	lttng_dynamic_pointer_array_init(&tokens, nullptr);

	/* Rate policy fields are separated by ':'. */
	ret = strutils_split(policy_str, ':', true, &tokens);
	if (ret == 0) {
		num_token = lttng_dynamic_pointer_array_get_count(&tokens);
	}

	/*
	 * Early sanity check that the number of parameter is exactly 2.
	 * i.e : type:value
	 */
	if (num_token != 2) {
		ERR("Rate policy format is invalid.");
		goto end;
	}

	policy_type_str = (char *) lttng_dynamic_pointer_array_get_pointer(&tokens, 0);
	policy_value_str = (char *) lttng_dynamic_pointer_array_get_pointer(&tokens, 1);

	/* Parse the type. */
	if (strcmp(policy_type_str, "once-after") == 0) {
		policy_type = LTTNG_RATE_POLICY_TYPE_ONCE_AFTER_N;
	} else if (strcmp(policy_type_str, "every") == 0) {
		policy_type = LTTNG_RATE_POLICY_TYPE_EVERY_N;
	} else {
		ERR("Rate policy type `%s` unknown.", policy_type_str);
		goto end;
	}

	/* Parse the value. */
	if (utils_parse_unsigned_long_long(policy_value_str, &value) != 0) {
		ERR("Failed to parse rate policy value `%s` as an integer.", policy_value_str);
		goto end;
	}

	if (value == 0) {
		ERR("Rate policy value `%s` must be > 0.", policy_value_str);
		goto end;
	}

	switch (policy_type) {
	case LTTNG_RATE_POLICY_TYPE_EVERY_N:
		policy = lttng_rate_policy_every_n_create(value);
		break;
	case LTTNG_RATE_POLICY_TYPE_ONCE_AFTER_N:
		policy = lttng_rate_policy_once_after_n_create(value);
		break;
	default:
		abort();
	}

	if (policy == nullptr) {
		ERR("Failed to create rate policy `%s`.", policy_str);
	}

end:
	lttng_dynamic_pointer_array_reset(&tokens);
	return policy;
}

static const struct argpar_opt_descr notify_action_opt_descrs[] = {
	{ OPT_RATE_POLICY, '\0', "rate-policy", true }, ARGPAR_OPT_DESCR_SENTINEL
};

static struct lttng_action *handle_action_notify(int *argc, const char ***argv, int argc_offset)
{
	struct lttng_action *action = nullptr;
	struct argpar_iter *argpar_iter = nullptr;
	const struct argpar_item *argpar_item = nullptr;
	struct lttng_rate_policy *policy = nullptr;

	argpar_iter = argpar_iter_create(*argc, *argv, notify_action_opt_descrs);
	if (!argpar_iter) {
		ERR("Failed to allocate an argpar iter.");
		goto error;
	}

	while (true) {
		enum parse_next_item_status status;

		status = parse_next_item(argpar_iter,
					 &argpar_item,
					 argc_offset,
					 *argv,
					 false,
					 nullptr,
					 "While parsing `notify` action:");
		if (status == PARSE_NEXT_ITEM_STATUS_ERROR ||
		    status == PARSE_NEXT_ITEM_STATUS_ERROR_MEMORY) {
			goto error;
		} else if (status == PARSE_NEXT_ITEM_STATUS_END) {
			break;
		}

		LTTNG_ASSERT(status == PARSE_NEXT_ITEM_STATUS_OK);

		if (argpar_item_type(argpar_item) == ARGPAR_ITEM_TYPE_OPT) {
			const struct argpar_opt_descr *descr = argpar_item_opt_descr(argpar_item);
			const char *arg = argpar_item_opt_arg(argpar_item);

			switch (descr->id) {
			case OPT_RATE_POLICY:
			{
				policy = parse_rate_policy(arg);
				if (!policy) {
					goto error;
				}
				break;
			}
			default:
				abort();
			}
		} else {
			const char *arg = argpar_item_non_opt_arg(argpar_item);

			ERR("Unexpected argument `%s`.", arg);
			goto error;
		}
	}

	*argc -= argpar_iter_ingested_orig_args(argpar_iter);
	*argv += argpar_iter_ingested_orig_args(argpar_iter);

	action = lttng_action_notify_create();
	if (!action) {
		ERR("Failed to create notify action");
		goto error;
	}

	if (policy) {
		enum lttng_action_status status;
		status = lttng_action_notify_set_rate_policy(action, policy);
		if (status != LTTNG_ACTION_STATUS_OK) {
			ERR("Failed to set rate policy");
			goto error;
		}
	}

	goto end;

error:
	lttng_action_destroy(action);
	action = nullptr;
end:
	lttng_rate_policy_destroy(policy);
	argpar_item_destroy(argpar_item);
	argpar_iter_destroy(argpar_iter);
	return action;
}

/*
 * Generic handler for a kind of action that takes a session name and an
 * optional rate policy.
 */

static struct lttng_action *handle_action_simple_session_with_policy(
	int *argc,
	const char ***argv,
	int argc_offset,
	struct lttng_action *(*create_action_cb)(),
	enum lttng_action_status (*set_session_name_cb)(struct lttng_action *, const char *),
	enum lttng_action_status (*set_rate_policy_cb)(struct lttng_action *,
						       const struct lttng_rate_policy *),
	const char *action_name)
{
	struct lttng_action *action = nullptr;
	struct argpar_iter *argpar_iter = nullptr;
	const struct argpar_item *argpar_item = nullptr;
	const char *session_name_arg = nullptr;
	enum lttng_action_status action_status;
	struct lttng_rate_policy *policy = nullptr;

	LTTNG_ASSERT(set_session_name_cb);
	LTTNG_ASSERT(set_rate_policy_cb);

	const struct argpar_opt_descr rate_policy_opt_descrs[] = {
		{ OPT_RATE_POLICY, '\0', "rate-policy", true }, ARGPAR_OPT_DESCR_SENTINEL
	};

	argpar_iter = argpar_iter_create(*argc, *argv, rate_policy_opt_descrs);
	if (!argpar_iter) {
		ERR("Failed to allocate an argpar iter.");
		goto error;
	}

	while (true) {
		enum parse_next_item_status status;

		status = parse_next_item(argpar_iter,
					 &argpar_item,
					 argc_offset,
					 *argv,
					 false,
					 nullptr,
					 "While parsing `%s` action:",
					 action_name);
		if (status == PARSE_NEXT_ITEM_STATUS_ERROR ||
		    status == PARSE_NEXT_ITEM_STATUS_ERROR_MEMORY) {
			goto error;
		} else if (status == PARSE_NEXT_ITEM_STATUS_END) {
			break;
		}

		LTTNG_ASSERT(status == PARSE_NEXT_ITEM_STATUS_OK);

		if (argpar_item_type(argpar_item) == ARGPAR_ITEM_TYPE_OPT) {
			const struct argpar_opt_descr *descr = argpar_item_opt_descr(argpar_item);
			const char *arg = argpar_item_opt_arg(argpar_item);

			switch (descr->id) {
			case OPT_RATE_POLICY:
			{
				policy = parse_rate_policy(arg);
				if (!policy) {
					goto error;
				}
				break;
			}
			default:
				abort();
			}
		} else {
			const char *arg = argpar_item_non_opt_arg(argpar_item);
			const unsigned int idx = argpar_item_non_opt_non_opt_index(argpar_item);

			switch (idx) {
			case 0:
				session_name_arg = arg;
				break;
			default:
				ERR("Unexpected argument `%s`.", arg);
				goto error;
			}
		}
	}

	*argc -= argpar_iter_ingested_orig_args(argpar_iter);
	*argv += argpar_iter_ingested_orig_args(argpar_iter);

	if (!session_name_arg) {
		ERR("Missing session name.");
		goto error;
	}

	action = create_action_cb();
	if (!action) {
		ERR("Failed to allocate %s session action.", action_name);
		goto error;
	}

	action_status = set_session_name_cb(action, session_name_arg);
	if (action_status != LTTNG_ACTION_STATUS_OK) {
		ERR("Failed to set action %s session's session name to '%s'.",
		    action_name,
		    session_name_arg);
		goto error;
	}

	if (policy) {
		action_status = set_rate_policy_cb(action, policy);
		if (action_status != LTTNG_ACTION_STATUS_OK) {
			ERR("Failed to set rate policy");
			goto error;
		}
	}

	goto end;

error:
	lttng_action_destroy(action);
	action = nullptr;

end:
	lttng_rate_policy_destroy(policy);
	argpar_item_destroy(argpar_item);
	argpar_iter_destroy(argpar_iter);
	return action;
}

static struct lttng_action *
handle_action_start_session(int *argc, const char ***argv, int argc_offset)
{
	return handle_action_simple_session_with_policy(argc,
							argv,
							argc_offset,
							lttng_action_start_session_create,
							lttng_action_start_session_set_session_name,
							lttng_action_start_session_set_rate_policy,
							"start");
}

static struct lttng_action *
handle_action_stop_session(int *argc, const char ***argv, int argc_offset)
{
	return handle_action_simple_session_with_policy(argc,
							argv,
							argc_offset,
							lttng_action_stop_session_create,
							lttng_action_stop_session_set_session_name,
							lttng_action_stop_session_set_rate_policy,
							"stop");
}

static struct lttng_action *
handle_action_rotate_session(int *argc, const char ***argv, int argc_offset)
{
	return handle_action_simple_session_with_policy(
		argc,
		argv,
		argc_offset,
		lttng_action_rotate_session_create,
		lttng_action_rotate_session_set_session_name,
		lttng_action_rotate_session_set_rate_policy,
		"rotate");
}

static const struct argpar_opt_descr snapshot_action_opt_descrs[] = {
	{ OPT_NAME, 'n', "name", true },
	{ OPT_MAX_SIZE, 'm', "max-size", true },
	{ OPT_CTRL_URL, '\0', "ctrl-url", true },
	{ OPT_DATA_URL, '\0', "data-url", true },
	{ OPT_URL, '\0', "url", true },
	{ OPT_PATH, '\0', "path", true },
	{ OPT_RATE_POLICY, '\0', "rate-policy", true },
	ARGPAR_OPT_DESCR_SENTINEL
};

static struct lttng_action *
handle_action_snapshot_session(int *argc, const char ***argv, int argc_offset)
{
	struct lttng_action *action = nullptr;
	struct argpar_iter *argpar_iter = nullptr;
	const struct argpar_item *argpar_item = nullptr;
	const char *session_name_arg = nullptr;
	char *snapshot_name_arg = nullptr;
	char *ctrl_url_arg = nullptr;
	char *data_url_arg = nullptr;
	char *max_size_arg = nullptr;
	char *url_arg = nullptr;
	char *path_arg = nullptr;
	char *error = nullptr;
	enum lttng_action_status action_status;
	struct lttng_snapshot_output *snapshot_output = nullptr;
	struct lttng_rate_policy *policy = nullptr;
	int ret;
	unsigned int locations_specified = 0;

	argpar_iter = argpar_iter_create(*argc, *argv, snapshot_action_opt_descrs);
	if (!argpar_iter) {
		ERR("Failed to allocate an argpar iter.");
		goto error;
	}

	while (true) {
		enum parse_next_item_status status;

		status = parse_next_item(argpar_iter,
					 &argpar_item,
					 argc_offset,
					 *argv,
					 false,
					 nullptr,
					 "While parsing `snapshot` action:");
		if (status == PARSE_NEXT_ITEM_STATUS_ERROR ||
		    status == PARSE_NEXT_ITEM_STATUS_ERROR_MEMORY) {
			goto error;
		} else if (status == PARSE_NEXT_ITEM_STATUS_END) {
			break;
		}

		LTTNG_ASSERT(status == PARSE_NEXT_ITEM_STATUS_OK);

		if (argpar_item_type(argpar_item) == ARGPAR_ITEM_TYPE_OPT) {
			const struct argpar_opt_descr *descr = argpar_item_opt_descr(argpar_item);
			const char *arg = argpar_item_opt_arg(argpar_item);

			switch (descr->id) {
			case OPT_NAME:
				if (!assign_string(&snapshot_name_arg, arg, "--name/-n")) {
					goto error;
				}

				break;
			case OPT_MAX_SIZE:
				if (!assign_string(&max_size_arg, arg, "--max-size/-m")) {
					goto error;
				}

				break;
			case OPT_CTRL_URL:
				if (!assign_string(&ctrl_url_arg, arg, "--ctrl-url")) {
					goto error;
				}

				break;
			case OPT_DATA_URL:
				if (!assign_string(&data_url_arg, arg, "--data-url")) {
					goto error;
				}

				break;
			case OPT_URL:
				if (!assign_string(&url_arg, arg, "--url")) {
					goto error;
				}

				break;
			case OPT_PATH:
				if (!assign_string(&path_arg, arg, "--path")) {
					goto error;
				}

				break;
			case OPT_RATE_POLICY:
			{
				policy = parse_rate_policy(arg);
				if (!policy) {
					goto error;
				}
				break;
			}
			default:
				abort();
			}
		} else {
			const char *arg = argpar_item_non_opt_arg(argpar_item);
			const unsigned int idx = argpar_item_non_opt_non_opt_index(argpar_item);

			switch (idx) {
			case 0:
				session_name_arg = arg;
				break;
			default:
				ERR("Unexpected argument `%s`.", arg);
				goto error;
			}
		}
	}

	*argc -= argpar_iter_ingested_orig_args(argpar_iter);
	*argv += argpar_iter_ingested_orig_args(argpar_iter);

	if (!session_name_arg) {
		ERR("Missing session name.");
		goto error;
	}

	/* --ctrl-url and --data-url must come in pair. */
	if (ctrl_url_arg && !data_url_arg) {
		ERR("--ctrl-url is specified, but --data-url is missing.");
		goto error;
	}

	if (!ctrl_url_arg && data_url_arg) {
		ERR("--data-url is specified, but --ctrl-url is missing.");
		goto error;
	}

	locations_specified += !!(ctrl_url_arg || data_url_arg);
	locations_specified += !!url_arg;
	locations_specified += !!path_arg;

	/* --ctrl-url/--data-url, --url and --path are mutually exclusive. */
	if (locations_specified > 1) {
		ERR("The --ctrl-url/--data-url, --url, and --path options can't be used together.");
		goto error;
	}

	/*
	 * Did the user specify an option that implies using a
	 * custom/unregistered output?
	 */
	if (url_arg || ctrl_url_arg || path_arg) {
		snapshot_output = lttng_snapshot_output_create();
		if (!snapshot_output) {
			ERR("Failed to allocate a snapshot output.");
			goto error;
		}
	}

	action = lttng_action_snapshot_session_create();
	if (!action) {
		ERR("Failed to allocate snapshot session action.");
		goto error;
	}

	action_status = lttng_action_snapshot_session_set_session_name(action, session_name_arg);
	if (action_status != LTTNG_ACTION_STATUS_OK) {
		ERR("Failed to set action snapshot session's session name to '%s'.",
		    session_name_arg);
		goto error;
	}

	if (snapshot_name_arg) {
		if (!snapshot_output) {
			ERR("Can't provide a snapshot output name without a snapshot output destination.");
			goto error;
		}

		ret = lttng_snapshot_output_set_name(snapshot_name_arg, snapshot_output);
		if (ret != 0) {
			ERR("Failed to set name of snapshot output.");
			goto error;
		}
	}

	if (max_size_arg) {
		uint64_t max_size;

		if (!snapshot_output) {
			ERR("Can't provide a snapshot output max size without a snapshot output destination.");
			goto error;
		}

		ret = utils_parse_size_suffix(max_size_arg, &max_size);
		if (ret != 0) {
			ERR("Failed to parse `%s` as a size.", max_size_arg);
			goto error;
		}

		ret = lttng_snapshot_output_set_size(max_size, snapshot_output);
		if (ret != 0) {
			ERR("Failed to set snapshot output's max size to %" PRIu64 " bytes.",
			    max_size);
			goto error;
		}
	}

	if (url_arg) {
		int num_uris;
		struct lttng_uri *uris;

		if (!strstr(url_arg, "://")) {
			ERR("Failed to parse '%s' as an URL.", url_arg);
			goto error;
		}

		num_uris = uri_parse_str_urls(url_arg, nullptr, &uris);
		if (num_uris < 1) {
			ERR("Failed to parse '%s' as an URL.", url_arg);
			goto error;
		}

		if (uris[0].dtype == LTTNG_DST_PATH) {
			ret = lttng_snapshot_output_set_local_path(uris[0].dst.path,
								   snapshot_output);
			free(uris);
			if (ret != 0) {
				ERR("Failed to assign '%s' as a local destination.", url_arg);
				goto error;
			}
		} else {
			ret = lttng_snapshot_output_set_network_url(url_arg, snapshot_output);
			free(uris);
			if (ret != 0) {
				ERR("Failed to assign '%s' as a network URL.", url_arg);
				goto error;
			}
		}
	}

	if (path_arg) {
		ret = lttng_snapshot_output_set_local_path(path_arg, snapshot_output);
		if (ret != 0) {
			ERR("Failed to parse '%s' as a local path.", path_arg);
			goto error;
		}
	}

	if (ctrl_url_arg) {
		/*
		 * Two argument form, network output with separate control and
		 * data URLs.
		 */
		ret = lttng_snapshot_output_set_network_urls(
			ctrl_url_arg, data_url_arg, snapshot_output);
		if (ret != 0) {
			ERR("Failed to parse `%s` and `%s` as control and data URLs.",
			    ctrl_url_arg,
			    data_url_arg);
			goto error;
		}
	}

	if (snapshot_output) {
		action_status = lttng_action_snapshot_session_set_output(action, snapshot_output);
		if (action_status != LTTNG_ACTION_STATUS_OK) {
			ERR("Failed to set snapshot session action's output.");
			goto error;
		}

		/* Ownership of `snapshot_output` has been transferred to the action. */
		snapshot_output = nullptr;
	}

	if (policy) {
		enum lttng_action_status status;
		status = lttng_action_snapshot_session_set_rate_policy(action, policy);
		if (status != LTTNG_ACTION_STATUS_OK) {
			ERR("Failed to set rate policy");
			goto error;
		}
	}

	goto end;

error:
	lttng_action_destroy(action);
	action = nullptr;
	free(error);
end:
	free(snapshot_name_arg);
	free(path_arg);
	free(url_arg);
	free(ctrl_url_arg);
	free(data_url_arg);
	free(snapshot_output);
	free(max_size_arg);
	lttng_rate_policy_destroy(policy);
	argpar_item_destroy(argpar_item);
	argpar_iter_destroy(argpar_iter);
	return action;
}

namespace {
struct action_descr {
	const char *name;
	struct lttng_action *(*handler)(int *argc, const char ***argv, int argc_offset);
};
} /* namespace */

static const struct action_descr action_descrs[] = {
	{ "notify", handle_action_notify },
	{ "start-session", handle_action_start_session },
	{ "stop-session", handle_action_stop_session },
	{ "rotate-session", handle_action_rotate_session },
	{ "snapshot-session", handle_action_snapshot_session },
};

static void print_valid_action_names()
{
	unsigned int i;

	ERR("Valid action names are:");

	for (i = 0; i < ARRAY_SIZE(action_descrs); ++i) {
		ERR("  %s", action_descrs[i].name);
	}
}

static struct lttng_action *parse_action(const char *action_name,
					 int *argc,
					 const char ***argv,
					 int argc_offset,
					 int orig_arg_index,
					 const char *orig_arg)
{
	int i;
	struct lttng_action *action;
	const struct action_descr *descr = nullptr;

	for (i = 0; i < ARRAY_SIZE(action_descrs); i++) {
		if (strcmp(action_name, action_descrs[i].name) == 0) {
			descr = &action_descrs[i];
			break;
		}
	}

	if (!descr) {
		ERR(WHILE_PARSING_ARG_N_ARG_FMT "Unknown action name '%s'",
		    orig_arg_index + 1,
		    orig_arg,
		    action_name);
		print_valid_action_names();
		goto error;
	}

	action = descr->handler(argc, argv, argc_offset);
	if (!action) {
		/* The handler has already printed an error message. */
		goto error;
	}

	goto end;
error:
	action = nullptr;
end:
	return action;
}

static const struct argpar_opt_descr add_trigger_options[] = {
	{ OPT_HELP, 'h', "help", false },
	{ OPT_LIST_OPTIONS, '\0', "list-options", false },
	{ OPT_CONDITION, '\0', "condition", true },
	{ OPT_ACTION, '\0', "action", true },
	{ OPT_NAME, '\0', "name", true },
	{ OPT_OWNER_UID, '\0', "owner-uid", true },
	ARGPAR_OPT_DESCR_SENTINEL,
};

static void lttng_actions_destructor(void *p)
{
	struct lttng_action *action = (lttng_action *) p;

	lttng_action_destroy(action);
}

int cmd_add_trigger(int argc, const char **argv)
{
	int ret;
	int my_argc = argc - 1;
	const char **my_argv = argv + 1;
	struct lttng_condition *condition = nullptr;
	struct lttng_dynamic_pointer_array actions;
	struct argpar_iter *argpar_iter = nullptr;
	const struct argpar_item *argpar_item = nullptr;
	const struct argpar_error *argpar_error = nullptr;
	struct lttng_action *action_list = nullptr;
	struct lttng_action *action = nullptr;
	struct lttng_trigger *trigger = nullptr;
	char *name = nullptr;
	int i;
	char *owner_uid = nullptr;
	enum lttng_error_code ret_code;
	struct mi_writer *mi_writer = nullptr;

	lttng_dynamic_pointer_array_init(&actions, lttng_actions_destructor);

	if (lttng_opt_mi) {
		mi_writer = mi_lttng_writer_create(fileno(stdout), lttng_opt_mi);
		if (!mi_writer) {
			ret = CMD_ERROR;
			goto error;
		}

		/* Open command element. */
		ret = mi_lttng_writer_command_open(mi_writer, mi_lttng_element_command_add_trigger);
		if (ret) {
			ret = CMD_ERROR;
			goto error;
		}

		/* Open output element. */
		ret = mi_lttng_writer_open_element(mi_writer, mi_lttng_element_command_output);
		if (ret) {
			ret = CMD_ERROR;
			goto error;
		}
	}

	while (true) {
		enum parse_next_item_status status;
		int ingested_args;
		const struct argpar_opt_descr *descr;
		const char *arg;

		argpar_iter_destroy(argpar_iter);
		argpar_iter = argpar_iter_create(my_argc, my_argv, add_trigger_options);
		if (!argpar_iter) {
			ERR("Failed to create argpar iter.");
			goto error;
		}

		status = parse_next_item(argpar_iter,
					 &argpar_item,
					 argc - my_argc,
					 my_argv,
					 true,
					 &argpar_error,
					 nullptr);
		if (status == PARSE_NEXT_ITEM_STATUS_ERROR) {
			if (argpar_error_type(argpar_error) == ARGPAR_ERROR_TYPE_MISSING_OPT_ARG) {
				const int opt_id =
					argpar_error_opt_descr(argpar_error, nullptr)->id;

				if (opt_id == OPT_CONDITION) {
					print_valid_condition_names();
				} else if (opt_id == OPT_ACTION) {
					print_valid_action_names();
				}
			}

			goto error;
		} else if (status == PARSE_NEXT_ITEM_STATUS_ERROR_MEMORY) {
			goto error;
		} else if (status == PARSE_NEXT_ITEM_STATUS_END) {
			break;
		}

		LTTNG_ASSERT(status == PARSE_NEXT_ITEM_STATUS_OK);

		if (argpar_item_type(argpar_item) == ARGPAR_ITEM_TYPE_NON_OPT) {
			ERR("Unexpected argument `%s`.", argpar_item_non_opt_arg(argpar_item));
			goto error;
		}

		ingested_args = argpar_iter_ingested_orig_args(argpar_iter);

		my_argc -= ingested_args;
		my_argv += ingested_args;

		descr = argpar_item_opt_descr(argpar_item);
		arg = argpar_item_opt_arg(argpar_item);

		switch (descr->id) {
		case OPT_HELP:
			SHOW_HELP();
			ret = 0;
			goto end;
		case OPT_LIST_OPTIONS:
			list_cmd_options_argpar(stdout, add_trigger_options);
			ret = 0;
			goto end;
		case OPT_CONDITION:
		{
			if (condition) {
				ERR("A --condition was already given.");
				goto error;
			}

			condition = parse_condition(arg,
						    &my_argc,
						    &my_argv,
						    argc - my_argc,
						    argc - my_argc - ingested_args,
						    my_argv[-ingested_args]);
			if (!condition) {
				/*
				 * An error message was already printed by
				 * parse_condition.
				 */
				goto error;
			}

			break;
		}
		case OPT_ACTION:
		{
			action = parse_action(arg,
					      &my_argc,
					      &my_argv,
					      argc - my_argc,
					      argc - my_argc - ingested_args,
					      my_argv[-ingested_args]);
			if (!action) {
				/*
				 * An error message was already printed by
				 * parse_condition.
				 */
				goto error;
			}

			ret = lttng_dynamic_pointer_array_add_pointer(&actions, action);
			if (ret) {
				ERR("Failed to add pointer to pointer array.");
				goto error;
			}

			/* Ownership of the action was transferred to the list. */
			action = nullptr;

			break;
		}
		case OPT_NAME:
		{
			if (!assign_string(&name, arg, "--name")) {
				goto error;
			}

			break;
		}
		case OPT_OWNER_UID:
		{
			if (!assign_string(&owner_uid, arg, "--owner-uid")) {
				goto error;
			}

			break;
		}
		default:
			abort();
		}
	}

	if (!condition) {
		ERR("Missing --condition.");
		goto error;
	}

	if (lttng_dynamic_pointer_array_get_count(&actions) == 0) {
		ERR("Need at least one --action.");
		goto error;
	}

	action_list = lttng_action_list_create();
	if (!action_list) {
		goto error;
	}

	for (i = 0; i < lttng_dynamic_pointer_array_get_count(&actions); i++) {
		enum lttng_action_status status;

		action = (lttng_action *) lttng_dynamic_pointer_array_steal_pointer(&actions, i);

		status = lttng_action_list_add_action(action_list, action);
		if (status != LTTNG_ACTION_STATUS_OK) {
			goto error;
		}

		/*
		 * The `lttng_action_list_add_action()` takes a reference to
		 * the action. We can destroy ours.
		 */
		lttng_action_destroy(action);
		action = nullptr;
	}

	trigger = lttng_trigger_create(condition, action_list);
	if (!trigger) {
		goto error;
	}

	if (owner_uid) {
		enum lttng_trigger_status trigger_status;
		char *end;
		long long uid;

		errno = 0;
		uid = strtol(owner_uid, &end, 10);
		if (end == owner_uid || *end != '\0' || errno != 0) {
			ERR("Failed to parse `%s` as a user id.", owner_uid);
			goto error;
		}

		trigger_status = lttng_trigger_set_owner_uid(trigger, uid);
		if (trigger_status != LTTNG_TRIGGER_STATUS_OK) {
			ERR("Failed to set trigger's user identity.");
			goto error;
		}
	}

	if (name) {
		ret_code = lttng_register_trigger_with_name(trigger, name);
	} else {
		ret_code = lttng_register_trigger_with_automatic_name(trigger);
	}

	if (ret_code != LTTNG_OK) {
		ERR("Failed to register trigger: %s.", lttng_strerror(-ret_code));
		goto error;
	}

	if (lttng_opt_mi) {
		ret_code = lttng_trigger_mi_serialize(trigger, mi_writer, nullptr);
		if (ret_code != LTTNG_OK) {
			goto error;
		}
	} else {
		const char *returned_trigger_name;
		const enum lttng_trigger_status trigger_status =
			lttng_trigger_get_name(trigger, &returned_trigger_name);

		if (trigger_status != LTTNG_TRIGGER_STATUS_OK) {
			WARN("Failed to retrieve the added trigger's name.");
		} else {
			MSG("Added trigger `%s`.", returned_trigger_name);
		}
	}

	ret = 0;

	goto end;

error:
	ret = 1;

end:
	/* Mi closing. */
	if (lttng_opt_mi && mi_writer) {
		int mi_ret;

		/* Close output element. */
		mi_ret = mi_lttng_writer_close_element(mi_writer);
		if (mi_ret) {
			ret = 1;
			goto cleanup;
		}

		mi_ret = mi_lttng_writer_write_element_bool(
			mi_writer, mi_lttng_element_command_success, ret ? 0 : 1);
		if (mi_ret) {
			ret = 1;
			goto cleanup;
		}

		/* Command element close. */
		mi_ret = mi_lttng_writer_command_close(mi_writer);
		if (mi_ret) {
			ret = 1;
			goto cleanup;
		}
	}

cleanup:
	argpar_error_destroy(argpar_error);
	argpar_iter_destroy(argpar_iter);
	argpar_item_destroy(argpar_item);
	lttng_dynamic_pointer_array_reset(&actions);
	lttng_condition_destroy(condition);
	lttng_action_destroy(action_list);
	lttng_action_destroy(action);
	lttng_trigger_destroy(trigger);
	free(name);
	free(owner_uid);
	if (mi_writer && mi_lttng_writer_destroy(mi_writer)) {
		/* Preserve original error code. */
		ret = ret ? ret : CMD_ERROR;
	}

	return ret;
}
