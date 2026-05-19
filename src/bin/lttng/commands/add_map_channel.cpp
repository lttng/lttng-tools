/*
 * SPDX-FileCopyrightText: 2026 Philippe Proulx <philippe.proulx@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE

#include "../command.hpp"
#include "../exception.hpp"

#include <common/argpar-utils/argpar-utils.hpp>
#include <common/format.hpp>
#include <common/make-unique-wrapper.hpp>
#include <common/mi-lttng.hpp>
#include <common/scope-exit.hpp>

#include <lttng/lttng.h>
#include <lttng/map/channel-buffer-ownership.h>
#include <lttng/map/channel-dead-group-policy.h>
#include <lttng/map/channel-descriptor-kernel.h>
#include <lttng/map/channel-descriptor-user.h>
#include <lttng/map/channel-descriptor.h>
#include <lttng/map/channel-type.h>
#include <lttng/map/channel-update-policy.h>
#include <lttng/map/value-type.h>
#include <lttng/session.h>

#include <vendor/argpar/argpar.hpp>
#include <vendor/optional.hpp>

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>

#ifdef LTTNG_EMBED_HELP
static const char help_msg[] =
#include <lttng-add-map-channel.1.h>
	;
#endif /* LTTNG_EMBED_HELP */

namespace {

enum add_map_channel_option_type {
	OPT_HELP,
	OPT_LIST_OPTIONS,
	OPT_TYPE,
	OPT_SESSION,
	OPT_VALUE_TYPE,
	OPT_MAX_KEY_COUNT,
	OPT_UPDATE_POLICY,
	OPT_BUFFER_OWNERSHIP,
	OPT_DEAD_PROCESS_POLICY,
};

struct cmd_cfg final {
	std::string session_name;
	nonstd::optional<std::string> channel_name;
	lttng_map_channel_type type = LTTNG_MAP_CHANNEL_TYPE_KERNEL;
	lttng_map_value_type value_type = LTTNG_MAP_VALUE_TYPE_SIGNED_INT_MAX;
	nonstd::optional<std::uint64_t> max_key_count;
	lttng_map_channel_update_policy update_policy = LTTNG_MAP_CHANNEL_UPDATE_POLICY_PER_EVENT;

	/* Buffer ownership model */
	lttng_map_channel_buffer_ownership buffer_ownership =
		LTTNG_MAP_CHANNEL_BUFFER_OWNERSHIP_PER_UID;
	bool buffer_ownership_set = false;

	/* Dead process policy */
	lttng_map_channel_dead_group_policy dead_process_policy =
		LTTNG_MAP_CHANNEL_DEAD_GROUP_POLICY_SUM_INTO_SHARED;
	bool dead_process_policy_set = false;
};

lttng_map_channel_type type_from_arg(const std::string& arg)
{
	if (arg == "kernel") {
		return LTTNG_MAP_CHANNEL_TYPE_KERNEL;
	} else if (arg == "user") {
		return LTTNG_MAP_CHANNEL_TYPE_USER;
	}

	LTTNG_THROW_CLI_INVALID_USAGE(fmt::format("Invalid value for `--type` option: `{}` "
						  "(expected `kernel` or `user`)",
						  arg));
}

lttng_map_value_type value_type_from_arg(const std::string& arg)
{
	if (arg == "signed-int-32") {
		return LTTNG_MAP_VALUE_TYPE_SIGNED_INT_32;
	} else if (arg == "signed-int-64") {
		return LTTNG_MAP_VALUE_TYPE_SIGNED_INT_64;
	} else if (arg == "signed-int-max") {
		return LTTNG_MAP_VALUE_TYPE_SIGNED_INT_MAX;
	}

	LTTNG_THROW_CLI_INVALID_USAGE(fmt::format("Invalid value for `--value-type` option: `{}` "
						  "(expected `signed-int-32`, `signed-int-64`, "
						  "or `signed-int-max`)",
						  arg));
}

lttng_map_channel_update_policy update_policy_from_arg(const std::string& arg)
{
	if (arg == "per-event") {
		return LTTNG_MAP_CHANNEL_UPDATE_POLICY_PER_EVENT;
	} else if (arg == "per-rule-match") {
		return LTTNG_MAP_CHANNEL_UPDATE_POLICY_PER_RULE_MATCH;
	}

	LTTNG_THROW_CLI_INVALID_USAGE(
		fmt::format("Invalid value for `--update-policy` option: `{}` "
			    "(expected `per-event` or `per-rule-match`)",
			    arg));
}

lttng_map_channel_buffer_ownership buffer_ownership_from_arg(const std::string& arg)
{
	if (arg == "user") {
		return LTTNG_MAP_CHANNEL_BUFFER_OWNERSHIP_PER_UID;
	} else if (arg == "process") {
		return LTTNG_MAP_CHANNEL_BUFFER_OWNERSHIP_PER_PID;
	}

	LTTNG_THROW_CLI_INVALID_USAGE(
		fmt::format("Invalid value for `--buffer-ownership` option: `{}` "
			    "(expected `user` or `process`)",
			    arg));
}

lttng_map_channel_dead_group_policy dead_process_policy_from_arg(const std::string& arg)
{
	if (arg == "drop") {
		return LTTNG_MAP_CHANNEL_DEAD_GROUP_POLICY_DROP;
	} else if (arg == "sum-into-shared") {
		return LTTNG_MAP_CHANNEL_DEAD_GROUP_POLICY_SUM_INTO_SHARED;
	}

	LTTNG_THROW_CLI_INVALID_USAGE(
		fmt::format("Invalid value for `--dead-process-policy` option: `{}` "
			    "(expected `drop` or `sum-into-shared`)",
			    arg));
}

std::uint64_t max_key_count_from_arg(const std::string& arg)
{
	if (arg.empty()) {
		LTTNG_THROW_CLI_INVALID_USAGE("Empty value for `--max-key-count` option");
	}

	errno = 0;

	char *end = nullptr;
	const auto value = std::strtoull(arg.c_str(), &end, 10);

	if (errno != 0 || end == arg.c_str() || *end != '\0') {
		LTTNG_THROW_CLI_INVALID_USAGE(
			fmt::format("Invalid value for `--max-key-count` option: `{}` "
				    "(expected a positive integer)",
				    arg));
	}

	if (value == 0) {
		LTTNG_THROW_CLI_INVALID_USAGE(
			"Value for `--max-key-count` option must be greater than 0");
	}

	return static_cast<std::uint64_t>(value);
}

void reject_duplicate_option(const char *const long_name, const bool already_set)
{
	if (already_set) {
		LTTNG_THROW_CLI_INVALID_USAGE(
			fmt::format("Option `--{}` specified more than once", long_name));
	}
}

nonstd::optional<cmd_cfg> cmd_cfg_from_cli_args(const int argc, const char **const argv)
{
	constexpr argpar_opt_descr add_map_channel_options[] = {
		{ OPT_HELP, 'h', "help", false },
		{ OPT_LIST_OPTIONS, '\0', "list-options", false },
		{ OPT_TYPE, 't', "type", true },
		{ OPT_SESSION, 's', "session", true },
		{ OPT_VALUE_TYPE, '\0', "value-type", true },
		{ OPT_MAX_KEY_COUNT, '\0', "max-key-count", true },
		{ OPT_UPDATE_POLICY, '\0', "update-policy", true },
		{ OPT_BUFFER_OWNERSHIP, '\0', "buffer-ownership", true },
		{ OPT_DEAD_PROCESS_POLICY, '\0', "dead-process-policy", true },
		ARGPAR_OPT_DESCR_SENTINEL,
	};

	argpar::Iter<nonstd::optional<argpar::Item>> argpar_iter(
		argc - 1, argv + 1, add_map_channel_options);

	std::string session_name;
	nonstd::optional<std::string> channel_name;
	nonstd::optional<lttng_map_channel_type> type;
	nonstd::optional<lttng_map_value_type> value_type;
	nonstd::optional<std::uint64_t> max_key_count;
	nonstd::optional<lttng_map_channel_update_policy> update_policy;
	nonstd::optional<lttng_map_channel_buffer_ownership> buffer_ownership;
	nonstd::optional<lttng_map_channel_dead_group_policy> dead_process_policy;

	try {
		while (const auto item = argpar_iter.next()) {
			if (item->isNonOpt()) {
				if (channel_name) {
					LTTNG_THROW_CLI_INVALID_USAGE(
						fmt::format("More than one map channel name given: "
							    "first was `{}`, then got `{}`",
							    *channel_name,
							    item->asNonOpt().arg()));
				}

				channel_name = item->asNonOpt().arg();
				continue;
			}

			const auto& opt = item->asOpt();
			const auto long_name = opt.descr().long_name;

			switch (opt.descr().id) {
			case OPT_HELP:
				SHOW_HELP_THROW("add-map-channel");
				return nonstd::nullopt;
			case OPT_LIST_OPTIONS:
				list_cmd_options_argpar(stdout, add_map_channel_options);
				return nonstd::nullopt;
			case OPT_TYPE:
				reject_duplicate_option(long_name, type.has_value());
				type = type_from_arg(opt.arg());
				break;
			case OPT_SESSION:
				reject_duplicate_option(long_name, !session_name.empty());
				session_name = opt.arg();
				break;
			case OPT_VALUE_TYPE:
				reject_duplicate_option(long_name, value_type.has_value());
				value_type = value_type_from_arg(opt.arg());
				break;
			case OPT_MAX_KEY_COUNT:
				reject_duplicate_option(long_name, max_key_count.has_value());
				max_key_count = max_key_count_from_arg(opt.arg());
				break;
			case OPT_UPDATE_POLICY:
				reject_duplicate_option(long_name, update_policy.has_value());
				update_policy = update_policy_from_arg(opt.arg());
				break;
			case OPT_BUFFER_OWNERSHIP:
				reject_duplicate_option(long_name, buffer_ownership.has_value());
				buffer_ownership = buffer_ownership_from_arg(opt.arg());
				break;
			case OPT_DEAD_PROCESS_POLICY:
				reject_duplicate_option(long_name, dead_process_policy.has_value());
				dead_process_policy = dead_process_policy_from_arg(opt.arg());
				break;
			default:
				break;
			}
		}
	} catch (const argpar::UnknownOptError& exc) {
		LTTNG_THROW_CLI_INVALID_USAGE(fmt::format("Unknown option `{}`", exc.name()));
	} catch (const argpar::MissingOptArgumentError& exc) {
		LTTNG_THROW_CLI_INVALID_USAGE(fmt::format("Missing argument for option `{}{}`",
							  exc.descr().isShort() ? "-" : "--",
							  exc.descr().isShort() ?
								  &exc.descr().descr().short_name :
								  exc.descr().descr().long_name));
	} catch (const argpar::UnexpectedOptArgumentError& exc) {
		LTTNG_THROW_CLI_INVALID_USAGE(fmt::format("Unexpected argument for option `{}{}`",
							  exc.descr().isShort() ? "-" : "--",
							  exc.descr().isShort() ?
								  &exc.descr().descr().short_name :
								  exc.descr().descr().long_name));
	}

	if (!type) {
		LTTNG_THROW_CLI_INVALID_USAGE("Missing mandatory `--type` option");
	}

	if (buffer_ownership && *type != LTTNG_MAP_CHANNEL_TYPE_USER) {
		LTTNG_THROW_CLI_INVALID_USAGE(
			"The `--buffer-ownership` option only applies with `--type=user`");
	}

	if (dead_process_policy) {
		const auto resolved_ownership =
			buffer_ownership.value_or(LTTNG_MAP_CHANNEL_BUFFER_OWNERSHIP_PER_UID);

		if (*type != LTTNG_MAP_CHANNEL_TYPE_USER ||
		    resolved_ownership != LTTNG_MAP_CHANNEL_BUFFER_OWNERSHIP_PER_PID) {
			LTTNG_THROW_CLI_INVALID_USAGE(
				"The `--dead-process-policy` option only applies with "
				"`--type=user` and `--buffer-ownership=process`");
		}
	}

	if (session_name.empty()) {
		const auto default_session_name =
			lttng::make_unique_wrapper<char, lttng::memory::free>(get_session_name());

		if (!default_session_name) {
			LTTNG_THROW_CLI_NO_DEFAULT_SESSION();
		}

		session_name = default_session_name.get();
	}

	cmd_cfg cmd_cfg;

	cmd_cfg.session_name = std::move(session_name);
	cmd_cfg.channel_name = std::move(channel_name);
	cmd_cfg.type = *type;

	if (value_type) {
		cmd_cfg.value_type = *value_type;
	}

	cmd_cfg.max_key_count = max_key_count;

	if (update_policy) {
		cmd_cfg.update_policy = *update_policy;
	}

	if (buffer_ownership) {
		cmd_cfg.buffer_ownership = *buffer_ownership;
		cmd_cfg.buffer_ownership_set = true;
	}

	if (dead_process_policy) {
		cmd_cfg.dead_process_policy = *dead_process_policy;
		cmd_cfg.dead_process_policy_set = true;
	}

	return cmd_cfg;
}

using map_channel_descriptor_uptr = std::unique_ptr<
	lttng_map_channel_descriptor,
	lttng::memory::create_deleter_class<lttng_map_channel_descriptor,
					    lttng_map_channel_descriptor_destroy>::deleter>;

map_channel_descriptor_uptr map_channel_descriptor_from_cmd_cfg(const cmd_cfg& cfg)
{
	lttng_map_channel_descriptor *const raw_descriptor = cfg.type ==
			LTTNG_MAP_CHANNEL_TYPE_KERNEL ?
		lttng_map_channel_descriptor_kernel_string_key_scalar_value_create(cfg.value_type) :
		lttng_map_channel_descriptor_user_string_key_scalar_value_create(
			cfg.value_type, cfg.buffer_ownership);
	auto descriptor =
		lttng::make_unique_wrapper<lttng_map_channel_descriptor,
					   lttng_map_channel_descriptor_destroy>(raw_descriptor);

	if (!descriptor) {
		LTTNG_THROW_ERROR("Failed to create map channel descriptor");
	}

	if (cfg.channel_name) {
		const auto status = lttng_map_channel_descriptor_set_name(
			descriptor.get(), cfg.channel_name->c_str());

		if (status != LTTNG_MAP_CHANNEL_DESCRIPTOR_STATUS_OK) {
			LTTNG_THROW_ERROR(fmt::format("Failed to set map channel descriptor "
						      " name to `{}`",
						      *cfg.channel_name));
		}
	}

	if (cfg.max_key_count) {
		const auto status = lttng_map_channel_descriptor_set_max_key_count(
			descriptor.get(), *cfg.max_key_count);

		if (status != LTTNG_MAP_CHANNEL_DESCRIPTOR_STATUS_OK) {
			LTTNG_THROW_ERROR(fmt::format("Failed to set maximum key count of "
						      "map channel descriptor to {}",
						      *cfg.max_key_count));
		}
	}

	{
		const auto status = lttng_map_channel_descriptor_set_update_policy(
			descriptor.get(), cfg.update_policy);

		if (status != LTTNG_MAP_CHANNEL_DESCRIPTOR_STATUS_OK) {
			LTTNG_THROW_ERROR("Failed to set map channel descriptor update policy");
		}
	}

	if (cfg.type == LTTNG_MAP_CHANNEL_TYPE_USER &&
	    cfg.buffer_ownership == LTTNG_MAP_CHANNEL_BUFFER_OWNERSHIP_PER_PID &&
	    cfg.dead_process_policy_set) {
		const auto status = lttng_map_channel_descriptor_user_set_dead_group_policy(
			descriptor.get(), cfg.dead_process_policy);

		if (status != LTTNG_MAP_CHANNEL_DESCRIPTOR_STATUS_OK) {
			LTTNG_THROW_ERROR(
				"Failed to set map channel descriptor dead process policy");
		}
	}

	return descriptor;
}

void add_map_channel_from_cmd_cfg(const cmd_cfg& cmd_cfg)
{
	const auto ret = lttng_session_add_map_channel(
		cmd_cfg.session_name.c_str(), map_channel_descriptor_from_cmd_cfg(cmd_cfg).get());

	if (ret != LTTNG_OK) {
		LTTNG_THROW_CTL(fmt::format("Failed to add map channel to recording session `{}`",
					    cmd_cfg.session_name),
				static_cast<lttng_error_code>(ret));
	}
}

void run_human_from_cmd_cfg(const cmd_cfg& cmd_cfg)
{
	add_map_channel_from_cmd_cfg(cmd_cfg);

	if (cmd_cfg.channel_name) {
		MSG("Map channel `%s` added to recording session `%s`.",
		    cmd_cfg.channel_name->c_str(),
		    cmd_cfg.session_name.c_str());
	} else {
		MSG("Map channel added to recording session `%s`.", cmd_cfg.session_name.c_str());
	}
}

void run_mi_from_cmd_cfg(const cmd_cfg& cmd_cfg)
{
	const mi_writer_uptr writer(mi_lttng_writer_create(fileno(stdout), LTTNG_MI_XML));

	if (!writer) {
		LTTNG_THROW_ERROR("Failed to create MI writer");
	}

	if (mi_lttng_writer_command_open(writer.get(), "add-map-channel")) {
		LTTNG_THROW_ERROR("Failed to open MI `<command>` element");
	}

	const auto command_close_guard = lttng::make_scope_exit([&writer]() noexcept {
		if (mi_lttng_writer_command_close(writer.get())) {
			ERR("Failed to close MI `<command>` element");
		}
	});

	const auto emit_empty_output_and_success = [&writer](const bool success) {
		if (mi_lttng_writer_open_element(writer.get(), mi_lttng_element_command_output)) {
			LTTNG_THROW_ERROR("Failed to open MI `<output>` element");
		}

		if (mi_lttng_writer_close_element(writer.get())) {
			LTTNG_THROW_ERROR("Failed to close MI `<output>` element");
		}

		if (mi_lttng_writer_write_element_bool(
			    writer.get(), mi_lttng_element_command_success, success ? 1 : 0)) {
			LTTNG_THROW_ERROR("Failed to write MI `<success>` element");
		}
	};

	try {
		add_map_channel_from_cmd_cfg(cmd_cfg);
	} catch (...) {
		/* Got some error: not a success */
		emit_empty_output_and_success(false);
		throw;
	}

	emit_empty_output_and_success(true);
}

} /* namespace */

int cmd_add_map_channel(const int argc, const char **const argv)
{
	try {
		const auto cmd_cfg = cmd_cfg_from_cli_args(argc, argv);

		if (!cmd_cfg) {
			return CMD_SUCCESS;
		}

		if (lttng_opt_mi) {
			run_mi_from_cmd_cfg(*cmd_cfg);
		} else {
			run_human_from_cmd_cfg(*cmd_cfg);
		}

		return CMD_SUCCESS;
	} catch (const lttng::ctl::error& exc) {
		ERR_FMT("Failed to add map channel: {}", lttng_strerror(exc.code()));
		return CMD_ERROR;
	} catch (const std::exception& exc) {
		ERR_FMT("Failed to add map channel: {}", exc.what());
		return CMD_ERROR;
	}
}
