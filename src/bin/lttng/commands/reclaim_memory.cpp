/*
 * SPDX-FileCopyrightText: 2025 Philippe Proulx <philippe.proulx@efficios.com>
 * SPDX-FileCopyrightText: 2025 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE

#include "../command.hpp"
#include "../exception.hpp"

#include <common/ctl/domain.hpp>
#include <common/ctl/format.hpp>
#include <common/ctl/memory.hpp>
#include <common/domain.hpp>
#include <common/format.hpp>
#include <common/make-unique-wrapper.hpp>
#include <common/make-unique.hpp>
#include <common/mi-lttng.hpp>
#include <common/scope-exit.hpp>
#include <common/utils.hpp>

#include <lttng/domain-internal.hpp>

#include <vendor/argpar/argpar.hpp>
#include <vendor/optional.hpp>

#include <chrono>
#include <cstdio>
#include <map>
#include <numeric>
#include <set>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

#ifdef LTTNG_EMBED_HELP
static const char help_msg[] =
#include <lttng-reclaim-memory.1.h>
	;
#endif /* LTTNG_EMBED_HELP */

namespace {
enum reclaim_option_types {
	OPT_HELP,
	OPT_LIST_OPTIONS,
	OPT_OLDER_THAN,
	OPT_USER_SPACE,
	OPT_SESSION,
	OPT_ALL_CHANNELS,
	OPT_NO_WAIT,
};

using channel_name_set = std::set<std::string>;

struct reclamation_amount {
	reclamation_amount() = delete;
	reclamation_amount(std::uint64_t immediate_bytes_, std::uint64_t deferred_bytes_) :
		immediate_bytes(immediate_bytes_), deferred_bytes(deferred_bytes_)
	{
	}

	const std::uint64_t immediate_bytes;
	const std::uint64_t deferred_bytes;
};

struct reclaim_result {
	std::map<std::string, reclamation_amount> reclaimed_per_channel;

	bool success = false;

	std::uint64_t total_reclaimed_immediate() const noexcept
	{
		return std::accumulate(
			reclaimed_per_channel.begin(),
			reclaimed_per_channel.end(),
			0ULL,
			[](std::uint64_t acc,
			   const std::pair<const std::string, reclamation_amount>& entry) {
				return acc + entry.second.immediate_bytes;
			});
	}

	std::uint64_t total_reclaimed_deferred() const noexcept
	{
		return std::accumulate(
			reclaimed_per_channel.begin(),
			reclaimed_per_channel.end(),
			0ULL,
			[](std::uint64_t acc,
			   const std::pair<const std::string, reclamation_amount>& entry) {
				return acc + entry.second.deferred_bytes;
			});
	}
};

struct reclaim_config {
	std::string session_name;
	channel_name_set channel_names;
	lttng::domain_class domain;
	nonstd::optional<std::chrono::microseconds> older_than;
	bool no_wait;
};

channel_name_set get_session_channel_names(const std::string& session_name,
					   lttng::domain_class domain)
{
	lttng_domain domain_handle{};
	domain_handle.type = lttng::ctl::get_lttng_domain_type_from_domain_class(domain);

	auto handle =
		lttng::ctl::handle_uptr(lttng_create_handle(session_name.c_str(), &domain_handle));
	const auto channels = [&handle]() {
		lttng_channel *raw_channels = nullptr;
		const auto channel_count [[maybe_unused]] = lttng_list_channels(
			const_cast<lttng_handle *>(handle.get()), &raw_channels);

		if (channel_count < 0) {
			LTTNG_THROW_CTL(fmt::format("Failed to list channels for session `{}`",
						    handle->session_name),
					static_cast<lttng_error_code>(-channel_count));
		}

		return lttng::ctl::channel_list(raw_channels, channel_count);
	}();

	channel_name_set channel_names;
	for (const auto& chan : channels) {
		channel_names.insert(chan.name);
	}

	return channel_names;
}

/* Parse CLI arguments into configuration struct */
nonstd::optional<reclaim_config> parse_cli_args(int argc, const char **argv)
{
	constexpr argpar_opt_descr reclaim_argpar_options[] = {
		{ reclaim_option_types::OPT_HELP, 'h', "help", false },
		{ reclaim_option_types::OPT_LIST_OPTIONS, '\0', "list-options", false },
		{ reclaim_option_types::OPT_OLDER_THAN, '\0', "older-than", false },
		{ reclaim_option_types::OPT_USER_SPACE, 'u', "userspace", false },
		{ reclaim_option_types::OPT_SESSION, 's', "session", true },
		{ reclaim_option_types::OPT_ALL_CHANNELS, 'a', "all", false },
		{ reclaim_option_types::OPT_NO_WAIT, '\0', "no-wait", false },
		ARGPAR_OPT_DESCR_SENTINEL,
	};

	argpar::Iter<nonstd::optional<argpar::Item>> argpar_iter(
		argc - 1, argv + 1, reclaim_argpar_options);

	std::string target_session_name;
	channel_name_set target_channel_names;
	nonstd::optional<lttng::domain_class> target_domain;
	nonstd::optional<std::chrono::microseconds> older_than;
	bool target_all_channels = false;
	bool no_wait = false;

	try {
		while (const auto item = argpar_iter.next()) {
			if (item->isNonOpt()) {
				/* Trailing argument is expected to be the channel name */
				target_channel_names.insert(item->asNonOpt().arg());
				continue;
			}

			switch (item->asOpt().descr().id) {
			case reclaim_option_types::OPT_HELP:
				SHOW_HELP_THROW("reclaim-memory");
				return nonstd::nullopt;
			case reclaim_option_types::OPT_LIST_OPTIONS:
				list_cmd_options_argpar(stdout, reclaim_argpar_options);
				return nonstd::nullopt;
			case reclaim_option_types::OPT_USER_SPACE:
				if (target_domain.has_value()) {
					LTTNG_THROW_CLI_INVALID_USAGE(
						fmt::format("Only one domain can be specified"));
				}

				target_domain = lttng::domain_class::USER_SPACE;
				break;
			case reclaim_option_types::OPT_OLDER_THAN:
			{
				std::uint64_t older_than_value = 0;

				if (utils_parse_time_suffix(item->asOpt().arg(),
							    &older_than_value) < 0) {
					LTTNG_THROW_CLI_INVALID_USAGE(
						fmt::format("Invalid value for --{} parameter: {}",
							    item->asOpt().descr().long_name,
							    item->asOpt().arg()));
				}

				older_than = std::chrono::microseconds(older_than_value);
				break;
			}
			case reclaim_option_types::OPT_SESSION:
				if (!target_session_name.empty()) {
					LTTNG_THROW_CLI_INVALID_USAGE(
						fmt::format("Only one session can be specified"));
				}

				target_session_name = item->asOpt().arg();
				break;
			case reclaim_option_types::OPT_ALL_CHANNELS:
				if (target_all_channels) {
					LTTNG_THROW_CLI_INVALID_USAGE(
						fmt::format("Option --{} specified multiple times",
							    item->asOpt().descr().long_name));
				}

				target_all_channels = true;
				break;
			case reclaim_option_types::OPT_NO_WAIT:
				if (no_wait) {
					LTTNG_THROW_CLI_INVALID_USAGE(
						fmt::format("Option --{} specified multiple times",
							    item->asOpt().descr().long_name));
				}

				no_wait = true;
				break;
			default:
				break;
			}
		}
	} catch (const argpar::UnknownOptError& e) {
		LTTNG_THROW_CLI_INVALID_USAGE(fmt::format("Unknown option `{}`", e.name()));
	} catch (const argpar::MissingOptArgumentError& e) {
		auto msg = fmt::format("Missing argument for option '{}{}'",
				       e.descr().isShort() ? "-" : "--",
				       e.descr().isShort() ? &e.descr().descr().short_name :
							     e.descr().descr().long_name);
		LTTNG_THROW_CLI_INVALID_USAGE(msg);
	} catch (const argpar::UnexpectedOptArgumentError& e) {
		auto msg = fmt::format("Unexpected argument for option '{}{}'",
				       e.descr().isShort() ? "-" : "--",
				       e.descr().isShort() ? &e.descr().descr().short_name :
							     e.descr().descr().long_name);
		LTTNG_THROW_CLI_INVALID_USAGE(msg);
	}

	/* Set default session name if not specified. */
	if (target_session_name.empty()) {
		const auto default_session_name =
			lttng::make_unique_wrapper<char, lttng::memory::free>(get_session_name());

		if (!default_session_name) {
			LTTNG_THROW_CLI_NO_DEFAULT_SESSION();
		}

		target_session_name = default_session_name.get();
	}

	/*
	 * Currently, only the user space domain is supported. However, the user must explicitly
	 * specify the domain to avoid ambiguity when support for additional domains is introduced
	 * in the future.
	 */
	if (!target_domain) {
		LTTNG_THROW_CLI_INVALID_USAGE(
			"One domain must be specified (--kernel/--userspace)");
	}

	auto existing_channel_names =
		get_session_channel_names(target_session_name, *target_domain);
	if (!target_channel_names.empty() && target_all_channels) {
		LTTNG_THROW_CLI_INVALID_USAGE("Cannot specify channel names with --all");
	}

	if (target_all_channels) {
		target_channel_names = std::move(existing_channel_names);
	} else {
		/* Validate that specified channels exist in the session. */
		for (const auto& chan_name : target_channel_names) {
			if (existing_channel_names.find(chan_name) ==
			    existing_channel_names.end()) {
				LTTNG_THROW_INVALID_ARGUMENT_ERROR(
					fmt::format("Channel `{}` does not exist in session `{}`",
						    chan_name,
						    target_session_name));
			}
		}
	}

	return reclaim_config{ .session_name = std::move(target_session_name),
			       .channel_names = std::move(target_channel_names),
			       .domain = *target_domain,
			       .older_than = older_than,
			       .no_wait = no_wait };
}

/* Execute the memory reclaim operation. */
reclaim_result execute_reclaim(const reclaim_config& config)
{
	LTTNG_ASSERT(!config.session_name.empty());

	reclaim_result result;

	result.success = true;
	std::vector<std::pair<std::string, lttng::ctl::lttng_reclaim_memory_handle_uptr>>
		pending_ops;

	for (auto& channel_name : config.channel_names) {
		auto handle = [config, channel_name]() {
			lttng_reclaim_handle *raw_reclaimed_memory_handle = nullptr;

			const auto reclaim_status = lttng_reclaim_channel_memory(
				config.session_name.c_str(),
				channel_name.c_str(),
				lttng::ctl::get_lttng_domain_type_from_domain_class(config.domain),
				config.older_than ? config.older_than->count() : 0,
				&raw_reclaimed_memory_handle);

			lttng::ctl::lttng_reclaim_memory_handle_uptr request_handle{
				raw_reclaimed_memory_handle
			};

			if (reclaim_status == LTTNG_RECLAIM_CHANNEL_MEMORY_STATUS_OK) {
				return request_handle;
			} else {
				LTTNG_THROW_ERROR(
					fmt::format("Failed to reclaim memory for channel `{}`: {}",
						    channel_name,
						    reclaim_status));
			}
		}();

		pending_ops.emplace_back(channel_name, std::move(handle));
	}

	for (auto& op : pending_ops) {
		if (!config.no_wait) {
			const auto wait_status =
				lttng_reclaim_handle_wait_for_completion(op.second.get(), -1);
			if (wait_status != LTTNG_RECLAIM_HANDLE_STATUS_COMPLETED) {
				LTTNG_THROW_ERROR(fmt::format(
					"Failed to wait for memory reclaim completion: {}",
					wait_status));
			}
		}

		std::uint64_t reclaimed_bytes = 0;
		const auto get_size_status = lttng_reclaim_handle_get_reclaimed_memory_size_bytes(
			op.second.get(), &reclaimed_bytes);
		if (get_size_status != LTTNG_RECLAIM_HANDLE_STATUS_OK) {
			LTTNG_THROW_ERROR(fmt::format("Failed to get reclaimed memory size: {}",
						      get_size_status));
		}

		std::uint64_t pending_bytes = 0;
		const auto get_pending_status = lttng_reclaim_handle_get_pending_memory_size_bytes(
			op.second.get(), &pending_bytes);
		if (get_pending_status != LTTNG_RECLAIM_HANDLE_STATUS_OK) {
			LTTNG_THROW_ERROR(fmt::format("Failed to get pending memory size: {}",
						      get_pending_status));
		}

		result.reclaimed_per_channel.emplace(
			std::move(op.first), reclamation_amount{ reclaimed_bytes, pending_bytes });
	}

	return result;
}

/* Print human-readable output */
void run_and_print_human_readable(const reclaim_config& config)
{
	const auto result = execute_reclaim(config);
	if (result.reclaimed_per_channel.empty()) {
		fmt::print("No channels to reclaim.\n");
		return;
	}

	for (const auto& channel_result : result.reclaimed_per_channel) {
		const auto& channel_name = channel_result.first;
		const auto& reclaimed_amount = channel_result.second;
		const auto human_readable_size =
			utils_string_from_size(reclaimed_amount.immediate_bytes);

		fmt::print("Channel `{}`: {} reclaimed\n", channel_name, human_readable_size);
	}

	/* Only display the total if multiple channels were targeted. */
	if (result.reclaimed_per_channel.size() > 1) {
		const auto total_bytes = result.total_reclaimed_immediate();
		const auto total_human_readable = utils_string_from_size(total_bytes);

		fmt::print("Total: {} reclaimed\n", total_human_readable);
	}
}

/* Print machine interface (XML) output */
void run_and_print_machine_interface(const reclaim_config& config)
{
	const mi_writer_uptr writer(mi_lttng_writer_create(fileno(stdout), LTTNG_MI_XML));

	if (mi_lttng_writer_command_open(writer.get(), "reclaim-memory")) {
		LTTNG_THROW_ERROR("Failed to open command element");
	}

	const auto command_close_guard = lttng::make_scope_exit([&writer]() noexcept {
		if (mi_lttng_writer_command_close(writer.get())) {
			ERR("Failed to close machine interface command element");
		}
	});

	const auto result = [config, &writer]() {
		try {
			return execute_reclaim(config);
		} catch (const std::exception& e) {
			if (mi_lttng_writer_write_element_bool(
				    writer.get(), mi_lttng_element_command_success, 0)) {
				LTTNG_THROW_ERROR("Failed to write command success element");
			}

			throw e;
		}
	}();

	if (!result.success) {
		if (mi_lttng_writer_write_element_bool(
			    writer.get(), mi_lttng_element_command_success, 0)) {
			LTTNG_THROW_ERROR("Failed to write command success element");
		}
	} else {
		if (mi_lttng_writer_open_element(writer.get(), mi_lttng_element_command_output)) {
			LTTNG_THROW_ERROR("Failed to open command output element");
		}

		const auto command_output_close_guard = lttng::make_scope_exit(
			[&writer]() noexcept { mi_lttng_writer_close_element(writer.get()); });

		if (mi_lttng_writer_open_element(writer.get(), "channels")) {
			LTTNG_THROW_ERROR("Failed to open channels element");
		}

		auto channels_close_guard = lttng::make_scope_exit(
			[&writer]() noexcept { mi_lttng_writer_close_element(writer.get()); });

		for (const auto& channel_result : result.reclaimed_per_channel) {
			const auto& channel_name = channel_result.first;
			const auto& reclaimed_amount = channel_result.second;

			if (mi_lttng_writer_open_element(writer.get(), "channel")) {
				LTTNG_THROW_ERROR("Failed to open channel element");
			}

			const auto channel_close_guard =
				lttng::make_scope_exit([&writer]() noexcept {
					mi_lttng_writer_close_element(writer.get());
				});

			if (mi_lttng_writer_write_element_string(
				    writer.get(), "name", channel_name.c_str())) {
				LTTNG_THROW_ERROR("Failed to write channel name element");
			}
			if (mi_lttng_writer_write_element_unsigned_int(
				    writer.get(),
				    "reclaimed_bytes",
				    reclaimed_amount.immediate_bytes)) {
				LTTNG_THROW_ERROR("Failed to write reclaimed bytes element");
			}
		}
	}
}
} /* namespace */

int cmd_reclaim_memory(int argc, const char **argv)
{
	try {
		const auto config = parse_cli_args(argc, argv);
		if (!config) {
			/* Help or list-options was handled. */
			return CMD_SUCCESS;
		}

		if (lttng_opt_mi) {
			run_and_print_machine_interface(*config);
		} else {
			run_and_print_human_readable(*config);
		}

		return CMD_SUCCESS;
	} catch (const lttng::ctl::error& e) {
		LTTNG_THROW_ERROR(
			fmt::format("Failed to reclaim memory: {}", lttng_strerror(e.code())));
		return CMD_ERROR;
	}
}
