/*
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 * SPDX-FileCopyrightText: 2020 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "common/exception.hpp"

#include <exception>
#include <stdint.h>
#define _LGPL_SOURCE
#include "../command.hpp"
#include "list-common.hpp"
#include "list-human.hpp"
#include "list-mi.hpp"

#include <common/mi-lttng.hpp>
#include <common/scope-exit.hpp>
#include <common/time.hpp>
#include <common/tracker.hpp>
#include <common/utils.hpp>

#include <lttng/domain-internal.hpp>
#include <lttng/lttng.h>
#include <lttng/stream-info.h>

#include <inttypes.h>
#include <popt.h>
#include <stdlib.h>

namespace {

int opt_userspace;
int opt_kernel;
int opt_jul;
int opt_log4j;
int opt_log4j2;
int opt_python;
char *opt_channel;
int opt_domain;
int opt_fields;
int opt_syscall;
int opt_stream_info_details;

enum {
	OPT_HELP = 1,
	OPT_USERSPACE,
	OPT_LIST_OPTIONS,
};

struct poptOption long_options[] = {
	/* longName, shortName, argInfo, argPtr, value, descrip, argDesc */
	{ "help", 'h', POPT_ARG_NONE, nullptr, OPT_HELP, nullptr, nullptr },
	{ "kernel", 'k', POPT_ARG_VAL, &opt_kernel, 1, nullptr, nullptr },
	{ "jul", 'j', POPT_ARG_VAL, &opt_jul, 1, nullptr, nullptr },
	{ "log4j", 'l', POPT_ARG_VAL, &opt_log4j, 1, nullptr, nullptr },
	{ "log4j2", 0, POPT_ARG_VAL, &opt_log4j2, 1, nullptr, nullptr },
	{ "python", 'p', POPT_ARG_VAL, &opt_python, 1, nullptr, nullptr },
	{ "userspace", 'u', POPT_ARG_NONE, nullptr, OPT_USERSPACE, nullptr, nullptr },
	{ "channel", 'c', POPT_ARG_STRING, &opt_channel, 0, nullptr, nullptr },
	{ "domain", 'd', POPT_ARG_VAL, &opt_domain, 1, nullptr, nullptr },
	{ "fields", 'f', POPT_ARG_VAL, &opt_fields, 1, nullptr, nullptr },
	{ "syscall", 'S', POPT_ARG_VAL, &opt_syscall, 1, nullptr, nullptr },
	{ "stream-info-details", 0, POPT_ARG_VAL, &opt_stream_info_details, 1, nullptr, nullptr },
	{ "list-options", 0, POPT_ARG_NONE, nullptr, OPT_LIST_OPTIONS, nullptr, nullptr },
	{ nullptr, 0, 0, nullptr, 0, nullptr, nullptr }
};

class undefined_opt final : std::exception {};

/*
 * Parse command-line arguments and returns a corresponding
 * command configuration.
 *
 * Returns `nonstd::nullopt` when printing help/usage/options.
 */
nonstd::optional<list_cmd_config> make_config(int argc, const char **argv)
{
	if (argc < 1) {
		LTTNG_THROW_ERROR("");
	}

	auto pc = poptGetContext(nullptr, argc, argv, long_options, 0);
	const auto pc_guard = lttng::make_scope_exit([pc]() noexcept { poptFreeContext(pc); });

	poptReadDefaultConfig(pc, 0);

	{
		int opt;

		while ((opt = poptGetNextOpt(pc)) != -1) {
			switch (opt) {
			case OPT_HELP:
			{
				int ret;
				SHOW_HELP();
			}

				return nonstd::nullopt;
			case OPT_USERSPACE:
				opt_userspace = 1;
				break;
			case OPT_LIST_OPTIONS:
				list_cmd_options(stdout, long_options);
				return nonstd::nullopt;
			default:
				throw undefined_opt();
			}
		}
	}

	list_cmd_config config;

	if (const auto session_name = poptGetArg(pc)) {
		config.session_name = session_name;
		DBG2("Session name: %s", session_name);
	}

	if (const auto leftover = poptGetArg(pc)) {
		ERR("Unknown argument: %s", leftover);
		LTTNG_THROW_ERROR("");
	}

	if (!opt_kernel && opt_syscall) {
		WARN("--syscall will only work with the Kernel domain (-k)");
		LTTNG_THROW_ERROR("");
	}

	if (opt_channel) {
		config.channel_name = opt_channel;
	}

	/* Determine domain type */
	if (opt_kernel) {
		config.domain_type = LTTNG_DOMAIN_KERNEL;
	} else if (opt_userspace) {
		DBG2("Listing userspace global domain");
		config.domain_type = LTTNG_DOMAIN_UST;
	} else if (opt_jul) {
		DBG2("Listing JUL domain");
		config.domain_type = LTTNG_DOMAIN_JUL;
	} else if (opt_log4j) {
		config.domain_type = LTTNG_DOMAIN_LOG4J;
	} else if (opt_log4j2) {
		config.domain_type = LTTNG_DOMAIN_LOG4J2;
	} else if (opt_python) {
		config.domain_type = LTTNG_DOMAIN_PYTHON;
	}

	/* Set boolean flags */
	config.kernel = opt_kernel;
	config.userspace = opt_userspace;
	config.jul = opt_jul;
	config.log4j = opt_log4j;
	config.log4j2 = opt_log4j2;
	config.python = opt_python;
	config.domain = opt_domain;
	config.fields = opt_fields;
	config.syscall = opt_syscall;
	config.stream_info_details = opt_stream_info_details;
	return config;
}

} /* namespace */

/*
 * The 'list <options>' first level command
 */
int cmd_list(int argc, const char **argv)
{
	try {
		if (const auto config = make_config(argc, argv)) {
			/* Actual command */
			if (lttng_opt_mi) {
				return list_mi(*config);
			} else {
				return list_human(*config);
			}
		} else {
			/* Help/usage/options */
			return CMD_SUCCESS;
		}
	} catch (const undefined_opt&) {
		return CMD_UNDEFINED;
	} catch (const std::exception& e) {
		ERR_FMT("Failed to list: {}", e.what());
		return CMD_ERROR;
	}
}
