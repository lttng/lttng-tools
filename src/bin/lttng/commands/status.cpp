/*
 * SPDX-FileCopyrightText: 2015 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include "../command.hpp"
#include "../utils.hpp"

#include <config.h>
#include <popt.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

#ifdef LTTNG_EMBED_HELP
static const char help_msg[] =
#include <lttng-status.1.h>
	;
#endif

static int opt_no_truncate;
static char *opt_mem_usage;
static char *opt_style;
static char *opt_channel;
static int opt_userspace;
static int opt_kernel;
static int opt_jul;
static int opt_log4j;
static int opt_log4j2;
static int opt_python;

enum {
	OPT_HELP = 1,
	OPT_LIST_OPTIONS,
};

static struct poptOption long_options[] = {
	/* longName, shortName, argInfo, argPtr, value, descrip, argDesc */
	{ "help", 'h', POPT_ARG_NONE, nullptr, OPT_HELP, nullptr, nullptr },
	{ "kernel", 'k', POPT_ARG_VAL, &opt_kernel, 1, nullptr, nullptr },
	{ "jul", 'j', POPT_ARG_VAL, &opt_jul, 1, nullptr, nullptr },
	{ "log4j", 'l', POPT_ARG_VAL, &opt_log4j, 1, nullptr, nullptr },
	{ "log4j2", 0, POPT_ARG_VAL, &opt_log4j2, 1, nullptr, nullptr },
	{ "python", 'p', POPT_ARG_VAL, &opt_python, 1, nullptr, nullptr },
	{ "userspace", 'u', POPT_ARG_VAL, &opt_userspace, 1, nullptr, nullptr },
	{ "channel", 'c', POPT_ARG_STRING, &opt_channel, 0, nullptr, nullptr },
	{ "no-truncate", 0, POPT_ARG_VAL, &opt_no_truncate, 1, nullptr, nullptr },
	{ "mem-usage", 0, POPT_ARG_STRING, &opt_mem_usage, 0, nullptr, nullptr },
	{ "style", 0, POPT_ARG_STRING, &opt_style, 0, nullptr, nullptr },
	{ "list-options", 0, POPT_ARG_NONE, nullptr, OPT_LIST_OPTIONS, nullptr, nullptr },
	{ nullptr, 0, 0, nullptr, 0, nullptr, nullptr }
};

static int status()
{
	const auto session_name =
		lttng::make_unique_wrapper<char, lttng::memory::free>(get_session_name_quiet());

	if (!session_name) {
		return CMD_ERROR;
	}

	/* Build argv array for cmd_list */
	std::vector<const char *> argv;

	argv.push_back("list");
	argv.push_back(session_name.get());

	if (opt_kernel) {
		argv.push_back("--kernel");
	}

	if (opt_userspace) {
		argv.push_back("--userspace");
	}

	if (opt_jul) {
		argv.push_back("--jul");
	}

	if (opt_log4j) {
		argv.push_back("--log4j");
	}

	if (opt_log4j2) {
		argv.push_back("--log4j2");
	}

	if (opt_python) {
		argv.push_back("--python");
	}

	if (opt_channel) {
		argv.push_back("--channel");
		argv.push_back(opt_channel);
	}

	if (opt_no_truncate) {
		argv.push_back("--no-truncate");
	}

	if (opt_mem_usage) {
		argv.push_back("--mem-usage");
		argv.push_back(opt_mem_usage);
	}

	if (opt_style) {
		argv.push_back("--style");
		argv.push_back(opt_style);
	}

	return cmd_list(argv.size(), argv.data());
}

/*
 * The 'status <options>' first level command
 */
int cmd_status(int argc, const char **argv)
{
	int opt, ret = CMD_SUCCESS;
	static poptContext pc;

	pc = poptGetContext(nullptr, argc, argv, long_options, 0);
	poptReadDefaultConfig(pc, 0);

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case OPT_HELP:
			SHOW_HELP();
			goto end;
		case OPT_LIST_OPTIONS:
			list_cmd_options(stdout, long_options);
			goto end;
		default:
			ret = CMD_UNDEFINED;
			goto end;
		}
	}

	if (poptPeekArg(pc) != nullptr) {
		ERR("This command does not accept positional arguments.\n");
		ret = CMD_UNDEFINED;
		goto end;
	}

	ret = status();
end:
	poptFreeContext(pc);
	return ret;
}
