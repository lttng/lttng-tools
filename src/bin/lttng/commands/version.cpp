/*
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include "../command.hpp"
#include "version.hpp"

#include <common/mi-lttng.hpp>
#include <common/mint.hpp>

#include <algorithm>
#include <limits>
#include <popt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef LTTNG_EMBED_HELP
static const char help_msg[] =
#include <lttng-version.1.h>
	;
#endif

namespace {

/*
 * Returns the wrap width: minimum of 80 and the terminal width.
 *
 * If terminal width cannot be determined, returns 80.
 */
std::size_t get_wrap_width() noexcept
{
	constexpr std::size_t default_width = 80;
	struct winsize ws;

	if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0) {
		return std::min(static_cast<std::size_t>(ws.ws_col), default_width);
	}

	return default_width;
}

/*
 * Wraps text at word boundaries to fit within `width` columns.
 *
 * Handles embedded newlines (\n) by starting a new line.
 * Double newlines (\n\n) result in a blank line (paragraph break).
 */
std::string wrap_text(const char *text, std::size_t width)
{
	std::string result;
	std::size_t current_line_len = 0;
	const char *word_start = text;

	while (*word_start != '\0') {
		/* Handle newlines */
		if (*word_start == '\n') {
			result += '\n';
			current_line_len = 0;
			++word_start;
			continue;
		}

		/* Skip leading spaces at the start of a line */
		if (current_line_len == 0) {
			while (*word_start == ' ') {
				++word_start;
			}

			if (*word_start == '\0') {
				break;
			}
		}

		/* Find end of current word */
		const char *word_end = word_start;

		while (*word_end != '\0' && *word_end != ' ' && *word_end != '\n') {
			++word_end;
		}

		const std::size_t word_len = word_end - word_start;

		/* Check if the word fits on the current line */
		if (current_line_len > 0 && current_line_len + 1 + word_len > width) {
			/* Start a new line */
			result += '\n';
			current_line_len = 0;
		}

		/* Add space between words on the same line */
		if (current_line_len > 0) {
			result += ' ';
			++current_line_len;
		}

		/* Add the word */
		result.append(word_start, word_len);
		current_line_len += word_len;

		/* Move to next word */
		word_start = word_end;

		/* Skip spaces between words (but not newlines) */
		while (*word_start == ' ') {
			++word_start;
		}
	}

	return result;
}

} /* namespace */

enum {
	OPT_HELP = 1,
	OPT_LIST_OPTIONS,
};

static const char *lttng_license = "lttng is free software and under the GPL license and part LGPL";

static struct poptOption long_options[] = {
	/* longName, shortName, argInfo, argPtr, value, descrip, argDesc */
	{ "help", 'h', POPT_ARG_NONE, nullptr, OPT_HELP, nullptr, nullptr },
	{ "list-options", 0, POPT_ARG_NONE, nullptr, OPT_LIST_OPTIONS, nullptr, nullptr },
	{ nullptr, 0, 0, nullptr, 0, nullptr, nullptr }
};

/*
 *  create_version
 */
static void create_version(struct mi_lttng_version_data *version)
{
	strncpy(version->version, VERSION, NAME_MAX);
	version->version_major = VERSION_MAJOR;
	version->version_minor = VERSION_MINOR;
	version->version_patchlevel = VERSION_PATCHLEVEL;
	strncpy(version->version_commit, GIT_VERSION, NAME_MAX);
	strncpy(version->version_name, VERSION_NAME, NAME_MAX);
	strncpy(version->package_url, PACKAGE_URL, NAME_MAX);
}

/*
 * Print the machine interface output of this command.
 */
static int print_mi()
{
	int ret = CMD_SUCCESS;
	struct mi_writer *writer = nullptr;
	struct mi_lttng_version_data version;

	create_version(&version);

	writer = mi_lttng_writer_create(fileno(stdout), lttng_opt_mi);
	if (!writer) {
		ret = -LTTNG_ERR_NOMEM;
		goto end;
	}

	/* Open the command element */
	ret = mi_lttng_writer_command_open(writer, mi_lttng_element_command_version);
	if (ret) {
		ret = CMD_ERROR;
		goto error;
	}

	/* Beginning of output */
	ret = mi_lttng_writer_open_element(writer, mi_lttng_element_command_output);
	if (ret) {
		ret = CMD_ERROR;
		goto error;
	}

	/* Print the machine interface of version */
	ret = mi_lttng_version(writer, &version, VERSION_DESCRIPTION, lttng_license);
	if (ret) {
		ret = CMD_ERROR;
		goto error;
	}

	/* Close the output element */
	ret = mi_lttng_writer_close_element(writer);
	if (ret) {
		ret = CMD_ERROR;
		goto error;
	}

	/* Close the command  */
	ret = mi_lttng_writer_command_close(writer);
	if (ret) {
		ret = CMD_ERROR;
	}

error:
	/* Cleanup */
	if (writer && mi_lttng_writer_destroy(writer)) {
		/* Preserve original error code */
		ret = ret ? ret : -LTTNG_ERR_MI_IO_FAIL;
	}

end:
	return ret;
}

/*
 *  cmd_version
 */
int cmd_version(int argc, const char **argv)
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

	if (lttng_opt_mi) {
		ret = print_mi();
	} else {
		lttng::mint_print("lttng version [!]{}[/] - [*b!]{}[/]", VERSION, VERSION_NAME);

		if (GIT_VERSION[0] != '\0') {
			lttng::mint_print(" - [*y]{}[/]", GIT_VERSION);
		}

		const auto wrapped_description = wrap_text(VERSION_DESCRIPTION, get_wrap_width());

		lttng::mint_print("\n\n[c]{}[/]\n\n"
				  "[!]Web site[/]: https://lttng.org\n\n",
				  wrapped_description);
		lttng::mint_print("[-]{}[/]\n", lttng_license);

		if (EXTRA_VERSION_NAME[0] != '\0' || EXTRA_VERSION_DESCRIPTION[0] != '\0' ||
		    EXTRA_VERSION_PATCHES[0] != '\0') {
			if (EXTRA_VERSION_NAME[0] != '\0') {
				lttng::mint_print("\n[!]Extra version name[/]: {}",
						  EXTRA_VERSION_NAME);
			}
			if (EXTRA_VERSION_DESCRIPTION[0] != '\0') {
				lttng::mint_print("\n[!]Extra version description[/]: {}",
						  EXTRA_VERSION_DESCRIPTION);
			}
			if (EXTRA_VERSION_PATCHES[0] != '\0') {
				lttng::mint_print("\n[!]Extra version patches[/]: {}",
						  EXTRA_VERSION_PATCHES);
			}

			lttng::print("\n");
		}
	}

end:
	poptFreeContext(pc);
	return ret;
}
