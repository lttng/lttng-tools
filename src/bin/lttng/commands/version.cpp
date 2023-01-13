/*
 * Copyright (C) 2011 EfficiOS Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include "../command.hpp"
#include "version.hpp"

#include <common/mi-lttng.hpp>

#include <popt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef LTTNG_EMBED_HELP
static const char help_msg[] =
#include <lttng-version.1.h>
	;
#endif

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
		MSG("lttng version " VERSION " - " VERSION_NAME "%s",
		    GIT_VERSION[0] == '\0' ? "" : " - " GIT_VERSION);
		MSG("\n" VERSION_DESCRIPTION "\n");
		MSG("Web site: https://lttng.org");
		MSG("\n%s", lttng_license);
		if (EXTRA_VERSION_NAME[0] != '\0') {
			MSG("\nExtra version name: " EXTRA_VERSION_NAME);
		}
		if (EXTRA_VERSION_DESCRIPTION[0] != '\0') {
			MSG("\nExtra version description:\n\t" EXTRA_VERSION_DESCRIPTION);
		}
		if (EXTRA_VERSION_PATCHES[0] != '\0') {
			MSG("\nExtra version patches:\n\t" EXTRA_VERSION_PATCHES);
		}
	}

end:
	poptFreeContext(pc);
	return ret;
}
