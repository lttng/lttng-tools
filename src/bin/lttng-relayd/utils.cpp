/*
 * Copyright (C) 2013 Julien Desfossez <jdesfossez@efficios.com>
 * Copyright (C) 2013 David Goulet <dgoulet@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include "lttng-relayd.hpp"
#include "utils.hpp"

#include <common/common.hpp>
#include <common/defaults.hpp>
#include <common/path.hpp>
#include <common/utils.hpp>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *create_output_path_auto(const char *path_name)
{
	int ret;
	char *traces_path = NULL;
	const char *default_path;

	default_path = utils_get_home_dir();
	if (default_path == NULL) {
		ERR("Home path not found.\n \
				Please specify an output path using -o, --output PATH");
		goto exit;
	}
	ret = asprintf(&traces_path, "%s/" DEFAULT_TRACE_DIR_NAME "/%s", default_path, path_name);
	if (ret < 0) {
		PERROR("asprintf trace dir name");
		goto exit;
	}
exit:
	return traces_path;
}

static char *create_output_path_noauto(const char *path_name)
{
	int ret;
	char *traces_path = NULL;
	char *full_path;

	full_path = utils_expand_path(opt_output_path);
	if (!full_path) {
		goto exit;
	}

	ret = asprintf(&traces_path, "%s/%s", full_path, path_name);
	if (ret < 0) {
		PERROR("asprintf trace dir name");
		goto exit;
	}
exit:
	free(full_path);
	return traces_path;
}

/*
 * Create the output trace directory path name string.
 *
 * Return the allocated string containing the path name or else NULL.
 */
char *create_output_path(const char *path_name)
{
	LTTNG_ASSERT(path_name);

	if (opt_output_path == NULL) {
		return create_output_path_auto(path_name);
	} else {
		return create_output_path_noauto(path_name);
	}
}
