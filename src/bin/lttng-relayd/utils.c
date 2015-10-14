/*
 * Copyright (C) 2013 - Julien Desfossez <jdesfossez@efficios.com>
 *                      David Goulet <dgoulet@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define _LGPL_SOURCE
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <common/common.h>
#include <common/defaults.h>
#include <common/utils.h>

#include "lttng-relayd.h"
#include "utils.h"

static char *create_output_path_auto(char *path_name)
{
	int ret;
	char *traces_path = NULL;
	char *alloc_path = NULL;
	char *default_path;

	default_path = utils_get_home_dir();
	if (default_path == NULL) {
		ERR("Home path not found.\n \
				Please specify an output path using -o, --output PATH");
		goto exit;
	}
	alloc_path = strdup(default_path);
	if (alloc_path == NULL) {
		PERROR("Path allocation");
		goto exit;
	}
	ret = asprintf(&traces_path, "%s/" DEFAULT_TRACE_DIR_NAME
			"/%s", alloc_path, path_name);
	if (ret < 0) {
		PERROR("asprintf trace dir name");
		goto exit;
	}
exit:
	free(alloc_path);
	return traces_path;
}

static char *create_output_path_noauto(char *path_name)
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
char *create_output_path(char *path_name)
{
	assert(path_name);

	if (opt_output_path == NULL) {
		return create_output_path_auto(path_name);
	} else {
		return create_output_path_noauto(path_name);
	}
}
