/*
 * SPDX-FileCopyrightText: 2013 Julien Desfossez <jdesfossez@efficios.com>
 * SPDX-FileCopyrightText: 2013 David Goulet <dgoulet@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include "lttng-relayd.hpp"
#include "utils.hpp"

#include <common/common.hpp>
#include <common/defaults.hpp>
#include <common/exception.hpp>
#include <common/path.hpp>
#include <common/utils.hpp>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *create_output_path_auto(const char *path_name)
{
	int ret;
	char *traces_path = nullptr;
	const char *default_path;

	default_path = utils_get_home_dir();
	if (default_path == nullptr) {
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
	char *traces_path = nullptr;
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

	if (opt_output_path == nullptr) {
		return create_output_path_auto(path_name);
	} else {
		return create_output_path_noauto(path_name);
	}
}

void create_lttng_rundir_with_perm(const char *rundir)
{
	DBG_FMT("Creating LTTng run directory: `{}`", rundir);

	const auto mkdir_ret = mkdir(rundir, S_IRWXU);
	if (mkdir_ret < 0) {
		if (errno != EEXIST) {
			LTTNG_THROW_POSIX(fmt::format("Failed to create rundir: path=`{}`", rundir),
					  errno);
		}
	}

	const auto is_root = !getuid();
	if (!is_root) {
		/* Nothing more to do. */
		return;
	}

	gid_t gid;
	const auto get_group_id_ret = utils_get_group_id(tracing_group_name, true, &gid);
	if (get_group_id_ret) {
		/* Default to root group. */
		gid = 0;
	}

	const auto chown_ret = chown(rundir, 0, gid);
	if (chown_ret < 0) {
		LTTNG_THROW_POSIX(
			fmt::format("Failed to set group on rundir: path=`{}`, group_id={}",
				    rundir,
				    gid),
			errno);
	}

	const auto permission_mask = S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH |
		S_IXOTH;
	const auto chmod_ret = chmod(rundir, permission_mask);
	if (chmod_ret < 0) {
		LTTNG_THROW_POSIX(
			fmt::format(
				"Failed to set permissions on rundir: path=`{}`, permission={:o}",
				rundir,
				permission_mask),
			errno);
	}
}
