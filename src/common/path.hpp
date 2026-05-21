/*
 * SPDX-FileCopyrightText: 2021 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef _COMMON_PATH_H
#define _COMMON_PATH_H

#include <common/string-utils/c-string-view.hpp>

char *utils_expand_path(const char *path);
char *utils_expand_path_keep_symlink(const char *path);
char *utils_partial_realpath(const char *path);

/*
 * Return true if `path` can be used to walk up the directory hierarchy, that
 * is, if any of its '/'-separated components is exactly "..".
 */
bool utils_path_walks_up_hierarchy(lttng::c_string_view path) noexcept;

#endif /* _COMMON_PATH_H */
