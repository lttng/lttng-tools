/*
 * Copyright (C) 2021 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef _COMMON_PATH_H
#define _COMMON_PATH_H

char *utils_expand_path(const char *path);
char *utils_expand_path_keep_symlink(const char *path);

#endif /* _COMMON_PATH_H */
