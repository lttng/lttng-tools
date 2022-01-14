/*
 * Copyright (C) 2011 EfficiOS Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef _LTTNG_CONFIG_H
#define _LTTNG_CONFIG_H

#define CONFIG_FILENAME ".lttngrc"

void config_destroy(const char *path);
void config_destroy_default(void);
int config_exists(const char *path);
int config_init(const char *path);
int config_add_session_name(const char *path, const char *name);

/* Must free() the return pointer */
char *config_read_session_name(const char *path);
char *config_read_session_name_quiet(const char *path);
char *config_get_file_path(const char *path);

#endif /* _LTTNG_CONFIG_H */
