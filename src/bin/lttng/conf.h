/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _LTTNG_CONFIG_H
#define _LTTNG_CONFIG_H

#define CONFIG_FILENAME ".lttngrc"

void config_destroy(char *path);
void config_destroy_default(void);
int config_exists(const char *path);
int config_init(char *path);
int config_add_session_name(char *path, char *name);

/* Must free() the return pointer */
char *config_read_session_name(char *path);
char *config_read_session_name_quiet(char *path);
char *config_get_file_path(char *path);

#endif /* _LTTNG_CONFIG_H */
