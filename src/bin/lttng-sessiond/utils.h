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

#ifndef _LTT_UTILS_H
#define _LTT_UTILS_H

const char *get_home_dir(void);
int notify_thread_pipe(int wpipe);
int utils_create_pipe_cloexec(int *dst);
int utils_create_pipe(int *dst);
void utils_close_pipe(int *src);

#endif /* _LTT_UTILS_H */
