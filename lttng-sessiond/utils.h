/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; only version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef _LTT_UTILS_H
#define _LTT_UTILS_H

#include <unistd.h>

#ifndef __stringify
#define __stringify1(x)	#x
#define __stringify(x)	__stringify1(x)
#endif

int mkdir_recursive_run_as(const char *path, mode_t mode, uid_t uid, gid_t gid);
int mkdir_run_as(const char *path, mode_t mode, uid_t uid, gid_t gid);
int open_run_as(const char *path, int flags, mode_t mode, uid_t uid, gid_t gid);

const char *get_home_dir(void);
int notify_thread_pipe(int wpipe);

#endif /* _LTT_UTILS_H */
