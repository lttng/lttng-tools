#ifndef _RUNAS_H
#define _RUNAS_H

/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *                      Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; only verion 2
 * of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#include <unistd.h>

int run_as_mkdir_recursive(const char *path, mode_t mode, uid_t uid, gid_t gid);
int run_as_mkdir(const char *path, mode_t mode, uid_t uid, gid_t gid);
int run_as_open(const char *path, int flags, mode_t mode, uid_t uid, gid_t gid);

#endif /* _RUNAS_H */
