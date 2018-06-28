#ifndef _RUNAS_STUB_H
#define _RUNAS_STUB_H

/*
 * Copyright (C) 2018 - Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <sys/types.h>
#include <stdint.h>

int run_as_mkdir_recursive(const char *path, mode_t mode, uid_t uid, gid_t gid)
{
	return -1;
}
int run_as_mkdir(const char *path, mode_t mode, uid_t uid, gid_t gid)
{
	return -1;
}
int run_as_open(const char *path, int flags, mode_t mode, uid_t uid, gid_t gid)
{
	return -1;
}
int run_as_unlink(const char *path, uid_t uid, gid_t gid)
{
	return -1;
}
int run_as_rmdir_recursive(const char *path, uid_t uid, gid_t gid)
{
	return -1;
}
int lttng_elf_get_symbol_offset(int fd, char *symbol, uint64_t *offset)
{
	return -1;
}
int run_as_create_worker(char *procname)
{
	return -1;
}
void run_as_destroy_worker(void)
{
	return;
}

#endif /* _RUNAS_STUB_H */
