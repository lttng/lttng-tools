#ifndef _COMPAT_GETENV_H
#define _COMPAT_GETENV_H

/*
 * Copyright (C) 2015 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <common/error.h>

static inline
int lttng_is_setuid_setgid(void)
{
	return geteuid() != getuid() || getegid() != getgid();
}

static inline
char *lttng_secure_getenv(const char *name)
{
	if (lttng_is_setuid_setgid()) {
		WARN("Getting environment variable '%s' from setuid/setgid binary refused for security reasons.",
			name);
		return NULL;
	}
	return getenv(name);
}

#endif /* _COMPAT_GETENV_H */
