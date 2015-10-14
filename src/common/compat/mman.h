/*
 * Copyright (C) 2011 - David Goulet <dgoulet@efficios.com>
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

#ifndef _COMPAT_MMAN_H
#define _COMPAT_MMAN_H

#include <sys/mman.h>

#ifdef __linux__

#elif defined(__FreeBSD__)

#define MAP_GROWSDOWN 0
#define MAP_ANONYMOUS MAP_ANON

#elif defined(__CYGWIN__) || defined(__sun__)

#define MAP_GROWSDOWN 0

#else
#error "Please add support for your OS."
#endif /* __linux__ */

#endif /* _COMPAT_MMAN_H */
