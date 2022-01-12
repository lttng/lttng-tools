/*
 * Copyright (C) 2011 David Goulet <dgoulet@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
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
