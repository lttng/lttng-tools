/*
 * Copyright (C) 2015 Michael Jeanson <mjeanson@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef _COMPAT_PATHS_H
#define _COMPAT_PATHS_H

#ifdef HAVE_PATHS_H
#include <paths.h>
#else
# define _PATH_DEVNULL "/dev/null"
#endif

#endif /* _COMPAT_PATHS_H */
