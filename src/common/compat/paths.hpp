/*
 * Copyright (C) 2015 Michael Jeanson <mjeanson@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef _COMPAT_PATHS_H
#define _COMPAT_PATHS_H

#ifdef HAVE_PATHS_H
#include <paths.h>
#else
#define _PATH_DEVNULL "/dev/null"
#endif

#endif /* _COMPAT_PATHS_H */
