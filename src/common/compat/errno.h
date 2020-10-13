/*
 * Copyright (C) 2020 Michael Jeanson <mjeanson@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef _COMPAT_ERRNO_H
#define _COMPAT_ERRNO_H

#include <errno.h>

/* Missing on FreeBSD */
#ifndef ENODATA
#define ENODATA ENOATTR
#endif

#endif /* _COMPAT_ERRNO_H */
