/*
 * SPDX-FileCopyrightText: 2020 Michael Jeanson <mjeanson@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
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
