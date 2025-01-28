/*
 * SPDX-FileCopyrightText: 2020 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef _COMPAT_PATH_H
#define _COMPAT_PATH_H

/* Build platform's preferred path separator. */
#if defined(_WIN32) || defined(__CYGWIN__)
#define LTTNG_PATH_SEPARATOR '\\'
#else
#define LTTNG_PATH_SEPARATOR '/'
#endif

#endif /* _COMPAT_PATH_H */
