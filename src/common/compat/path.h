/*
 * Copyright (C) 2020 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

/* Build platform's preferred path separator. */
#if defined(_WIN32) || defined(__CYGWIN__)
#define LTTNG_PATH_SEPARATOR '\\'
#else
#define LTTNG_PATH_SEPARATOR '/'
#endif
