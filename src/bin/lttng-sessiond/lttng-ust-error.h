/*
 * Copyright (C) 2019 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License only.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef LTTNG_UST_ERROR_H
#define LTTNG_UST_ERROR_H

#ifdef HAVE_LIBLTTNG_UST_CTL
#include <lttng/ust-error.h>
#else /* HAVE_LIBLTTNG_UST_CTL */
/* Use local copy of the LTTng-UST header. */
#include "ust-error-internal.h"
#endif /* HAVE_LIBLTTNG_UST_CTL */

#endif /* LTTNG_UST_ERROR_H */
