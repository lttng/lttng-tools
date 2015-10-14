/*
 * ust-ctl.h
 *
 * Meta header used to include all relevant file from the lttng ust ABI.
 *
 * Copyright (C) 2013 - David Goulet <dgoulet@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef LTTNG_UST_CTL_H
#define LTTNG_UST_CTL_H

struct ust_app;

/*
 * FIXME: temporary workaround: we use a lttng-tools local version of
 * lttng-ust-abi.h if UST is not found. Eventually, we should use our
 * own internal structures within lttng-tools instead of relying on the
 * UST ABI.
 */
#ifdef HAVE_LIBLTTNG_UST_CTL

#include <lttng/ust-ctl.h>
#include <lttng/ust-abi.h>
#include <lttng/ust-error.h>

int ust_app_release_object(struct ust_app *app, struct lttng_ust_object_data *data);

#else /* HAVE_LIBLTTNG_UST_CTL */

#include "lttng-ust-ctl.h"
#include "lttng-ust-abi.h"
#include "lttng-ust-error.h"

static inline
int ust_app_release_object(struct ust_app *app, struct lttng_ust_object_data *data)
{
	return 0;
}

#endif /* HAVE_LIBLTTNG_UST_CTL */

#endif /* _LTT_UST_CTL_H */
