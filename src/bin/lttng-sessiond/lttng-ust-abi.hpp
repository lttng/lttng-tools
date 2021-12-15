/*
 * Copyright (C) 2019 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_UST_ABI_H
#define LTTNG_UST_ABI_H

#ifdef HAVE_LIBLTTNG_UST_CTL
#include <lttng/ust-abi.h>
#else /* HAVE_LIBLTTNG_UST_CTL */
/* Use local copy of the LTTng-UST header. */
#include "ust-abi-internal.hpp"
#endif /* HAVE_LIBLTTNG_UST_CTL */

#endif /* LTTNG_UST_ABI_H */
