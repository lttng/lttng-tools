/*
 * Copyright (C) 2021 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_UST_SIGBUS_H
#define LTTNG_UST_SIGBUS_H

#ifdef HAVE_LIBLTTNG_UST_CTL

void lttng_ust_handle_sigbus(void *address);

#else /* HAVE_LIBLTTNG_UST_CTL */

static inline void lttng_ust_handle_sigbus(void *address __attribute__((unused)))
{
}

#endif /* HAVE_LIBLTTNG_UST_CTL */

#endif /* LTTNG_UST_SIGBUS_H */
