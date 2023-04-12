/*
 * Copyright (C) 2014 David Goulet <dgoulet@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_HANDLE_H
#define LTTNG_HANDLE_H

#include <lttng/domain.h>
#include <lttng/lttng-export.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Handle used as a context for commands.
 *
 * The structures should be initialized to zero before use.
 */
#define LTTNG_HANDLE_PADDING1 16
struct lttng_handle {
	char session_name[LTTNG_NAME_MAX];
	struct lttng_domain domain;

	char padding[LTTNG_HANDLE_PADDING1];
};

/*
 * Create an handle used as a context for every request made to the library.
 *
 * This handle contains the session name and domain on which the command will
 * be executed. A domain is basically a tracer like the kernel or user space.
 *
 * A NULL domain indicates that the handle is not bound to a specific domain.
 * This is mostly used for actions that apply on a session and not on a domain
 * (e.g lttng_set_consumer_url).
 *
 * Return a newly allocated handle that should be freed using
 * lttng_destroy_handle. On error, NULL is returned.
 */
LTTNG_EXPORT extern struct lttng_handle *lttng_create_handle(const char *session_name,
							     struct lttng_domain *domain);

/*
 * Destroy an handle that has been previously created with lttng_create_handle.
 *
 * It free the given pointer making it unusable.
 */
LTTNG_EXPORT extern void lttng_destroy_handle(struct lttng_handle *handle);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_HANDLE_H */
