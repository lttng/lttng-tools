/*
 * Copyright (C) 2014 - David Goulet <dgoulet@efficios.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License, version 2.1 only,
 * as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef LTTNG_HANDLE_H
#define LTTNG_HANDLE_H

#include <lttng/domain.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Handle used as a context for commands.
 *
 * The structures should be initialized to zero before use.
 */
#define LTTNG_HANDLE_PADDING1              16
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
extern struct lttng_handle *lttng_create_handle(const char *session_name,
		struct lttng_domain *domain);

/*
 * Destroy an handle that has been previously created with lttng_create_handle.
 *
 * It free the given pointer making it unusable.
 */
extern void lttng_destroy_handle(struct lttng_handle *handle);


#ifdef __cplusplus
}
#endif

#endif /* LTTNG_HANDLE_H */
