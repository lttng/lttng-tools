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

#ifndef LTTNG_DOMAIN_H
#define LTTNG_DOMAIN_H

#ifdef __cplusplus
extern "C" {
#endif

#include <lttng/constant.h>

/*
 * Domain types: the different possible tracers.
 */
enum lttng_domain_type {
	LTTNG_DOMAIN_NONE                     = 0,	/* No associated domain. */
	LTTNG_DOMAIN_KERNEL                   = 1,	/* Linux Kernel tracer. */
	LTTNG_DOMAIN_UST                      = 2,	/* Global Userspace tracer. */
	LTTNG_DOMAIN_JUL                      = 3,	/* Java Util Logging. */
	LTTNG_DOMAIN_LOG4J                    = 4,	/* Java Log4j Framework. */
	LTTNG_DOMAIN_PYTHON                   = 5,	/* Python logging Framework. */
};

/* Buffer type for a specific domain. */
enum lttng_buffer_type {
	LTTNG_BUFFER_PER_PID,	/* Only supported by UST being the default. */
	LTTNG_BUFFER_PER_UID,	/* Only supported by UST. */
	LTTNG_BUFFER_GLOBAL,	/* Only supported by the Kernel. */
};

/*
 * The structures should be initialized to zero before use.
 */
#define LTTNG_DOMAIN_PADDING1              12
#define LTTNG_DOMAIN_PADDING2              LTTNG_SYMBOL_NAME_LEN + 32
struct lttng_domain {
	enum lttng_domain_type type;
	enum lttng_buffer_type buf_type;
	char padding[LTTNG_DOMAIN_PADDING1];

	union {
		pid_t pid;
		char exec_name[LTTNG_NAME_MAX];
		char padding[LTTNG_DOMAIN_PADDING2];
	} attr;
};

/*
 * List the registered domain(s) of a session.
 *
 * Session name CAN NOT be NULL.
 *
 * Return the size (number of entries) of the "lttng_domain" array. Caller
 * must free domains. On error, a negative LTTng error code is returned.
 */
extern int lttng_list_domains(const char *session_name,
		struct lttng_domain **domains);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_DOMAIN_H */
