/*
 * Copyright (C) 2013 David Goulet <dgoulet@efficios.com>
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

#ifndef LTTNG_CTL_HELPER_H
#define LTTNG_CTL_HELPER_H

#define _GNU_SOURCE
#include <stdio.h>

#include <common/sessiond-comm/sessiond-comm.h>
#include <lttng/lttng.h>

/*
 * NOTE: Every symbol in this helper header MUST be set to hidden so not to
 * polute the library name space. Use LTTNG_HIDDEN macro before declaring the
 * function in the C file.
 */

/* Copy helper functions. */
void lttng_ctl_copy_string(char *dst, const char *src, size_t len);
void lttng_ctl_copy_lttng_domain(struct lttng_domain *dst,
		struct lttng_domain *src);

/*
 * Sends the lttcomm message to the session daemon and fills buf of the
 * returned data is not NULL.
 *
 * Return the size of the received data on success or else a negative lttng
 * error code. If buf is NULL, 0 is returned on success.
 */
int lttng_ctl_ask_sessiond_varlen(struct lttcomm_session_msg *lsm,
		void *vardata, size_t varlen, void **buf);

/*
 * Use this if no variable length data needs to be sent.
 */
static inline
int lttng_ctl_ask_sessiond(struct lttcomm_session_msg *lsm, void **buf)
{
	return lttng_ctl_ask_sessiond_varlen(lsm, NULL, 0, buf);
}

int lttng_check_tracing_group(void);

#endif /* LTTNG_CTL_HELPER_H */
