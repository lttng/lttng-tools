/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; only version 2
 * of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef _LTT_UST_CTL_H
#define _LTT_UST_CTL_H

#include <lttng/lttng.h>

#include "trace-ust.h"

#ifdef CONFIG_LTTNG_TOOLS_HAVE_UST

int ustctl_register_done(int sock);
int ustctl_create_channel(int sock, struct ltt_ust_session *session,
		struct lttng_channel *channel);
int ustctl_create_session(int sock, struct ltt_ust_session *session);
int ustctl_destroy_session(int sock, struct ltt_ust_session *session);
int ustctl_disable_channel(int sock, struct ltt_ust_session *session,
		struct ltt_ust_channel *chan);
int ustctl_enable_channel(int sock, struct ltt_ust_session *session,
		struct ltt_ust_channel *chan);

#else

static inline
int ustctl_register_done(int sock)
{
	return -ENOSYS;
}
static inline
int ustctl_create_channel(int sock, struct ltt_ust_session *session,
		struct lttng_channel *channel)
{
	return -ENOSYS;
}
static inline
int ustctl_create_session(int sock, struct ltt_ust_session *session)
{
	return -ENOSYS;
}
static inline
int ustctl_destroy_session(int sock, struct ltt_ust_session *session)
{
	return -ENOSYS;
}
static inline
int ustctl_disable_channel(int sock, struct ltt_ust_session *session,
		struct ltt_ust_channel *chan)
{
	return -ENOSYS;
}
static inline
int ustctl_enable_channel(int sock, struct ltt_ust_session *session,
		struct ltt_ust_channel *chan)
{
	return -ENOSYS;
}

#endif

#endif /* _LTT_UST_CTL_H */
