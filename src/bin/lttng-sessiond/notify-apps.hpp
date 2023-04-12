/*
 * Copyright (C) 2013 David Goulet <dgoulet@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef UST_THREAD_H
#define UST_THREAD_H

#ifdef HAVE_LIBLTTNG_UST_CTL

bool launch_application_notification_thread(int apps_cmd_notify_pipe_read_fd);

#else /* HAVE_LIBLTTNG_UST_CTL */

static bool launch_application_notification_thread(int apps_cmd_notify_pipe_read_fd
						   __attribute__((unused)))
{
	return true;
}

#endif /* HAVE_LIBLTTNG_UST_CTL */

#endif /* UST_THREAD_H */
