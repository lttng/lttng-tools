/*
 * Copyright (C) - 2018 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 */

#ifndef LTTNG_TESTAPP_SIGNAL_HELPER_H
#define LTTNG_TESTAPP_SIGNAL_HELPER_H

#include <signal.h>

static volatile int should_quit;

static
void sighandler(int sig)
{
	if (sig == SIGTERM) {
		should_quit = 1;
	}
}

static
int set_signal_handler(void)
{
	int ret;
	struct sigaction sa = {
		.sa_flags = 0,
		.sa_handler = sighandler,
	};

	ret = sigemptyset(&sa.sa_mask);
	if (ret) {
		perror("sigemptyset");
		goto end;
	}

	ret = sigaction(SIGTERM, &sa, NULL);
	if (ret) {
		perror("sigaction");
		goto end;
	}
end:
	return ret;
}

#endif /* LTTNG_TESTAPP_SIGNAL_HELPER_H */
