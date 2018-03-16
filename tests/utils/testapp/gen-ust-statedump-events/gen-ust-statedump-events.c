/*
 * Copyright (C) - 2018 Geneviève Bastien <gbastien@versatic.net>
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

#define _LGPL_SOURCE
#include <assert.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdbool.h>
#include <signal.h>
#include <poll.h>
#include <errno.h>
#include <lttng/statedump-notifier.h>
#include "utils.h"
#include "signal-helper.h"

#define TRACEPOINT_DEFINE
#define TRACEPOINT_CREATE_PROBES
#define TP_SESSION_CHECK
#include "../gen-ust-statedump-events/tp.h"

static struct lttng_ust_notifier notifier;

static void notifier_cb(struct lttng_session *session, void *priv)
{
	/* This file synchronizes with test control to make sure the statedump ran */
	char *statedump_done_file = (char *) priv;
	tracepoint(tp, tpteststdmp, session, 123, "test string");
	tracepoint(tp, tpteststdmp, session, 444, "another string");
	if (statedump_done_file) {
		// Somebody may be waiting on this thread, how to tell it if file creation went wrong?
		create_file(statedump_done_file);
	}
}

int main(int argc, char **argv)
{
	int delay = 0;
	char *initialization_file = NULL;
	char *terminating_file = NULL;
	char *statedump_done_file = NULL;
	int ret = 0;

	if (set_signal_handler()) {
		ret = -1;
		goto end;
	}

	if (argc >= 2) {
		/* Set the application running time */
		delay = atoi(argv[1]);
	}
	if (argc >= 3) {
		statedump_done_file = argv[2];
	}
	if (argc >= 4) {
		initialization_file = argv[3];
	}
	if (argc >= 5) {
		terminating_file = argv[4];
	}

	lttng_ust_init_statedump_notifier(&notifier, notifier_cb, (void *) statedump_done_file);
	lttng_ust_register_statedump_notifier(&notifier);

	if (initialization_file) {
		ret = create_file(initialization_file);
		if (ret != 0) {
			goto end;
		}
	}

	if (delay >= 0) {
		sleep(delay);
	} else if (terminating_file) {
		ret = wait_on_file(terminating_file);
	} else {
		while (!should_quit) {
			sleep(1);
		}
	}

	lttng_ust_unregister_statedump_notifier(&notifier);

end:
	exit(!ret ? EXIT_SUCCESS : EXIT_FAILURE);
}
