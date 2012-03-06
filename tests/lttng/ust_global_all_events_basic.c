/*
 * Copyright (c)  2011 David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * as published by the Free Software Foundation; only version 2
 * of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include <lttng/lttng.h>

#include "../utils.h"

int lttng_opt_quiet;

int main(int argc, char **argv)
{
	struct lttng_handle *handle = NULL;
	struct lttng_domain dom;
	struct lttng_event event;
	char *channel_name = "channel0";
	char *session_name = "ust_global_all_events_basic";
	int ret = 0;

	memset(&dom, 0, sizeof(dom));
	memset(&event, 0, sizeof(event));
	dom.type = LTTNG_DOMAIN_UST;
	event.type = LTTNG_EVENT_TRACEPOINT;
	event.loglevel_type = LTTNG_EVENT_LOGLEVEL_ALL;

	printf("\nTesting tracing all UST events:\n");
	printf("-----------\n");

	if (argc < 2) {
		printf("Missing session trace path\n");
		return 1;
	}

	printf("Creating tracing session (%s): ", argv[1]);
	if ((ret = lttng_create_session(session_name, argv[1])) < 0) {
		printf("error creating the session : %s\n", lttng_strerror(ret));
		goto create_fail;
	}
	PRINT_OK();

	printf("Creating session handle: ");
	if ((handle = lttng_create_handle(session_name, &dom)) == NULL) {
		printf("error creating handle: %s\n", lttng_strerror(ret));
		goto handle_fail;
	}
	PRINT_OK();

	printf("Enabling all UST events: ");
	if ((ret = lttng_enable_event(handle, &event, channel_name)) < 0) {
		printf("error enabling event: %s\n", lttng_strerror(ret));
		goto enable_fail;
	}
	PRINT_OK();

	printf("Start tracing: ");
	if ((ret = lttng_start_tracing(session_name)) < 0) {
		printf("error starting tracing: %s\n", lttng_strerror(ret));
		goto start_fail;
	}
	PRINT_OK();

	sleep(2);

	printf("Stop tracing: ");
	if ((ret = lttng_stop_tracing(session_name)) < 0) {
		printf("error stopping tracing: %s\n", lttng_strerror(ret));
		goto stop_fail;
	}
	PRINT_OK();

	printf("Destroy tracing session: ");
	if ((ret = lttng_destroy_session(session_name)) < 0) {
		printf("error destroying session: %s\n", lttng_strerror(ret));
	}
	PRINT_OK();

	return 0;

create_fail:
	assert(ret != 0);
handle_fail:
	assert(handle != NULL);

stop_fail:
start_fail:
enable_fail:
	lttng_destroy_session(session_name);
	lttng_destroy_handle(handle);

	return 1;
}
