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
	struct lttng_channel channel;
	struct lttng_event ev1, ev2, ev3;
	char *session_name = "ust_global_event_basic";
	int ret = 0;

	memset(&dom, 0, sizeof(dom));
	memset(&channel, 0, sizeof(channel));
	memset(&ev1, 0, sizeof(ev1));
	memset(&ev2, 0, sizeof(ev2));
	memset(&ev3, 0, sizeof(ev3));

	dom.type = LTTNG_DOMAIN_UST;
	strcpy(channel.name, "mychan");
	channel.attr.overwrite = 0;
	channel.attr.subbuf_size = 4096;
	channel.attr.num_subbuf = 4;
	channel.attr.switch_timer_interval = 0;
	channel.attr.read_timer_interval = 200;
	channel.attr.output = LTTNG_EVENT_MMAP;

	strcpy(ev1.name, "tp1");
	ev1.type = LTTNG_EVENT_TRACEPOINT;
	ev1.loglevel_type = LTTNG_EVENT_LOGLEVEL_ALL;

	strcpy(ev2.name, "ev2");
	ev2.type = LTTNG_EVENT_TRACEPOINT;
	ev2.loglevel_type = LTTNG_EVENT_LOGLEVEL_ALL;

	strcpy(ev3.name, "ev3");
	ev3.type = LTTNG_EVENT_TRACEPOINT;
	ev3.loglevel_type = LTTNG_EVENT_LOGLEVEL_ALL;

	printf("\nTesting tracing UST events:\n");
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

	printf("Enabling %s UST channel: ", channel.name);
	if ((ret = lttng_enable_channel(handle, &channel)) < 0) {
		printf("error enable channel: %s\n", lttng_strerror(ret));
		goto enable_fail;
	}
	PRINT_OK();

	printf("Enabling %s UST event: ", ev1.name);
	if ((ret = lttng_enable_event(handle, &ev1, channel.name)) < 0) {
		printf("error enabling event: %s\n", lttng_strerror(ret));
		goto enable_fail;
	}
	PRINT_OK();

	printf("Enabling %s UST event: ", ev2.name);
	if ((ret = lttng_enable_event(handle, &ev2, channel.name)) < 0) {
		printf("error enabling event: %s\n", lttng_strerror(ret));
		goto enable_fail;
	}
	PRINT_OK();

	printf("Enabling %s UST event: ", ev3.name);
	if ((ret = lttng_enable_event(handle, &ev3, channel.name)) < 0) {
		printf("error enabling event: %s\n", lttng_strerror(ret));
		goto enable_fail;
	}
	PRINT_OK();

	printf("Disabling %s UST event: ", ev1.name);
	if ((ret = lttng_disable_event(handle, ev1.name, channel.name)) < 0) {
		printf("error enabling event: %s\n", lttng_strerror(ret));
		goto enable_fail;
	}
	PRINT_OK();

	printf("Disabling %s UST event: ", ev3.name);
	if ((ret = lttng_disable_event(handle, ev3.name, channel.name)) < 0) {
		printf("error enabling event: %s\n", lttng_strerror(ret));
		goto enable_fail;
	}
	PRINT_OK();

	printf("Renabling %s UST event: ", ev1.name);
	if ((ret = lttng_enable_event(handle, &ev1, channel.name)) < 0) {
		printf("error enabling event: %s\n", lttng_strerror(ret));
		goto enable_fail;
	}
	PRINT_OK();

	printf("Renabling %s UST event: ", ev3.name);
	if ((ret = lttng_enable_event(handle, &ev3, channel.name)) < 0) {
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

	printf("Restart tracing: ");
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
