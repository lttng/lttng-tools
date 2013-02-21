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

#include "utils.h"

int lttng_opt_quiet;

int main(int argc, char **argv)
{
	struct lttng_handle *handle = NULL;
	struct lttng_domain dom;
	struct lttng_channel channel, channel2;
	struct lttng_event ev1, ev2, ev3;
	struct lttng_event_context context;
	char *session_name = "ust_global_event_basic";
	char *session_name2 = "ust_global_event_basic2";
	int ret = 0;

	memset(&dom, 0, sizeof(dom));
	memset(&channel, 0, sizeof(channel));
	memset(&channel2, 0, sizeof(channel2));
	memset(&ev1, 0, sizeof(ev1));
	memset(&ev2, 0, sizeof(ev2));
	memset(&ev3, 0, sizeof(ev3));
	memset(&context, 0, sizeof(context));

	dom.type = LTTNG_DOMAIN_UST;

	/* Setup channel 1 */
	strcpy(channel.name, "mychan");
	channel.attr.overwrite = 0;
	channel.attr.subbuf_size = 4096;
	channel.attr.num_subbuf = 4;
	channel.attr.switch_timer_interval = 0;
	channel.attr.read_timer_interval = 200;
	channel.attr.output = LTTNG_EVENT_MMAP;

	/* Setup channel 2 */
	strcpy(channel2.name, "mychan2");
	channel2.attr.overwrite = 0;
	channel2.attr.subbuf_size = 8192;
	channel2.attr.num_subbuf = 8;
	channel2.attr.switch_timer_interval = 0;
	channel2.attr.read_timer_interval = 500;
	channel2.attr.output = LTTNG_EVENT_MMAP;

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

	printf("Creating tracing session 2 (%s): ", argv[1]);
	if ((ret = lttng_create_session(session_name2, argv[1])) < 0) {
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

	printf("Enabling %s UST channel2: ", channel2.name);
	if ((ret = lttng_enable_channel(handle, &channel2)) < 0) {
		printf("error enable channel: %s\n", lttng_strerror(ret));
		goto enable_fail;
	}
	PRINT_OK();

	printf("Enabling %s UST event in channel %s: ", ev1.name, channel.name);
	if ((ret = lttng_enable_event(handle, &ev1, channel.name)) < 0) {
		printf("error enabling event: %s\n", lttng_strerror(ret));
		goto enable_fail;
	}
	PRINT_OK();

	printf("Enabling %s UST event in channel %s: ", ev2.name, channel.name);
	if ((ret = lttng_enable_event(handle, &ev2, channel.name)) < 0) {
		printf("error enabling event: %s\n", lttng_strerror(ret));
		goto enable_fail;
	}
	PRINT_OK();

	printf("Enabling %s UST event in channel %s: ", ev3.name, channel2.name);
	if ((ret = lttng_enable_event(handle, &ev3, channel2.name)) < 0) {
		printf("error enabling event: %s\n", lttng_strerror(ret));
		goto enable_fail;
	}
	PRINT_OK();

	context.ctx = LTTNG_EVENT_CONTEXT_VPID;

	printf("Adding context VPID to UST event %s in channel %s: ", ev1.name,
			channel.name);
	if ((ret = lttng_add_context(handle, &context, ev1.name,
					channel.name)) < 0) {
		printf("error adding context VPID: %s\n", lttng_strerror(ret));
		goto context_fail;
	}
	PRINT_OK();

	context.ctx = LTTNG_EVENT_CONTEXT_VTID;

	printf("Adding context VTID to UST event %s in channel %s: ", ev1.name,
			channel.name);
	if ((ret = lttng_add_context(handle, &context, ev1.name,
					channel.name)) < 0) {
		printf("error adding context VTID: %s\n", lttng_strerror(ret));
		goto context_fail;
	}
	PRINT_OK();

	context.ctx = LTTNG_EVENT_CONTEXT_PTHREAD_ID;

	printf("Adding context PTHREAD_ID to UST event %s in channel %s: ",
			ev1.name, channel.name);
	if ((ret = lttng_add_context(handle, &context, ev1.name,
					channel.name)) < 0) {
		printf("error adding context PTHREAD_ID: %s\n", lttng_strerror(ret));
		goto context_fail;
	}
	PRINT_OK();

	context.ctx = LTTNG_EVENT_CONTEXT_PROCNAME;

	printf("Adding context PROCNAME to UST event %s in channel %s: ",
			ev1.name, channel.name);
	if ((ret = lttng_add_context(handle, &context, ev1.name,
					channel.name)) < 0) {
		printf("error adding context PROCNAME: %s\n", lttng_strerror(ret));
		goto context_fail;
	}
	PRINT_OK();

	context.ctx = LTTNG_EVENT_CONTEXT_PROCNAME;

	printf("Adding context PROCNAME to UST event %s in channel %s: ",
			ev3.name, channel2.name);
	if ((ret = lttng_add_context(handle, &context, ev3.name,
					channel2.name)) < 0) {
		printf("error adding context PROCNAME: %s\n", lttng_strerror(ret));
		goto context_fail;
	}
	PRINT_OK();

	printf("Disabling %s UST event: ", ev1.name);
	if ((ret = lttng_disable_event(handle, ev1.name, channel.name)) < 0) {
		printf("error enabling event: %s\n", lttng_strerror(ret));
		goto enable_fail;
	}
	PRINT_OK();

	printf("Disabling %s UST event: ", ev3.name);
	if ((ret = lttng_disable_event(handle, ev3.name, channel2.name)) < 0) {
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

	printf("Disabling channel %s: ", channel2.name);
	if ((ret = lttng_disable_channel(handle, channel2.name)) < 0) {
		printf("error disabling channel: %s\n", lttng_strerror(ret));
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

	printf("Destroy tracing session 2: ");
	if ((ret = lttng_destroy_session(session_name2)) < 0) {
		printf("error destroying session 2: %s\n", lttng_strerror(ret));
	}
	PRINT_OK();

	printf("Destroy tracing session: ");
	if ((ret = lttng_destroy_session(session_name)) < 0) {
		printf("error destroying session: %s\n", lttng_strerror(ret));
	}
	PRINT_OK();

	return 0;

handle_fail:
	assert(handle != NULL);
create_fail:
	assert(ret != 0);

stop_fail:
start_fail:
context_fail:
enable_fail:
	lttng_destroy_session(session_name2);
	lttng_destroy_session(session_name);
	lttng_destroy_handle(handle);

	return 1;
}
