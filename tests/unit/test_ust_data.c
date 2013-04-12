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
#include <bin/lttng-sessiond/lttng-ust-abi.h>
#include <common/defaults.h>
#include <bin/lttng-sessiond/trace-ust.h>
#include <bin/lttng-sessiond/ust-app.h>

#include <tap/tap.h>

#include "utils.h"

/* This path will NEVER be created in this test */
#define PATH1 "/tmp/.test-junk-lttng"

#define RANDOM_STRING_LEN	11

/* Number of TAP tests in this file */
#define NUM_TESTS 10

/* For lttngerr.h */
int lttng_opt_quiet = 1;
int lttng_opt_verbose;

int ust_consumerd32_fd;
int ust_consumerd64_fd;

static const char alphanum[] =
	"0123456789"
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyz";
static char random_string[RANDOM_STRING_LEN];

static struct ltt_ust_session *usess;
static struct lttng_domain dom;

/*
 * Return random string of 10 characters.
 * Not thread-safe.
 */
static char *get_random_string(void)
{
	int i;

	for (i = 0; i < RANDOM_STRING_LEN - 1; i++) {
		random_string[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
	}

	random_string[RANDOM_STRING_LEN - 1] = '\0';

	return random_string;
}

static void test_create_one_ust_session(void)
{
	dom.type = LTTNG_DOMAIN_UST;

	usess = trace_ust_create_session(42);
	ok(usess != NULL, "Create UST session");

	ok(usess->id == 42 &&
	   usess->start_trace == 0 &&
	   usess->domain_global.channels != NULL &&
	   usess->uid == 0 &&
	   usess->gid == 0,
	   "Validate UST session");

	trace_ust_destroy_session(usess);
}

static void test_create_ust_metadata(void)
{
	struct ltt_ust_metadata *metadata;

	assert(usess != NULL);

	metadata = trace_ust_create_metadata(PATH1);
	ok(metadata != NULL, "Create UST metadata");

	ok(metadata->handle == -1 &&
	   strlen(metadata->pathname) &&
	   metadata->attr.overwrite
			== DEFAULT_CHANNEL_OVERWRITE &&
	   metadata->attr.subbuf_size
			== default_get_metadata_subbuf_size() &&
	   metadata->attr.num_subbuf
			== DEFAULT_METADATA_SUBBUF_NUM &&
	   metadata->attr.switch_timer_interval
			== DEFAULT_UST_CHANNEL_SWITCH_TIMER &&
	   metadata->attr.read_timer_interval
			== DEFAULT_UST_CHANNEL_READ_TIMER &&
	   metadata->attr.output == LTTNG_UST_MMAP,
	   "Validate UST session metadata");

	trace_ust_destroy_metadata(metadata);
}

static void test_create_ust_channel(void)
{
	struct ltt_ust_channel *uchan;
	struct lttng_channel attr;

	memset(&attr, 0, sizeof(attr));

	strncpy(attr.name, "channel0", 8);

	uchan = trace_ust_create_channel(&attr);
	ok(uchan != NULL, "Create UST channel");

	ok(uchan->enabled == 0 &&
	   strncmp(uchan->name, "channel0", 8) == 0 &&
	   uchan->name[LTTNG_UST_SYM_NAME_LEN - 1] == '\0' &&
	   uchan->ctx != NULL &&
	   uchan->events != NULL &&
	   uchan->attr.overwrite  == attr.attr.overwrite,
	   "Validate UST channel");

	trace_ust_destroy_channel(uchan);
}

static void test_create_ust_event(void)
{
	struct ltt_ust_event *event;
	struct lttng_event ev;

	memset(&ev, 0, sizeof(ev));
	strncpy(ev.name, get_random_string(), LTTNG_SYMBOL_NAME_LEN);
	ev.type = LTTNG_EVENT_TRACEPOINT;
	ev.loglevel_type = LTTNG_EVENT_LOGLEVEL_ALL;

	event = trace_ust_create_event(&ev, NULL);

	ok(event != NULL, "Create UST event");

	ok(event->enabled == 0 &&
	   event->attr.instrumentation == LTTNG_UST_TRACEPOINT &&
	   strcmp(event->attr.name, ev.name) == 0 &&
	   event->attr.name[LTTNG_UST_SYM_NAME_LEN - 1] == '\0',
	   "Validate UST event");

	trace_ust_destroy_event(event);
}

static void test_create_ust_context(void)
{
	struct lttng_event_context ectx;
	struct ltt_ust_context *uctx;

	ectx.ctx = LTTNG_EVENT_CONTEXT_VTID;

	uctx = trace_ust_create_context(&ectx);
	ok(uctx != NULL, "Create UST context");

	ok((int) uctx->ctx.ctx == LTTNG_UST_CONTEXT_VTID,
	   "Validate UST context");
}

int main(int argc, char **argv)
{
	plan_tests(NUM_TESTS);

	diag("UST data structures unit test");

	test_create_one_ust_session();
	test_create_ust_metadata();
	test_create_ust_channel();
	test_create_ust_event();
	test_create_ust_context();

	return exit_status();
}
