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

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <urcu.h>

#include <lttng/lttng.h>
#include <bin/lttng-sessiond/lttng-ust-abi.h>
#include <common/defaults.h>
#include <bin/lttng-sessiond/trace-ust.h>
#include <bin/lttng-sessiond/ust-app.h>
#include <bin/lttng-sessiond/notification-thread.h>

#include <tap/tap.h>

/* This path will NEVER be created in this test */
#define PATH1 "/tmp/.test-junk-lttng"

#define RANDOM_STRING_LEN	11

/* Number of TAP tests in this file */
#define NUM_TESTS 16

/* For error.h */
int lttng_opt_quiet = 1;
int lttng_opt_verbose;
int lttng_opt_mi;

int ust_consumerd32_fd;
int ust_consumerd64_fd;

/* Global variables required by sessiond objects being linked-in */
struct lttng_ht *agent_apps_ht_by_sock;
struct notification_thread_handle *notification_thread_handle;

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

	if (!usess) {
		skip(1, "UST session is null");
		return;
	}

	ok(usess->id == 42 &&
	   usess->active == 0 &&
	   usess->domain_global.channels != NULL &&
	   usess->uid == 0 &&
	   usess->gid == 0,
	   "Validate UST session");

	trace_ust_destroy_session(usess);
}

static void test_create_ust_channel(void)
{
	struct ltt_ust_channel *uchan;
	struct lttng_channel attr;
	struct lttng_channel_extended extended;

	memset(&attr, 0, sizeof(attr));
	memset(&extended, 0, sizeof(extended));
	attr.attr.extended.ptr = &extended;

	ok(lttng_strncpy(attr.name, "channel0", sizeof(attr.name)) == 0,
		"Validate channel name length");
	uchan = trace_ust_create_channel(&attr, LTTNG_DOMAIN_UST);
	ok(uchan != NULL, "Create UST channel");

	if (!usess) {
		skip(1, "UST session is null");
		return;
	}

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
	ok(lttng_strncpy(ev.name, get_random_string(),
			LTTNG_SYMBOL_NAME_LEN) == 0,
		"Validate string length");
	ev.type = LTTNG_EVENT_TRACEPOINT;
	ev.loglevel_type = LTTNG_EVENT_LOGLEVEL_ALL;

	event = trace_ust_create_event(&ev, NULL, NULL, NULL, false);

	ok(event != NULL, "Create UST event");

	if (!event) {
		skip(1, "UST event is null");
		return;
	}

	ok(event->enabled == 0 &&
	   event->attr.instrumentation == LTTNG_UST_TRACEPOINT &&
	   strcmp(event->attr.name, ev.name) == 0 &&
	   event->attr.name[LTTNG_UST_SYM_NAME_LEN - 1] == '\0',
	   "Validate UST event");

	trace_ust_destroy_event(event);
}

static void test_create_ust_event_exclusion(void)
{
	struct ltt_ust_event *event;
	struct lttng_event ev;
	char *name;
	char *random_name;
	struct lttng_event_exclusion *exclusion;
	const int exclusion_count = 2;

	memset(&ev, 0, sizeof(ev));

	/* make a wildcarded event name */
	name = get_random_string();
	name[strlen(name) - 1] = '*';
	ok(lttng_strncpy(ev.name, name, LTTNG_SYMBOL_NAME_LEN) == 0,
		"Validate string length");

	ev.type = LTTNG_EVENT_TRACEPOINT;
	ev.loglevel_type = LTTNG_EVENT_LOGLEVEL_ALL;

	/* set up an exclusion set */
	exclusion = zmalloc(sizeof(*exclusion) +
		LTTNG_SYMBOL_NAME_LEN * exclusion_count);
	ok(exclusion != NULL, "Create UST exclusion");
	if (!exclusion) {
		skip(4, "zmalloc failed");
		goto end;
	}

	exclusion->count = exclusion_count;
	random_name = get_random_string();
	strncpy(LTTNG_EVENT_EXCLUSION_NAME_AT(exclusion, 0), random_name,
		LTTNG_SYMBOL_NAME_LEN);
	strncpy(LTTNG_EVENT_EXCLUSION_NAME_AT(exclusion, 1), random_name,
		LTTNG_SYMBOL_NAME_LEN);

	event = trace_ust_create_event(&ev, NULL, NULL, exclusion, false);
	exclusion = NULL;

	ok(!event, "Create UST event with identical exclusion names fails");

	exclusion = zmalloc(sizeof(*exclusion) +
		LTTNG_SYMBOL_NAME_LEN * exclusion_count);
	ok(exclusion != NULL, "Create UST exclusion");
	if (!exclusion) {
		skip(2, "zmalloc failed");
		goto end;
	}

	exclusion->count = exclusion_count;
	strncpy(LTTNG_EVENT_EXCLUSION_NAME_AT(exclusion, 0),
		get_random_string(), LTTNG_SYMBOL_NAME_LEN);
	strncpy(LTTNG_EVENT_EXCLUSION_NAME_AT(exclusion, 1),
		get_random_string(), LTTNG_SYMBOL_NAME_LEN);

	event = trace_ust_create_event(&ev, NULL, NULL, exclusion, false);
	ok(event != NULL, "Create UST event with different exclusion names");

	if (!event) {
		skip(1, "UST event with exclusion is null");
		goto end;
	}

	ok(event->enabled == 0 &&
	   event->attr.instrumentation == LTTNG_UST_TRACEPOINT &&
	   strcmp(event->attr.name, ev.name) == 0 &&
	   event->exclusion != NULL &&
	   event->exclusion->count == exclusion_count &&
	   !memcmp(event->exclusion->names, exclusion->names,
	   	LTTNG_SYMBOL_NAME_LEN * exclusion_count) &&
	   event->attr.name[LTTNG_UST_SYM_NAME_LEN - 1] == '\0',
	   "Validate UST event and exclusion");

	trace_ust_destroy_event(event);
end:
	return;
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
	free(uctx);
}

int main(int argc, char **argv)
{
	plan_tests(NUM_TESTS);

	diag("UST data structures unit test");

	rcu_register_thread();

	test_create_one_ust_session();
	test_create_ust_channel();
	test_create_ust_event();
	test_create_ust_context();
	test_create_ust_event_exclusion();

	rcu_unregister_thread();

	return exit_status();
}
