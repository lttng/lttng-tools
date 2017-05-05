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

#include <bin/lttng-sessiond/trace-kernel.h>
#include <common/defaults.h>

#include <tap/tap.h>

#define RANDOM_STRING_LEN	11

/* Number of TAP tests in this file */
#define NUM_TESTS 11

/* For error.h */
int lttng_opt_quiet = 1;
int lttng_opt_verbose;
int lttng_opt_mi;
struct notification_thread_handle *notification_thread_handle;

int ust_consumerd32_fd;
int ust_consumerd64_fd;

static const char alphanum[] =
	"0123456789"
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyz";

static struct ltt_kernel_session *kern;
static char random_string[RANDOM_STRING_LEN];

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

static void test_create_one_kernel_session(void)
{
	kern = trace_kernel_create_session();
	ok(kern != NULL, "Create kernel session");

	if (!kern) {
		skip(1, "Kernel session is null");
		return;
	}
	ok(kern->fd == -1 &&
	   kern->metadata_stream_fd == -1 &&
	   kern->consumer_fds_sent == 0 &&
	   kern->channel_count == 0 &&
	   kern->stream_count_global == 0 &&
	   kern->metadata == NULL,
	   "Validate kernel session");
}

static void test_create_kernel_metadata(void)
{
	assert(kern != NULL);

	kern->metadata = trace_kernel_create_metadata();
	ok(kern->metadata != NULL, "Create kernel metadata");

	ok(kern->metadata->fd == -1 &&
	   kern->metadata->conf != NULL &&
	   kern->metadata->conf->attr.overwrite
			== DEFAULT_CHANNEL_OVERWRITE &&
	   kern->metadata->conf->attr.subbuf_size
			== default_get_metadata_subbuf_size() &&
	   kern->metadata->conf->attr.num_subbuf
			== DEFAULT_METADATA_SUBBUF_NUM &&
	   kern->metadata->conf->attr.switch_timer_interval
			== DEFAULT_KERNEL_CHANNEL_SWITCH_TIMER &&
	   kern->metadata->conf->attr.read_timer_interval
			== DEFAULT_KERNEL_CHANNEL_READ_TIMER &&
	   kern->metadata->conf->attr.output
	       == DEFAULT_KERNEL_CHANNEL_OUTPUT,
	   "Validate kernel session metadata");

	trace_kernel_destroy_metadata(kern->metadata);
}

static void test_create_kernel_channel(void)
{
	struct ltt_kernel_channel *chan;
	struct lttng_channel attr;
	struct lttng_channel_extended extended;

	memset(&attr, 0, sizeof(attr));
	memset(&extended, 0, sizeof(extended));
	attr.attr.extended.ptr = &extended;

	chan = trace_kernel_create_channel(&attr);
	ok(chan != NULL, "Create kernel channel");

	if (!chan) {
		skip(1, "Channel is null");
		return;
	}

	ok(chan->fd == -1 &&
	   chan->enabled == 1 &&
	   chan->stream_count == 0 &&
	   chan->channel->attr.overwrite  == attr.attr.overwrite,
	   "Validate kernel channel");

	/* Init list in order to avoid sefaults from cds_list_del */
	CDS_INIT_LIST_HEAD(&chan->list);
	trace_kernel_destroy_channel(chan);
}

static void test_create_kernel_event(void)
{
	struct ltt_kernel_event *event;
	struct lttng_event ev;

	memset(&ev, 0, sizeof(ev));
	ok(!lttng_strncpy(ev.name, get_random_string(),
			LTTNG_KERNEL_SYM_NAME_LEN),
		"Validate string length");
	ev.type = LTTNG_EVENT_TRACEPOINT;
	ev.loglevel_type = LTTNG_EVENT_LOGLEVEL_ALL;

	event = trace_kernel_create_event(&ev, NULL, NULL);
	ok(event != NULL, "Create kernel event");

	if (!event) {
		skip(1, "Event is null");
		return;
	}

	ok(event->fd == -1 &&
	   event->enabled == 1 &&
	   event->event->instrumentation == LTTNG_KERNEL_TRACEPOINT &&
	   strlen(event->event->name),
	   "Validate kernel event");

	/* Init list in order to avoid sefaults from cds_list_del */
	CDS_INIT_LIST_HEAD(&event->list);
	trace_kernel_destroy_event(event);
}

static void test_create_kernel_stream(void)
{
	struct ltt_kernel_stream *stream;

	stream = trace_kernel_create_stream("stream1", 0);
	ok(stream != NULL, "Create kernel stream");

	if (!stream) {
		skip(1, "Stream is null");
		return;
	}

	ok(stream->fd == -1 &&
	   stream->state == 0,
	   "Validate kernel stream");

	/* Init list in order to avoid sefaults from cds_list_del */
	CDS_INIT_LIST_HEAD(&stream->list);
	trace_kernel_destroy_stream(stream);
}

int main(int argc, char **argv)
{
	plan_tests(NUM_TESTS);

	diag("Kernel data structure unit test");

	test_create_one_kernel_session();
	test_create_kernel_metadata();
	test_create_kernel_channel();
	test_create_kernel_event();
	test_create_kernel_stream();

	/* Success */
	return 0;
}
