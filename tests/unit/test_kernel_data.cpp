/*
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include <common/compat/errno.hpp>
#include <common/defaults.hpp>

#include <bin/lttng-sessiond/trace-kernel.hpp>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tap/tap.h>
#include <time.h>
#include <unistd.h>

#define RANDOM_STRING_LEN 11

/* Number of TAP tests in this file */
#define NUM_TESTS 11

#ifdef HAVE_LIBLTTNG_UST_CTL
#include <lttng/lttng-export.h>
#include <lttng/ust-sigbus.h>
LTTNG_EXPORT DEFINE_LTTNG_UST_SIGBUS_STATE();
#endif

static const char alphanum[] = "0123456789"
			       "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			       "abcdefghijklmnopqrstuvwxyz";

static struct ltt_kernel_session *kern;
static char random_string[RANDOM_STRING_LEN];

/*
 * Return random string of 10 characters.
 * Not thread-safe.
 */
static char *get_random_string()
{
	int i;

	for (i = 0; i < RANDOM_STRING_LEN - 1; i++) {
		random_string[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
	}

	random_string[RANDOM_STRING_LEN - 1] = '\0';

	return random_string;
}

static void test_create_one_kernel_session()
{
	kern = trace_kernel_create_session();
	ok(kern != nullptr, "Create kernel session");

	if (!kern) {
		skip(1, "Kernel session is null");
		return;
	}
	ok(kern->fd == -1 && kern->metadata_stream_fd == -1 && kern->consumer_fds_sent == 0 &&
		   kern->channel_count == 0 && kern->stream_count_global == 0 &&
		   kern->metadata == nullptr,
	   "Validate kernel session");
}

static void test_create_kernel_metadata()
{
	LTTNG_ASSERT(kern != nullptr);

	kern->metadata = trace_kernel_create_metadata();
	ok(kern->metadata != nullptr, "Create kernel metadata");

	ok(kern->metadata->fd == -1 && kern->metadata->conf != nullptr &&
		   kern->metadata->conf->attr.overwrite == DEFAULT_METADATA_OVERWRITE &&
		   kern->metadata->conf->attr.subbuf_size == default_get_metadata_subbuf_size() &&
		   kern->metadata->conf->attr.num_subbuf == DEFAULT_METADATA_SUBBUF_NUM &&
		   kern->metadata->conf->attr.switch_timer_interval ==
			   DEFAULT_METADATA_SWITCH_TIMER &&
		   kern->metadata->conf->attr.read_timer_interval == DEFAULT_METADATA_READ_TIMER &&
		   kern->metadata->conf->attr.output == LTTNG_EVENT_MMAP,
	   "Validate kernel session metadata");

	trace_kernel_destroy_metadata(kern->metadata);
}

static void test_create_kernel_channel()
{
	struct ltt_kernel_channel *chan;
	struct lttng_channel attr;
	struct lttng_channel_extended extended;

	memset(&attr, 0, sizeof(attr));
	memset(&extended, 0, sizeof(extended));
	attr.attr.extended.ptr = &extended;

	chan = trace_kernel_create_channel(&attr);
	ok(chan != nullptr, "Create kernel channel");

	if (!chan) {
		skip(1, "Channel is null");
		return;
	}

	ok(chan->fd == -1 && chan->enabled && chan->stream_count == 0 &&
		   chan->channel->attr.overwrite == attr.attr.overwrite,
	   "Validate kernel channel");

	/* Init list in order to avoid sefaults from cds_list_del */
	CDS_INIT_LIST_HEAD(&chan->list);
	trace_kernel_destroy_channel(chan);
}

static void test_create_kernel_event()
{
	enum lttng_error_code ret;
	struct ltt_kernel_event *event;
	struct lttng_event ev;

	memset(&ev, 0, sizeof(ev));
	ok(!lttng_strncpy(ev.name, get_random_string(), RANDOM_STRING_LEN),
	   "Validate string length");
	ev.type = LTTNG_EVENT_TRACEPOINT;
	ev.loglevel_type = LTTNG_EVENT_LOGLEVEL_ALL;

	ret = trace_kernel_create_event(&ev, nullptr, nullptr, &event);
	ok(ret == LTTNG_OK, "Create kernel event");

	if (!event) {
		skip(1, "Event is null");
		return;
	}

	ok(event->fd == -1 && event->enabled &&
		   event->event->instrumentation == LTTNG_KERNEL_ABI_TRACEPOINT &&
		   strlen(event->event->name),
	   "Validate kernel event");

	/* Init list in order to avoid sefaults from cds_list_del */
	CDS_INIT_LIST_HEAD(&event->list);
	trace_kernel_destroy_event(event);
}

static void test_create_kernel_stream()
{
	struct ltt_kernel_stream *stream;

	stream = trace_kernel_create_stream("stream1", 0);
	ok(stream != nullptr, "Create kernel stream");

	if (!stream) {
		skip(1, "Stream is null");
		return;
	}

	ok(stream->fd == -1 && stream->state == 0, "Validate kernel stream");

	/* Init list in order to avoid sefaults from cds_list_del */
	CDS_INIT_LIST_HEAD(&stream->list);
	trace_kernel_destroy_stream(stream);
}

int main()
{
	plan_tests(NUM_TESTS);

	diag("Kernel data structure unit test");

	test_create_one_kernel_session();
	test_create_kernel_metadata();
	test_create_kernel_channel();
	test_create_kernel_event();
	test_create_kernel_stream();

	return exit_status();
}
