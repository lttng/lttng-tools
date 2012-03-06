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

#include <bin/lttng-sessiond/trace-kernel.h>
#include <common/defaults.h>

#include "utils.h"

/* This path will NEVER be created in this test */
#define PATH1 "/tmp/.test-junk-lttng"

#define RANDOM_STRING_LEN	11

/* For lttngerr.h */
int lttng_opt_quiet = 1;
int lttng_opt_verbose;

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

static void create_one_kernel_session(void)
{
	printf("Create kernel session: ");
	kern = trace_kernel_create_session(PATH1);
	assert(kern != NULL);
	PRINT_OK();

	printf("Validating kernel session: ");
	assert(kern->fd == -1);
	assert(kern->metadata_stream_fd == -1);
	assert(kern->consumer_fds_sent == 0);
	assert(kern->channel_count == 0);
	assert(kern->stream_count_global == 0);
	assert(kern->metadata == NULL);
	assert(kern->consumer_fd == -1);
	PRINT_OK();

	/* Init list in order to avoid sefaults from cds_list_del */
	trace_kernel_destroy_session(kern);
}

static void create_kernel_metadata(void)
{
	assert(kern != NULL);

	printf("Create kernel metadata: ");
	kern->metadata = trace_kernel_create_metadata(PATH1);
	assert(kern->metadata != NULL);
	PRINT_OK();

	printf("Validating kernel session metadata: ");
	assert(kern->metadata->fd == -1);
	assert(strlen(kern->metadata->pathname));
	assert(kern->metadata->conf != NULL);
	assert(kern->metadata->conf->attr.overwrite
			== DEFAULT_CHANNEL_OVERWRITE);
	assert(kern->metadata->conf->attr.subbuf_size
			== DEFAULT_METADATA_SUBBUF_SIZE);
	assert(kern->metadata->conf->attr.num_subbuf
			== DEFAULT_METADATA_SUBBUF_NUM);
	assert(kern->metadata->conf->attr.switch_timer_interval
			== DEFAULT_CHANNEL_SWITCH_TIMER);
	assert(kern->metadata->conf->attr.read_timer_interval
			== DEFAULT_CHANNEL_READ_TIMER);
	assert(kern->metadata->conf->attr.output
			== DEFAULT_KERNEL_CHANNEL_OUTPUT);
	PRINT_OK();

	trace_kernel_destroy_metadata(kern->metadata);
}

static void create_kernel_channel(void)
{
	struct ltt_kernel_channel *chan;
	struct lttng_channel attr;

	memset(&attr, 0, sizeof(attr));

	printf("Creating kernel channel: ");
	chan = trace_kernel_create_channel(&attr, PATH1);
	assert(chan != NULL);
	PRINT_OK();

	printf("Validating kernel channel: ");
	assert(chan->fd == -1);
	assert(chan->enabled == 1);
	assert(strcmp(PATH1, chan->pathname) == 0);
	assert(chan->stream_count == 0);
	assert(chan->ctx == NULL);
	assert(chan->channel->attr.overwrite  == attr.attr.overwrite);
	PRINT_OK();

	/* Init list in order to avoid sefaults from cds_list_del */
	CDS_INIT_LIST_HEAD(&chan->list);
	trace_kernel_destroy_channel(chan);
}

static void create_kernel_event(void)
{
	struct ltt_kernel_event *event;
	struct lttng_event ev;

	memset(&ev, 0, sizeof(ev));
	strncpy(ev.name, get_random_string(), LTTNG_KERNEL_SYM_NAME_LEN);
	ev.type = LTTNG_EVENT_TRACEPOINT;
	ev.loglevel_type = LTTNG_EVENT_LOGLEVEL_ALL;

	printf("Creating kernel event: ");
	event = trace_kernel_create_event(&ev);
	assert(event != NULL);
	PRINT_OK();

	printf("Validating kernel event: ");
	assert(event->fd == -1);
	assert(event->enabled == 1);
	assert(event->ctx == NULL);
	assert(event->event->instrumentation == LTTNG_KERNEL_TRACEPOINT);
	assert(strlen(event->event->name));
	PRINT_OK();

	/* Init list in order to avoid sefaults from cds_list_del */
	CDS_INIT_LIST_HEAD(&event->list);
	trace_kernel_destroy_event(event);
}

static void create_kernel_stream(void)
{
	struct ltt_kernel_stream *stream;

	printf("Creating kernel stream: ");
	stream = trace_kernel_create_stream();
	assert(stream != NULL);
	PRINT_OK();

	printf("Validating kernel stream: ");
	assert(stream->fd == -1);
	assert(stream->pathname == NULL);
	assert(stream->state == 0);
	PRINT_OK();

	/* Init list in order to avoid sefaults from cds_list_del */
	CDS_INIT_LIST_HEAD(&stream->list);
	trace_kernel_destroy_stream(stream);
}

int main(int argc, char **argv)
{
	printf("\nTesting kernel data structures:\n-----------\n");

	create_one_kernel_session();

	create_kernel_metadata();
	create_kernel_channel();


	create_kernel_event();

	create_kernel_stream();

	/* Success */
	return 0;
}
