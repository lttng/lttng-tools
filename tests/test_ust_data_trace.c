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
#include <common/lttng-share.h>
#include <bin/lttng-sessiond/trace-ust.h>

#include "utils.h"

/* This path will NEVER be created in this test */
#define PATH1 "/tmp/.test-junk-lttng"

/* For lttngerr.h */
int opt_quiet = 1;
int opt_verbose = 0;

static const char alphanum[] =
	"0123456789"
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyz";

static struct ltt_ust_session *usess;
static struct lttng_domain dom;

/*
 * Return random string of 10 characters.
 */
static char *get_random_string(void)
{
	int i;
	char *str = malloc(11);

	for (i = 0; i < 10; i++) {
		str[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
	}

	str[10] = '\0';

	return str;
}

static void create_one_ust_session(void)
{
	printf("Create UST session: ");

	dom.type = LTTNG_DOMAIN_UST;

	usess = trace_ust_create_session(PATH1, 42, &dom);
	assert(usess != NULL);
	PRINT_OK();

	printf("Validating UST session: ");
	assert(usess->id == 42);
	assert(usess->start_trace == 0);
	assert(usess->domain_global.channels != NULL);
	assert(usess->domain_pid != NULL);
	assert(usess->domain_exec != NULL);
	assert(usess->uid == 0);
	assert(usess->gid == 0);
	PRINT_OK();

	trace_ust_destroy_session(usess);
}

static void create_ust_metadata(void)
{
	struct ltt_ust_metadata *metadata;

	assert(usess != NULL);

	printf("Create UST metadata: ");
	metadata = trace_ust_create_metadata(PATH1);
	assert(metadata != NULL);
	PRINT_OK();

	printf("Validating UST session metadata: ");
	assert(metadata->handle == -1);
	assert(strlen(metadata->pathname));
	assert(metadata->attr.overwrite
			== DEFAULT_CHANNEL_OVERWRITE);
	assert(metadata->attr.subbuf_size
			== DEFAULT_METADATA_SUBBUF_SIZE);
	assert(metadata->attr.num_subbuf
			== DEFAULT_METADATA_SUBBUF_NUM);
	assert(metadata->attr.switch_timer_interval
			== DEFAULT_CHANNEL_SWITCH_TIMER);
	assert(metadata->attr.read_timer_interval
			== DEFAULT_CHANNEL_READ_TIMER);
	assert(metadata->attr.output == LTTNG_UST_MMAP);
	PRINT_OK();

	trace_ust_destroy_metadata(metadata);
}

static void create_ust_channel(void)
{
	struct ltt_ust_channel *uchan;
	struct lttng_channel attr;

	strncpy(attr.name, "channel0", 8);

	printf("Creating UST channel: ");
	uchan = trace_ust_create_channel(&attr, PATH1);
	assert(uchan != NULL);
	PRINT_OK();

	printf("Validating UST channel: ");
	assert(uchan->enabled == 0);
	assert(strcmp(PATH1, uchan->pathname) == 0);
	assert(strncmp(uchan->name, "channel0", 8) == 0);
	assert(uchan->name[LTTNG_UST_SYM_NAME_LEN - 1] == '\0');
	assert(uchan->ctx != NULL);
	assert(uchan->events != NULL);
	assert(uchan->attr.overwrite  == attr.attr.overwrite);
	PRINT_OK();

	trace_ust_destroy_channel(uchan);
}

static void create_ust_event(void)
{
	struct ltt_ust_event *event;
	struct lttng_event ev;

	strncpy(ev.name, get_random_string(), LTTNG_SYMBOL_NAME_LEN);
	ev.type = LTTNG_EVENT_TRACEPOINT;

	printf("Creating UST event: ");
	event = trace_ust_create_event(&ev);
	assert(event != NULL);
	PRINT_OK();

	printf("Validating UST event: ");
	assert(event->enabled == 0);
	assert(event->ctx != NULL);
	assert(event->attr.instrumentation == LTTNG_UST_TRACEPOINT);
	assert(strcmp(event->attr.name, ev.name) == 0);
	assert(event->attr.name[LTTNG_UST_SYM_NAME_LEN - 1] == '\0');
	PRINT_OK();

	trace_ust_destroy_event(event);
}

static void create_ust_context(void)
{
	struct lttng_event_context ctx;
	struct ltt_ust_context *uctx;

	printf("Creating UST context: ");
	uctx = trace_ust_create_context(&ctx);
	assert(uctx != NULL);
	PRINT_OK();

	printf("Validating UST context: ");
	assert((int) ctx.ctx == (int)uctx->ctx.ctx);
	PRINT_OK();
}

int main(int argc, char **argv)
{
	printf("\nTesting UST data structures:\n-----------\n");

	create_one_ust_session();
	create_ust_metadata();
	create_ust_channel();
	create_ust_event();
	create_ust_context();

	/* Success */
	return 0;
}
