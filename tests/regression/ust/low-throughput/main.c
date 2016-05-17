/*
 * Copyright (C) 2012 - David Goulet <dgoulet@efficios.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; version 2.1 of
 * the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 */

#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

#define TRACEPOINT_DEFINE
#include "tp.h"

/*
 * Thread recording a tracepoint every minute for 20 minutes.
 */
static void *th_event_minute(void *data)
{
	int i;

	/* Loop for 20 minutes */
	for (i = 1; i < 21; i++) {
		/* Sleep 60 seconds */
		(void) poll(NULL, 0, 60000);

		/* 20 minutes tracepoint */
		if ((i % 20) == 0) {
			tracepoint(tp, slow, i, "twenty");
		}

		/* 10 minutes tracepoint */
		if ((i % 10) == 0) {
			tracepoint(tp, slow, i, "ten");
		}

		/* 1 minute tracepoint */
		tracepoint(tp, slow, i, "one");
	}

	return NULL;
}

/*
 * main
 */
int main(int argc, char **argv)
{
	int ret;
	void *status;
	pthread_t thread;

	ret = pthread_create(&thread, NULL, th_event_minute, NULL);
	if (ret != 0) {
		perror("pthread_create event minute");
		goto error;
	}

	ret = pthread_join(thread, &status);
	if (ret != 0) {
		perror("pthread_join");
		goto error;
	}

	return 0;

error:
	return 1;
}
