/*
 * SPDX-FileCopyrightText: 2012 David Goulet <dgoulet@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
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
static void *th_event_minute(void *data __attribute__((unused)))
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
int main(void)
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
