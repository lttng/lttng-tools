/*
 * Copyright (C) 2020 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 *
 */

#include "tracepoint-trigger-example.h"

#include <lttng/tracepoint.h>

#include <stdio.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

int main(void)
{
	uint64_t i;

	for (i = 0; i < UINT64_MAX; i++) {
		char time_str[64];
		struct timeval tv;
		time_t the_time;

		gettimeofday(&tv, NULL);
		the_time = tv.tv_sec;

		strftime(time_str, sizeof(time_str), "[%m-%d-%Y] %T", localtime(&the_time));
		printf("%s.%ld - Tracing event \"trigger_example:my_event\"\n",
		       time_str,
		       tv.tv_usec);

		tracepoint(trigger_example, my_event, i);
		sleep(2);
	}
	return 0;
}
