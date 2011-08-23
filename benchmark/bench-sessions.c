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

#include "ltt-sessiond/session.h"
#include "utils.h"
#include "benchmark.h"

#define SESSION1 "test1"

/* This path will NEVER be created in this test */
#define PATH1 "/tmp/.test-junk-lttng"

/* For lttngerr.h */
int opt_quiet = 1;
int opt_verbose = 0;

static const char alphanum[] =
	"0123456789"
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyz";

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

int main(int argc, char **argv)
{
	int ret, i, nb_iter;
	char **names;
	double value, total = 0;

	if (getuid() != 0) {
		printf("Aborting test. Must be uid 0 to drop_caches\n");
		return 1;
	}

	if (argc < 2) {
		printf("Missing arguments\n");
		return 1;
	}

	nb_iter = atoi(argv[1]);

	names = malloc(sizeof(char*) * nb_iter);

	srand(time(NULL));
	bench_init();

	fprintf(fp, "--- Create tracing session ---\n");
	for (i = 0; i < nb_iter; i++) {
		names[i] = get_random_string();
		ret = system("echo 3 >/proc/sys/vm/drop_caches");
		tracepoint(create_session_start);
		ret = create_session(names[i], PATH1);
		tracepoint(create_session_end);
		if (ret < 0) {
			printf("Create session went wrong. Aborting\n");
			goto error;
		}
		value = bench_get_create_session();
		fprintf(fp, "%.20f\n", value);
		total += value;
	}

	fprintf(fp, "--> Average: %.20f\n\n", total/nb_iter);
	total = 0;

	fprintf(fp, "--- Destroy tracing session ---\n");
	for (i = 0; i < nb_iter; i++) {
		ret = system("echo 3 >/proc/sys/vm/drop_caches");
		tracepoint(destroy_session_start);
		ret = destroy_session(names[i]);
		tracepoint(destroy_session_end);
		if (ret < 0) {
			printf("Destroy session went wrong. Aborting\n");
			goto error;
		}
		value = bench_get_destroy_session();
		fprintf(fp, "%.20f\n", value);
		total += value;
		free(names[i]);
	}
	fprintf(fp, "--> Average: %.20f\n\n", total/nb_iter);

	/* Success */
	bench_close();
	return 0;

error:
	bench_close();
	free(names);

	return 1;
}
