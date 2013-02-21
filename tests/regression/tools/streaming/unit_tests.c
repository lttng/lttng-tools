/*
 * Copyright (C) - 2012 David Goulet <dgoulet@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by as
 * published by the Free Software Foundation; only version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>

#include <common/sessiond-comm/sessiond-comm.h>
#include <common/uri.h>

#include "utils.h"

/* This path will NEVER be created in this test */
#define PATH1 "tmp/.test-junk-lttng"

#define RANDOM_STRING_LEN 16

/* For lttngerr.h */
int lttng_opt_quiet = 1;
int lttng_opt_verbose = 3;

/*
 * Test string URI and if uri_parse works well.
 */
void test_uri_parsing(void)
{
	ssize_t size;
	const char *s_uri1;
	struct lttng_uri *uri;

	fprintf(stdout, "Testing URIs...\n");

	s_uri1 = "net://localhost";
	fprintf(stdout, " [+] URI set to %s ", s_uri1);
	size = uri_parse(s_uri1, &uri);
	assert(size == 2);
	assert(uri[0].dtype == LTTNG_DST_IPV4);
	assert(uri[0].utype == LTTNG_URI_DST);
	assert(uri[0].stype == 0);
	assert(uri[0].port == 0);
	assert(strlen(uri[0].subdir) == 0);
	assert(strcmp(uri[0].dst.ipv4, "127.0.0.1") == 0);

	assert(uri[1].dtype == LTTNG_DST_IPV4);
	assert(uri[1].utype == LTTNG_URI_DST);
	assert(uri[1].stype == 0);
	assert(uri[1].port == 0);
	assert(strlen(uri[1].subdir) == 0);
	assert(strcmp(uri[1].dst.ipv4, "127.0.0.1") == 0);
	PRINT_OK();
	uri_free(uri);

	s_uri1 = "net://localhost:8989:4242/my/test/path";
	fprintf(stdout, " [+] URI set to %s ", s_uri1);
	size = uri_parse(s_uri1, &uri);
	assert(size == 2);
	assert(uri[0].dtype == LTTNG_DST_IPV4);
	assert(uri[0].utype == LTTNG_URI_DST);
	assert(uri[0].stype == 0);
	assert(uri[0].port == 8989);
	assert(strcmp(uri[0].subdir, "my/test/path") == 0);
	assert(strcmp(uri[0].dst.ipv4, "127.0.0.1") == 0);

	assert(uri[1].dtype == LTTNG_DST_IPV4);
	assert(uri[1].utype == LTTNG_URI_DST);
	assert(uri[1].stype == 0);
	assert(uri[1].port == 4242);
	assert(strcmp(uri[0].subdir, "my/test/path") == 0);
	assert(strcmp(uri[1].dst.ipv4, "127.0.0.1") == 0);
	PRINT_OK();
	uri_free(uri);

	s_uri1 = "net://localhost:8989:4242";
	fprintf(stdout, " [+] URI set to %s ", s_uri1);
	size = uri_parse(s_uri1, &uri);
	assert(size == 2);
	assert(uri[0].dtype == LTTNG_DST_IPV4);
	assert(uri[0].utype == LTTNG_URI_DST);
	assert(uri[0].stype == 0);
	assert(uri[0].port == 8989);
	assert(strlen(uri[1].subdir) == 0);
	assert(strcmp(uri[0].dst.ipv4, "127.0.0.1") == 0);

	assert(uri[1].dtype == LTTNG_DST_IPV4);
	assert(uri[1].utype == LTTNG_URI_DST);
	assert(uri[1].stype == 0);
	assert(uri[1].port == 4242);
	assert(strlen(uri[1].subdir) == 0);
	assert(strcmp(uri[1].dst.ipv4, "127.0.0.1") == 0);
	PRINT_OK();
	uri_free(uri);

	s_uri1 = "net6://localhost:8989";
	fprintf(stdout, " [+] URI set to %s ", s_uri1);
	size = uri_parse(s_uri1, &uri);
	assert(size == 2);
	assert(uri[0].dtype == LTTNG_DST_IPV6);
	assert(uri[0].utype == LTTNG_URI_DST);
	assert(uri[0].stype == 0);
	assert(uri[0].port == 8989);
	assert(strlen(uri[1].subdir) == 0);
	assert(strcmp(uri[0].dst.ipv6, "::1") == 0);

	assert(uri[1].dtype == LTTNG_DST_IPV6);
	assert(uri[1].utype == LTTNG_URI_DST);
	assert(uri[1].stype == 0);
	assert(uri[1].port == 0);
	assert(strlen(uri[1].subdir) == 0);
	assert(strcmp(uri[0].dst.ipv6, "::1") == 0);
	PRINT_OK();
	uri_free(uri);

	s_uri1 = "tcp://42.42.42.42/my/test/path";
	fprintf(stdout, " [+] URI set to %s ", s_uri1);
	size = uri_parse(s_uri1, &uri);
	assert(size == 1);
	assert(uri[0].dtype == LTTNG_DST_IPV4);
	assert(uri[0].utype == LTTNG_URI_DST);
	assert(uri[0].stype == 0);
	assert(uri[0].port == 0);
	assert(strcmp(uri[0].subdir, "my/test/path") == 0);
	assert(strcmp(uri[0].dst.ipv4, "42.42.42.42") == 0);
	PRINT_OK();
	uri_free(uri);

	s_uri1 = "tcp6://[fe80::f66d:4ff:fe53:d220]/my/test/path";
	fprintf(stdout, " [+] URI set to %s ", s_uri1);
	size = uri_parse(s_uri1, &uri);
	assert(size == 1);
	assert(uri[0].dtype == LTTNG_DST_IPV6);
	assert(uri[0].utype == LTTNG_URI_DST);
	assert(uri[0].stype == 0);
	assert(uri[0].port == 0);
	assert(strcmp(uri[0].subdir, "my/test/path") == 0);
	assert(strcmp(uri[0].dst.ipv6, "fe80::f66d:4ff:fe53:d220") == 0);
	PRINT_OK();
	uri_free(uri);

	s_uri1 = "file:///my/test/path";
	fprintf(stdout, " [+] URI set to %s ", s_uri1);
	size = uri_parse(s_uri1, &uri);
	assert(size == 1);
	assert(uri[0].dtype == LTTNG_DST_PATH);
	assert(uri[0].utype == LTTNG_URI_DST);
	assert(uri[0].stype == 0);
	assert(uri[0].port == 0);
	assert(strlen(uri[0].subdir) == 0);
	assert(strcmp(uri[0].dst.path, "/my/test/path") == 0);
	PRINT_OK();
	uri_free(uri);

	s_uri1 = "file/my/test/path";
	fprintf(stdout, " [+] Bad URI set to %s ", s_uri1);
	size = uri_parse(s_uri1, &uri);
	assert(size == -1);
	PRINT_OK();

	s_uri1 = "net://:8999";
	fprintf(stdout, " [+] Bad URI set to %s ", s_uri1);
	size = uri_parse(s_uri1, &uri);
	assert(size == -1);
	PRINT_OK();
}

void test_uri_cmp()
{
	struct lttng_uri *uri1, *uri2;
	const char *s_uri1 = "net://localhost";
	const char *s_uri2 = "net://localhost:8989:4242";
	ssize_t size1, size2;
	int res;

	size1 = uri_parse(s_uri1, &uri1);

	/* Sanity checks */
	assert(size1 == 2);
	assert(uri1[0].dtype == LTTNG_DST_IPV4);
	assert(uri1[0].utype == LTTNG_URI_DST);
	assert(uri1[0].stype == 0);
	assert(uri1[0].port == 0);
	assert(strlen(uri1[0].subdir) == 0);
	assert(strcmp(uri1[0].dst.ipv4, "127.0.0.1") == 0);
	assert(uri1[1].dtype == LTTNG_DST_IPV4);
	assert(uri1[1].utype == LTTNG_URI_DST);
	assert(uri1[1].stype == 0);
	assert(uri1[1].port == 0);
	assert(strlen(uri1[1].subdir) == 0);
	assert(strcmp(uri1[1].dst.ipv4, "127.0.0.1") == 0);

	size2 = uri_parse(s_uri2, &uri2);

	assert(size2 == 2);
	assert(uri2[0].dtype == LTTNG_DST_IPV4);
	assert(uri2[0].utype == LTTNG_URI_DST);
	assert(uri2[0].stype == 0);
	assert(uri2[0].port == 8989);
	assert(strlen(uri2[1].subdir) == 0);
	assert(strcmp(uri2[0].dst.ipv4, "127.0.0.1") == 0);
	assert(uri2[1].dtype == LTTNG_DST_IPV4);
	assert(uri2[1].utype == LTTNG_URI_DST);
	assert(uri2[1].stype == 0);
	assert(uri2[1].port == 4242);
	assert(strlen(uri2[1].subdir) == 0);
	assert(strcmp(uri2[1].dst.ipv4, "127.0.0.1") == 0);


	res = uri_compare(uri1, uri1);
	fprintf(stdout, " [+] %s == %s ", s_uri1, s_uri1);
	assert(res == 0);
	PRINT_OK();

	res = uri_compare(uri1, uri2);
	fprintf(stdout, " [+] %s != %s ", s_uri1, s_uri2);
	assert(res != 0);
	PRINT_OK();

	uri_free(uri1);
	uri_free(uri2);
}

int main(int argc, char **argv)
{
	srand(time(NULL));

	printf("\nStreaming unit tests\n-----------\n");

	/* URI tests */
	test_uri_parsing();
	test_uri_cmp();

	return 0;
}
