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

#include <assert.h>
#include <string.h>

#include <tap/tap.h>

#include <common/uri.h>

/* For error.h */
int lttng_opt_quiet = 1;
int lttng_opt_verbose = 3;
int lttng_opt_mi;

/* Number of TAP tests in this file */
#define NUM_TESTS 11

void test_uri_parsing(void)
{
	ssize_t size;
	const char *s_uri1;
	struct lttng_uri *uri = NULL;

	s_uri1 = "net://localhost";

	size = uri_parse(s_uri1, &uri);

	ok(size == 2 &&
	   uri[0].dtype == LTTNG_DST_IPV4 &&
	   uri[0].utype == LTTNG_URI_DST &&
	   uri[0].stype == 0 &&
	   uri[0].port == 0 &&
	   strlen(uri[0].subdir) == 0 &&
	   strcmp(uri[0].dst.ipv4, "127.0.0.1") == 0 &&
	   uri[1].dtype == LTTNG_DST_IPV4 &&
	   uri[1].utype == LTTNG_URI_DST &&
	   uri[1].stype == 0 &&
	   uri[1].port == 0 &&
	   strlen(uri[1].subdir) == 0 &&
	   strcmp(uri[1].dst.ipv4, "127.0.0.1") == 0,
	   "URI set to net://localhost");

	if (uri) {
		uri_free(uri);
		uri = NULL;
	}

	s_uri1 = "net://localhost:8989:4242/my/test/path";

	size = uri_parse(s_uri1, &uri);

	ok(size == 2 &&
	   uri[0].dtype == LTTNG_DST_IPV4 &&
	   uri[0].utype == LTTNG_URI_DST &&
	   uri[0].stype == 0 &&
	   uri[0].port == 8989 &&
	   strcmp(uri[0].subdir, "my/test/path") == 0 &&
	   strcmp(uri[0].dst.ipv4, "127.0.0.1") == 0 &&
	   uri[1].dtype == LTTNG_DST_IPV4 &&
	   uri[1].utype == LTTNG_URI_DST &&
	   uri[1].stype == 0 &&
	   uri[1].port == 4242 &&
	   strlen(uri[1].subdir) == 0 &&
	   strcmp(uri[1].dst.ipv4, "127.0.0.1") == 0,
	   "URI set to net://localhost:8989:4242/my/test/path");

	if (uri) {
		uri_free(uri);
		uri = NULL;
	}

	s_uri1 = "net://localhost:8989:4242";

	size = uri_parse(s_uri1, &uri);

	ok(size == 2 &&
	   uri[0].dtype == LTTNG_DST_IPV4 &&
	   uri[0].utype == LTTNG_URI_DST &&
	   uri[0].stype == 0 &&
	   uri[0].port == 8989 &&
	   strlen(uri[0].subdir) == 0 &&
	   strcmp(uri[0].dst.ipv4, "127.0.0.1") == 0 &&
	   uri[1].dtype == LTTNG_DST_IPV4 &&
	   uri[1].utype == LTTNG_URI_DST &&
	   uri[1].stype == 0 &&
	   uri[1].port == 4242 &&
	   strlen(uri[1].subdir) == 0 &&
	   strcmp(uri[1].dst.ipv4, "127.0.0.1") == 0,
	   "URI set to net://localhost:8989:4242");

	if (uri) {
		uri_free(uri);
		uri = NULL;
	}

	s_uri1 = "net6://[::1]:8989";

	size = uri_parse(s_uri1, &uri);

	ok(size == 2 &&
	   uri[0].dtype == LTTNG_DST_IPV6 &&
	   uri[0].utype == LTTNG_URI_DST &&
	   uri[0].stype == 0 &&
	   uri[0].port == 8989 &&
	   strlen(uri[0].subdir) == 0 &&
	   strcmp(uri[0].dst.ipv6, "::1") == 0 &&
	   uri[1].dtype == LTTNG_DST_IPV6 &&
	   uri[1].utype == LTTNG_URI_DST &&
	   uri[1].stype == 0 &&
	   uri[1].port == 0 &&
	   strlen(uri[1].subdir) == 0 &&
	   strcmp(uri[1].dst.ipv6, "::1") == 0,
	   "URI set to net6://[::1]:8989");

	if (uri) {
		uri_free(uri);
		uri = NULL;
	}

	s_uri1 = "tcp://42.42.42.42/my/test/path";

	size = uri_parse(s_uri1, &uri);

	ok(size == 1 &&
	   uri[0].dtype == LTTNG_DST_IPV4 &&
	   uri[0].utype == LTTNG_URI_DST &&
	   uri[0].stype == 0 &&
	   uri[0].port == 0 &&
	   strcmp(uri[0].subdir, "my/test/path") == 0 &&
	   strcmp(uri[0].dst.ipv4, "42.42.42.42") == 0,
	   "URI set to tcp://42.42.42.42/my/test/path");

	if (uri) {
		uri_free(uri);
		uri = NULL;
	}

	s_uri1 = "tcp6://[fe80::f66d:4ff:fe53:d220]/my/test/path";

	size = uri_parse(s_uri1, &uri);

	ok(size == 1 &&
	   uri[0].dtype == LTTNG_DST_IPV6 &&
	   uri[0].utype == LTTNG_URI_DST &&
	   uri[0].stype == 0 &&
	   uri[0].port == 0 &&
	   strcmp(uri[0].subdir, "my/test/path") == 0 &&
	   strcmp(uri[0].dst.ipv6, "fe80::f66d:4ff:fe53:d220") == 0,
	   "URI set to tcp6://[fe80::f66d:4ff:fe53:d220]/my/test/path");

	if (uri) {
		uri_free(uri);
		uri = NULL;
	}

	s_uri1 = "file:///my/test/path";

	size = uri_parse(s_uri1, &uri);

	ok(size == 1 &&
	   uri[0].dtype == LTTNG_DST_PATH &&
	   uri[0].utype == LTTNG_URI_DST &&
	   uri[0].stype == 0 &&
	   uri[0].port == 0 &&
	   strlen(uri[0].subdir) == 0 &&
	   strcmp(uri[0].dst.path, "/my/test/path") == 0,
	   "URI set to file:///my/test/path");

	if (uri) {
		uri_free(uri);
		uri = NULL;
	}

	/* FIXME: Noisy on stdout */
	s_uri1 = "file/my/test/path";
	size = uri_parse(s_uri1, &uri);
	ok(size == -1, "Bad URI set to file/my/test/path");
	assert(!uri);

	s_uri1 = "net://:8999";
	size = uri_parse(s_uri1, &uri);
	ok(size == -1, "Bad URI set to net://:8999");
	assert(!uri);
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
	assert(strlen(uri2[0].subdir) == 0);
	assert(strcmp(uri2[0].dst.ipv4, "127.0.0.1") == 0);
	assert(uri2[1].dtype == LTTNG_DST_IPV4);
	assert(uri2[1].utype == LTTNG_URI_DST);
	assert(uri2[1].stype == 0);
	assert(uri2[1].port == 4242);
	assert(strlen(uri2[1].subdir) == 0);
	assert(strcmp(uri2[1].dst.ipv4, "127.0.0.1") == 0);

	res = uri_compare(uri1, uri1);

	ok(res == 0,
	   "URI compare net://localhost == net://localhost");

	res = uri_compare(uri1, uri2);

	ok(res != 0,
	   "URI compare net://localhost != net://localhost:8989:4242");

	uri_free(uri1);
	uri_free(uri2);
}

int main(int argc, char **argv)
{
	plan_tests(NUM_TESTS);

	diag("URI unit tests");

	test_uri_parsing();

	test_uri_cmp();

	return exit_status();
}
