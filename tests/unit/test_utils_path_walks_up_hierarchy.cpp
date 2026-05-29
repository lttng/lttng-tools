/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include <common/path.hpp>

#include <tap/tap.h>

/* For error.h */
bool lttng_opt_is_tui = true;
int lttng_opt_quiet = 1;
int lttng_opt_verbose = 3;
int lttng_opt_mi;

namespace {
struct test_input {
	const char *path;
	bool walks_up;
};

/*
 * A path "walks up" when at least one of its '/'-separated components is
 * exactly "..". A bare substring match on ".." must not count, so names that
 * merely contain dots (such as "my..name" or "...") are expected to be
 * accepted.
 */
const test_input test_inputs[] = {
	/* Paths that walk up the hierarchy. */
	{ "..", true },
	{ "../", true },
	{ "../foo", true },
	{ "foo/..", true },
	{ "foo/../bar", true },
	{ "a/b/../c", true },
	{ "/..", true },
	{ "/../etc", true },
	{ "../../../../etc/cron.d", true },
	{ "foo/bar/baz/..", true },
	{ "..//foo", true },
	{ "foo//../bar", true },

	/* Paths that do not walk up the hierarchy. */
	{ "", false },
	{ ".", false },
	{ "./foo", false },
	{ "foo", false },
	{ "foo/bar", false },
	{ "/", false },
	{ "/etc/cron.d", false },
	{ "my..name", false },
	{ "..foo", false },
	{ "foo..", false },
	{ "...", false },
	{ "....", false },
	{ "a/...b/c", false },
	{ "foo/..bar/baz", false },
	{ ".hidden", false },
};
} /* namespace */

int main()
{
	plan_tests((int) (sizeof(test_inputs) / sizeof(test_inputs[0])) + 1);

	diag("utils_path_walks_up_hierarchy tests");

	for (const auto& test_input : test_inputs) {
		ok(utils_path_walks_up_hierarchy(test_input.path) == test_input.walks_up,
		   "\"%s\" %s the hierarchy",
		   test_input.path,
		   test_input.walks_up ? "walks up" : "does not walk up");
	}

	/* A null path must be handled gracefully and reported as benign. */
	ok(!utils_path_walks_up_hierarchy(nullptr), "null path does not walk up the hierarchy");

	return exit_status();
}
