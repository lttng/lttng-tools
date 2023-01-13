/*
 * Copyright (C) 2013 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include <common/ini-config/ini-config.hpp>
#include <common/path.hpp>
#include <common/utils.hpp>

#include <lttng/constant.h>

#include <string.h>
#include <tap/tap.h>

namespace {
struct state {
	int section_1;
	int section_2;
	int section_3;
	int section_global;
	int text_entry;
	int int_entry;
};
} /* namespace */

int lttng_opt_quiet = 1;
int lttng_opt_verbose = 0;
int lttng_opt_mi;

static int entry_handler(const struct config_entry *entry, struct state *state)
{
	int ret = 0;

	if (!entry || !state) {
		ret = -1;
		goto end;
	}

	if (!strcmp(entry->section, "section1")) {
		state->section_1 = 1;
		if (!strcmp(entry->name, "section1_entry") && !strcmp(entry->value, "42")) {
			state->int_entry = 1;
		}
	}

	if (!strcmp(entry->section, "section2")) {
		state->section_2 = 1;
	}

	if (!strcmp(entry->section, "section 3")) {
		state->section_3 = 1;
		if (!strcmp(entry->name, "name with a space") &&
		    !strcmp(entry->value, "another value")) {
			state->text_entry = 1;
		}
	}

	if (!strcmp(entry->section, "")) {
		state->section_global = 1;
	}
end:
	return ret;
}

int main(int argc, char **argv)
{
	char *path = NULL;
	int ret;
	struct state state = {};

	if (argc < 2) {
		diag("Usage: path_to_sample_INI_file");
		goto end;
	}

	if (strlen(argv[1]) >= LTTNG_PATH_MAX) {
		diag("The provided path exceeds the maximal permitted length of %i bytes",
		     LTTNG_PATH_MAX);
		goto end;
	}
	path = utils_expand_path(argv[1]);
	if (!path) {
		fail("Failed to resolve sample INI file path");
	}

	plan_no_plan();
	ret = config_get_section_entries(
		path, NULL, (config_entry_handler_cb) entry_handler, &state);
	ok(ret == 0, "Successfully opened a config file, registered to all sections");
	ok(state.section_1 && state.section_2 && state.section_3 && state.section_global,
	   "Processed entries from each sections");
	ok(state.text_entry, "Text value parsed correctly");

	memset(&state, 0, sizeof(struct state));
	ret = config_get_section_entries(
		path, "section1", (config_entry_handler_cb) entry_handler, &state);
	ok(ret == 0, "Successfully opened a config file, registered to one section");
	ok(state.section_1 && !state.section_2 && !state.section_3 && !state.section_global,
	   "Processed an entry from section1 only");
	ok(state.int_entry, "Int value parsed correctly");

	memset(&state, 0, sizeof(struct state));
	ret = config_get_section_entries(path, "", (config_entry_handler_cb) entry_handler, &state);
	ok(ret == 0, "Successfully opened a config file, registered to the global section");
	ok(!state.section_1 && !state.section_2 && !state.section_3 && state.section_global,
	   "Processed an entry from the global section only");
end:
	free(path);
	return exit_status();
}
