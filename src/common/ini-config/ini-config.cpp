/*
 * Copyright (C) 2013 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include "ini-config.hpp"

#include <common/defaults.hpp>
#include <common/error.hpp>
#include <common/ini-config/ini.hpp>
#include <common/macros.hpp>
#include <common/utils.hpp>

#include <ctype.h>

LTTNG_EXPORT const char *config_str_yes = "yes";
LTTNG_EXPORT const char *config_str_true = "true";
LTTNG_EXPORT const char *config_str_on = "on";
LTTNG_EXPORT const char *config_str_no = "no";
LTTNG_EXPORT const char *config_str_false = "false";
LTTNG_EXPORT const char *config_str_off = "off";

namespace {
struct handler_filter_args {
	const char *section;
	config_entry_handler_cb handler;
	void *user_data;
};
} /* namespace */

static int config_entry_handler_filter(struct handler_filter_args *args,
				       const char *section,
				       const char *name,
				       const char *value)
{
	int ret = 0;
	const config_entry entry = { section, name, value };

	LTTNG_ASSERT(args);

	if (!section || !name || !value) {
		ret = -EIO;
		goto end;
	}

	if (args->section) {
		if (strcmp(args->section, section) != 0) {
			goto end;
		}
	}

	ret = args->handler(&entry, args->user_data);
end:
	return ret;
}

int config_get_section_entries(const char *override_path,
			       const char *section,
			       config_entry_handler_cb handler,
			       void *user_data)
{
	int ret = 0;
	const char *path;
	FILE *config_file = nullptr;
	struct handler_filter_args filter = { section, handler, user_data };

	/* First, try system-wide conf. file. */
	path = DEFAULT_DAEMON_SYSTEM_CONFIGPATH;

	config_file = fopen(path, "r");
	if (config_file) {
		DBG("Loading daemon conf file at %s", path);
		/*
		 * Return value is not very important here since error or not, we
		 * continue and try the next possible conf. file.
		 */
		(void) ini_parse_file(config_file,
				      (ini_entry_handler) config_entry_handler_filter,
				      (void *) &filter);
		fclose(config_file);
	}

	/* Second is the user local configuration. */
	path = utils_get_home_dir();
	if (path) {
		char fullpath[PATH_MAX];

		ret = snprintf(fullpath, sizeof(fullpath), DEFAULT_DAEMON_HOME_CONFIGPATH, path);
		if (ret < 0) {
			PERROR("snprintf user conf. path");
			goto error;
		}

		config_file = fopen(fullpath, "r");
		if (config_file) {
			DBG("Loading daemon user conf file at %s", path);
			/*
			 * Return value is not very important here since error or not, we
			 * continue and try the next possible conf. file.
			 */
			(void) ini_parse_file(config_file,
					      (ini_entry_handler) config_entry_handler_filter,
					      (void *) &filter);
			fclose(config_file);
		}
	}

	/* Final path is the one that the user might have provided. */
	if (override_path) {
		config_file = fopen(override_path, "r");
		if (config_file) {
			DBG("Loading daemon command line conf file at %s", override_path);
			(void) ini_parse_file(config_file,
					      (ini_entry_handler) config_entry_handler_filter,
					      (void *) &filter);
			fclose(config_file);
		} else {
			ERR("Failed to open daemon configuration file at %s", override_path);
			ret = -ENOENT;
			goto error;
		}
	}

	/* Everything went well. */
	ret = 0;

error:
	return ret;
}

int config_parse_value(const char *value)
{
	int i, ret = 0;
	char *endptr, *lower_str;
	size_t len;
	unsigned long v;

	len = strlen(value);
	if (!len) {
		ret = -1;
		goto end;
	}

	v = strtoul(value, &endptr, 10);
	if (endptr != value) {
		ret = v;
		goto end;
	}

	lower_str = zmalloc<char>(len + 1);
	if (!lower_str) {
		PERROR("zmalloc");
		ret = -errno;
		goto end;
	}

	for (i = 0; i < len; i++) {
		lower_str[i] = tolower(value[i]);
	}

	if (!strcmp(lower_str, config_str_yes) || !strcmp(lower_str, config_str_true) ||
	    !strcmp(lower_str, config_str_on)) {
		ret = 1;
	} else if (!strcmp(lower_str, config_str_no) || !strcmp(lower_str, config_str_false) ||
		   !strcmp(lower_str, config_str_off)) {
		ret = 0;
	} else {
		ret = -1;
	}

	free(lower_str);
end:
	return ret;
}
