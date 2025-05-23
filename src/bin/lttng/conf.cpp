/*
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include "conf.hpp"

#include <common/common.hpp>
#include <common/compat/errno.hpp>
#include <common/utils.hpp>

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/*
 * Returns the path with '/CONFIG_FILENAME' added to it;
 * path will be NULL if an error occurs.
 */
char *config_get_file_path(const char *path)
{
	int ret;
	char *file_path;

	ret = asprintf(&file_path, "%s/%s", path, CONFIG_FILENAME);
	if (ret < 0) {
		ERR("Fail allocating config file path");
		file_path = nullptr;
	}

	return file_path;
}

/*
 * Returns an open FILE pointer to the config file;
 * on error, NULL is returned.
 */
static FILE *open_config(const char *path, const char *mode)
{
	FILE *fp = nullptr;
	char *file_path;

	file_path = config_get_file_path(path);
	if (file_path == nullptr) {
		goto error;
	}

	fp = fopen(file_path, mode);
	if (fp == nullptr) {
		PWARN("Failed to open configuration file '%s'", file_path);
		goto error;
	}

error:
	free(file_path);
	return fp;
}

/*
 * Creates the empty config file at the path.
 * On success, returns 0;
 * on error, returns -1.
 */
static int create_config_file(const char *path)
{
	int ret;
	FILE *fp;

	fp = open_config(path, "w+");
	if (fp == nullptr) {
		ret = -1;
		goto error;
	}

	ret = fclose(fp);

error:
	return ret;
}

/*
 * Append data to the config file in file_path
 * On success, returns 0;
 * on error, returns -1.
 */
static int write_config(const char *file_path, std::size_t size, const char *data)
{
	FILE *fp;
	std::size_t len;
	int ret = 0;

	fp = open_config(file_path, "a");
	if (fp == nullptr) {
		ret = -1;
		goto end;
	}

	/* Write session name into config file */
	len = fwrite(data, size, 1, fp);
	if (len != 1) {
		ret = -1;
	}
	if (fclose(fp)) {
		PERROR("close write_config");
	}
end:
	return ret;
}

/*
 * Destroys directory config and file config.
 */
void config_destroy(const char *path)
{
	int ret;
	char *config_path;

	config_path = config_get_file_path(path);
	if (config_path == nullptr) {
		return;
	}

	if (!config_exists(config_path)) {
		goto end;
	}

	DBG("Removing %s\n", config_path);
	ret = remove(config_path);
	if (ret < 0) {
		PERROR("remove config file");
	}
end:
	free(config_path);
}

/*
 * Destroys the default config
 */
void config_destroy_default()
{
	const char *path = utils_get_home_dir();
	if (path == nullptr) {
		return;
	}
	config_destroy(path);
}

/*
 * Returns 1 if config exists, 0 otherwise
 */
int config_exists(const char *path)
{
	int ret;
	struct stat info;

	ret = stat(path, &info);
	if (ret < 0) {
		return 0;
	}
	return S_ISREG(info.st_mode) || S_ISDIR(info.st_mode);
}

static int _config_read_session_name(const char *path, char **name)
{
	int ret = 0;
	FILE *fp;
	char var[NAME_MAX], *session_name;

#if (NAME_MAX == 255)
#define NAME_MAX_SCANF_IS_A_BROKEN_API "254"
#endif

	session_name = calloc<char>(NAME_MAX);
	if (session_name == nullptr) {
		ret = -ENOMEM;
		ERR("Out of memory");
		goto error;
	}

	fp = open_config(path, "r");
	if (fp == nullptr) {
		ret = -ENOENT;
		goto error;
	}

	while (!feof(fp)) {
		if ((ret = fscanf(fp,
				  "%" NAME_MAX_SCANF_IS_A_BROKEN_API
				  "[^'=']=%" NAME_MAX_SCANF_IS_A_BROKEN_API "s\n",
				  var,
				  session_name)) != 2) {
			if (ret == -1) {
				ERR("Missing session=NAME in config file.");
				goto error_close;
			}
			continue;
		}

		if (strcmp(var, "session") == 0) {
			goto found;
		}
	}

error_close:
	if (fclose(fp) < 0) {
		PERROR("close config read session name");
	}
error:
	free(session_name);
	return ret;
found:
	*name = session_name;
	if (fclose(fp) < 0) {
		PERROR("close config read session name found");
	}
	return ret;
}

/*
 * Returns the session name from the config file.
 *
 * The caller is responsible for freeing the returned string.
 * On error, NULL is returned.
 */
char *config_read_session_name(const char *path)
{
	int ret;
	char *name = nullptr;

	ret = _config_read_session_name(path, &name);
	if (ret == -ENOENT) {
		const char *home_dir = utils_get_home_dir();

		ERR("Can't find valid lttng config %s/.lttngrc", home_dir);
		MSG("Did you create a session? (lttng create <my_session>)");
	}

	return name;
}

/*
 * Returns the session name from the config file. (no warnings/errors emitted)
 *
 * The caller is responsible for freeing the returned string.
 * On error, NULL is returned.
 */
char *config_read_session_name_quiet(const char *path)
{
	char *name = nullptr;

	(void) _config_read_session_name(path, &name);
	return name;
}

/*
 * Write session name option to the config file.
 * On success, returns 0;
 * on error, returns -1.
 */
int config_add_session_name(const char *path, const char *name)
{
	std::string attribute;
	try {
		attribute = fmt::format("session={}", name);
	} catch (const std::exception& ex) {
		ERR_FMT("Failed to format session name attribute for configuration file: {}",
			ex.what());
		return -1;
	}

	return write_config(path, attribute.size(), attribute.c_str());
}

/*
 * Init configuration directory and file.
 * On success, returns 0;
 * on error, returns -1.
 */
int config_init(const char *session_name)
{
	int ret;
	const char *path;

	path = utils_get_home_dir();
	if (path == nullptr) {
		ret = -1;
		goto error;
	}

	/* Create default config file */
	ret = create_config_file(path);
	if (ret < 0) {
		goto error;
	}

	ret = config_add_session_name(path, session_name);
	if (ret < 0) {
		goto error;
	}

	DBG("Init config session in %s", path);

error:
	return ret;
}
