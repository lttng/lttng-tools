/*
 * Copyright (c)  2011 David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2 only,
 * as published by the Free Software Foundation.
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
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <common/error.h>
#include <common/utils.h>

#include "conf.h"

/*
 * Returns the full path of the lttng user configuration file or NULL on error.
 *
 * Caller MUST free return value.
 */
static char *get_conf_file_path(void)
{
	int ret;
	char *file_path = NULL;
	const char *home_path;

	home_path = utils_get_home_dir();
	if (!home_path) {
		goto error;
	}

	ret = asprintf(&file_path, "%s/%s", home_path, CONFIG_FILENAME);
	if (ret < 0) {
		ERR("Fail allocating config file path");
		file_path = NULL;
	}

error:
	return file_path;
}

/*
 * Returns 1 if config exists, 0 otherwise
 */
static int conf_file_exists(const char *path)
{
	int ret;
	struct stat info;

	ret = stat(path, &info);
	if (ret < 0) {
		return 0;
	}
	return S_ISREG(info.st_mode) || S_ISDIR(info.st_mode);
}

/*
 * Returns an open FILE pointer to the config file;
 * on error, NULL is returned.
 */
static FILE *open_config(const char *mode)
{
	FILE *fp = NULL;
	char *file_path;

	file_path = get_conf_file_path();
	if (file_path == NULL) {
		goto error;
	}

	fp = fopen(file_path, mode);
	if (fp == NULL) {
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
static int create_config_file(void)
{
	int ret;
	FILE *fp;

	fp = open_config("w+");
	if (fp == NULL) {
		ERR("Unable to create config file");
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
static int write_config(size_t size, char *data)
{
	FILE *fp;
	size_t len;
	int ret = 0;

	fp = open_config("a");
	if (fp == NULL) {
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
static void destroy_config(void)
{
	int ret;
	char *config_path;

	config_path = get_conf_file_path();
	if (config_path == NULL) {
		return;
	}

	if (!conf_file_exists(config_path)) {
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
void conf_destroy_default(void)
{
	destroy_config();
}

/*
 * Returns the session name from the config file.
 * The caller is responsible for freeing the returned string.
 * On error, NULL is returned.
 */
char *conf_read_session_name(void)
{
	int ret;
	FILE *fp;
	char var[NAME_MAX], *session_name;
#if (NAME_MAX == 255)
#define NAME_MAX_SCANF_IS_A_BROKEN_API	"254"
#endif

	session_name = malloc(NAME_MAX);
	if (session_name == NULL) {
		ERR("Out of memory");
		goto error;
	}

	fp = open_config("r");
	if (fp == NULL) {
		ERR("Can't find valid lttng config .lttngrc");
		MSG("Did you create a session? (lttng create <my_session>)");
		free(session_name);
		goto error;
	}

	while (!feof(fp)) {
		if ((ret = fscanf(fp, "%" NAME_MAX_SCANF_IS_A_BROKEN_API
				"[^'=']=%" NAME_MAX_SCANF_IS_A_BROKEN_API "s\n",
				var, session_name)) != 2) {
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
	free(session_name);
	ret = fclose(fp);
	if (ret < 0) {
		PERROR("close config read session name");
	}

error:
	return NULL;

found:
	ret = fclose(fp);
	if (ret < 0) {
		PERROR("close config read session name found");
	}
	return session_name;

}

/*
 * Write session name option to the config file.
 * On success, returns 0;
 * on error, returns -1.
 */
int conf_add_session_name(char *name)
{
	int ret;
	char *attr = "session=";
	/* Max name len accepted plus attribute's len and the NULL byte. */
	char session_name[NAME_MAX + strlen(attr) + 1];

	/*
	 * With GNU C <  2.1, snprintf returns -1 if the target buffer is too small;
	 * With GNU C >= 2.1, snprintf returns the required size (excluding closing null)
	 */
	ret = snprintf(session_name, sizeof(session_name), "%s%s\n", attr, name);
	if (ret < 0) {
		ret = -1;
		goto error;
	}
	ret = write_config(ret, session_name);
error:
	return ret;
}

/*
 * Init configuration directory and file.
 * On success, returns 0;
 * on error, returns -1.
 */
int conf_init(void)
{
	int ret;

	/* Create default config file */
	ret = create_config_file();
	if (ret < 0) {
		goto error;
	}

	DBG("LTTng rc configuration created");

error:
	return ret;
}
