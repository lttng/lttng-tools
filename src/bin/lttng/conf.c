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
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <common/error.h>

#include "conf.h"

/*
 *  config_get_file_path
 *
 *  Return the path with '/CONFIG_FILENAME' added to it.
 */
char *config_get_file_path(char *path)
{
	int ret;
	char *file_path;

	ret = asprintf(&file_path, "%s/%s", path, CONFIG_FILENAME);
	if (ret < 0) {
		ERR("Fail allocating config file path");
	}

	return file_path;
}

/*
 *  open_config
 *
 *  Return an open FILE pointer to the config file.
 */
static FILE *open_config(char *path, const char *mode)
{
	FILE *fp = NULL;
	char *file_path;

	file_path = config_get_file_path(path);
	if (file_path == NULL) {
		goto error;
	}

	fp = fopen(file_path, mode);
	if (fp == NULL) {
		goto error;
	}

error:
	if (file_path) {
		free(file_path);
	}
	return fp;
}

/*
 *  create_config_file
 *
 *  Create the empty config file a the path.
 */
static int create_config_file(char *path)
{
	int ret;
	FILE *fp;

	fp = open_config(path, "w+");
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
 *  write_config
 *
 *  Append data to the config file in file_path
 */
static int write_config(char *file_path, size_t size, char *data)
{
	FILE *fp;
	size_t len;
	int ret = 0;

	fp = open_config(file_path, "a");
	if (fp == NULL) {
		ret = -1;
		goto end;
	}

	/* Write session name into config file */
	len = fwrite(data, size, 1, fp);
	if (len < 1) {
		ret = -1;
	}
	fclose(fp);
end:
	return ret;
}

/*
 *  config_get_default_path
 *
 *  Return the HOME directory path. Caller MUST NOT free(3) the return pointer.
 */
char *config_get_default_path(void)
{
	return getenv("HOME");
}

/*
 *  config_destroy
 *
 *  Destroy directory config and file config.
 */
void config_destroy(char *path)
{
	int ret;
	char *config_path;

	config_path = config_get_file_path(path);
	if (config_path == NULL) {
		return;
	}

	ret = remove(config_path);
	if (ret < 0) {
		perror("remove config file");
	}

	free(config_path);
}

/*
 *  config_read_session_name
 *
 *  Return sesson name from the config file.
 */
char *config_read_session_name(char *path)
{
	int ret;
	FILE *fp;
	char var[NAME_MAX], *session_name;

	fp = open_config(path, "r");
	if (fp == NULL) {
		ERR("Can't find valid lttng config %s/.lttngrc", path);
		MSG("Did you create a session? (lttng create <my_sesion>)");
		goto error;
	}

	session_name = malloc(NAME_MAX);
	while (!feof(fp)) {
		if ((ret = fscanf(fp, "%[^'=']=%s\n", var, session_name)) != 2) {
			if (ret == -1) {
				ERR("Missing session=NAME in config file.");
				goto error;
			}
			continue;
		}

		if (strcmp(var, "session") == 0) {
			goto found;
		}
	}

	fclose(fp);

error:
	return NULL;

found:
	fclose(fp);
	return session_name;

}

/*
 *  config_add_session_name
 *
 *  Write session name option to the config file.
 */
int config_add_session_name(char *path, char *name)
{
	int ret;
	char session_name[NAME_MAX];

	ret = snprintf(session_name, NAME_MAX, "session=%s\n", name);
	if (ret < 0) {
		goto error;
	}
	ret = write_config(path, ret, session_name);
error:
	return ret;
}

/*
 *  config_init
 *
 *  Init configuration directory and file.
 */
int config_init(char *session_name)
{
	int ret;
	char *path;

	path = config_get_default_path();
	if (path == NULL) {
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
