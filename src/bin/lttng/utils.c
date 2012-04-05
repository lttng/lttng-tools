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
#include <stdlib.h>
#include <ctype.h>
#include <limits.h>

#include <common/error.h>

#include "conf.h"
#include "utils.h"

/*
 * Return the realpath(3) of the path even if the last directory token does not
 * exist. For example, with /tmp/test1/test2, if test2/ does not exist but the
 * /tmp/test1 does, the real path is returned. In normal time, realpath(3)
 * fails if the end point directory does not exist.
 */
char *expand_full_path(const char *path)
{
	const char *end_path = path;
	char *next, *cut_path, *expanded_path;

	/* Find last token delimited by '/' */
	while ((next = strpbrk(end_path + 1, "/"))) {
		end_path = next;
	}

	/* Cut last token from original path */
	cut_path = strndup(path, end_path - path);

	expanded_path = malloc(PATH_MAX);
	if (expanded_path == NULL) {
		goto error;
	}

	expanded_path = realpath((char *)cut_path, expanded_path);
	if (expanded_path == NULL) {
		switch (errno) {
		case ENOENT:
			ERR("%s: No such file or directory", cut_path);
			break;
		default:
			perror("realpath");
			break;
		}
		goto error;
	}

	/* Add end part to expanded path */
	strcat(expanded_path, end_path);

	free(cut_path);
	return expanded_path;

error:
	free(cut_path);
	return NULL;
}

/*
 *  get_session_name
 *
 *  Return allocated string with the session name found in the config
 *  directory.
 */
char *get_session_name(void)
{
	char *path, *session_name = NULL;

	/* Get path to config file */
	path = config_get_default_path();
	if (path == NULL) {
		goto error;
	}

	/* Get session name from config */
	session_name = config_read_session_name(path);
	if (session_name == NULL) {
		goto error;
	}

	DBG2("Config file path found: %s", path);
	DBG("Session name found: %s", session_name);
	return session_name;

error:
	return NULL;
}


/*
 * list_cmd_options
 *
 * Prints a simple list of the options available to a command. This is intended
 * to be easily parsed for bash completion.
 */
void list_cmd_options(FILE *ofp, struct poptOption *options)
{
	int i;
	struct poptOption *option = NULL;

	for (i = 0; options[i].longName != NULL; i++) {
		option = &options[i];

		fprintf(ofp, "--%s\n", option->longName);

		if (isprint(option->shortName)) {
			fprintf(ofp, "-%c\n", option->shortName);
		}
	}
}
