/*
 * Copyright (c)  2011 David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
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

#include <stdlib.h>
#include <ctype.h>

#include <common/error.h>

#include "conf.h"
#include "utils.h"

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

error:
	DBG("Session name found: %s", session_name);
	return session_name;
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
