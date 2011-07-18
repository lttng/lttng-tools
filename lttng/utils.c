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

#include <lttng/lttng.h>

#include "conf.h"

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
	return session_name;
}

/*
 *  set_session_name
 *
 *  Get session name and set it for the lttng control lib.
 */
int set_session_name(char *name)
{
	int ret;
	char *session_name;

	if (!name) {
		session_name = get_session_name();
		if (session_name == NULL) {
			ret = -1;
			goto error;
		}
	} else {
		session_name = name;
	}

	lttng_set_session_name(session_name);
	if (!name)
		free(session_name);

	ret = 0;

error:
	return ret;
}
