/*
 * Copyright (C) 2014 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define _LGPL_SOURCE
#include <common/error.h>
#include <common/config/session-config.h>

#include "load-session-thread.h"
#include "lttng-sessiond.h"

/*
 * Destroy the thread data previously created with the init function.
 */
void load_session_destroy_data(struct load_session_thread_data *data)
{
	if (!data) {
		return;
	}
}

/*
 * Initialize the thread data. This MUST be called before the thread load
 * session is created.
 *
 * Return 0 on success else a negative value. Note that the destroy function
 * can be called with no or partially initialized data.
 */
int load_session_init_data(struct load_session_thread_data **data)
{
	struct load_session_thread_data *_data = NULL;

	assert(data);

	/*
	 * Allocate memory here since this function is called from the main thread
	 * can die *before* the end of the load session thread.
	 */
	_data = zmalloc(sizeof(*_data));
	if (!_data) {
		PERROR("zmalloc load session info");
		goto error;
	}

	*data = _data;
	return 0;

error:
	free(_data);
	return -1;
}

/*
 * This thread loads session configurations once the session daemon is
 * ready to process client messages.
 */
void *thread_load_session(void *data)
{
	int ret;
	struct load_session_thread_data *info = data;

	DBG("[load-session-thread] Load session");

	/* Override existing session and autoload also. */
	ret = config_load_session(info->path, NULL, 1, 1, NULL);
	if (ret) {
		ERR("Session load failed: %s", error_get_str(ret));
	}

	sessiond_signal_parents();
	return NULL;
}
