/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <lttng-sessiond-comm.h>
#include <lttngerr.h>

#include "ust-comm.h"
#include "ust-ctl.h"

/*
 * Send registration done packet to the application.
 */
int ustctl_register_done(int sock)
{
	struct lttcomm_ust_msg command;
	struct lttcomm_ust_reply *reply;

	DBG("Sending register done command to %d", sock);

	command.cmd = LTTNG_UST_REGISTER_DONE;
	command.handle = LTTNG_UST_ROOT_HANDLE;

	reply = ustcomm_send_command(sock, &command);
	if (reply == NULL) {
		goto error;
	}

	if (reply->ret_code != LTTCOMM_OK) {
		DBG("Return code: %s", lttcomm_get_readable_code(reply->ret_code));
		goto error;
	}

	return 0;

error:
	return -1;
}

/*
 * Create an UST session on the tracer.
 */
int ustctl_create_session(struct ltt_ust_session *session)
{
	struct lttcomm_ust_msg command;
	struct lttcomm_ust_reply *reply;

	DBG("Creating UST session for app pid:%d", session->app->pid);

	command.cmd = LTTNG_UST_SESSION;
	command.handle = LTTNG_UST_ROOT_HANDLE;

	reply = ustcomm_send_command(session->app->sock, &command);
	if (reply == NULL) {
		goto error;
	}

	if (reply->ret_code != LTTCOMM_OK) {
		DBG("Return code: %s", lttcomm_get_readable_code(reply->ret_code));
		goto error;
	}

	/* Save session handle */
	session->handle = reply->handle;

	return 0;

error:
	return -1;
}
