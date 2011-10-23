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
#include <config.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <ust/lttng-ust-comm.h>
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

	if (reply->ret_code != USTCOMM_OK) {
		DBG("Return code: %s", ustcomm_get_readable_code(reply->ret_code));
		goto error;
	}

	return 0;

error:
	return -1;
}

/*
 * Create an UST session on the tracer.
 */
int ustctl_create_session(int sock, struct ltt_ust_session *session)
{
	struct lttcomm_ust_msg command;
	struct lttcomm_ust_reply *reply = NULL;

	command.cmd = LTTNG_UST_SESSION;
	command.handle = LTTNG_UST_ROOT_HANDLE;

	reply = ustcomm_send_command(sock, &command);
	if (reply == NULL) {
		goto error;
	}

	if (reply->ret_code != USTCOMM_OK) {
		DBG("Return code: %s", ustcomm_get_readable_code(reply->ret_code));
		goto error;
	}

	/* Save session handle */
	session->handle = reply->ret_val;
	free(reply);

	DBG2("ustctl create session command successful");
	return 0;

error:
	free(reply);
	return -1;
}

/*
 * Create UST channel to the tracer.
 */
int ustctl_create_channel(int sock, struct ltt_ust_session *session,
		struct lttng_channel *channel)
{
	struct lttcomm_ust_msg command;
	struct lttcomm_ust_reply *reply = NULL;
	struct ltt_ust_channel *uchan;

	uchan = trace_ust_create_channel(channel, session->path);
	if (uchan == NULL) {
		goto error;
	}

	memset(&command, 0, sizeof(command));

	command.cmd = LTTNG_UST_CHANNEL;
	command.handle = session->handle;

	/* Copy channel attributes to command */
	memcpy(&command.u.channel, &uchan->attr, sizeof(command.u.channel));

	reply = ustcomm_send_command(sock, &command);
	if (reply == NULL) {
		goto error;
	}

	if (reply->ret_code != USTCOMM_OK) {
		DBG("Return code (%d): %s", reply->ret_code,
				ustcomm_get_readable_code(reply->ret_code));
		goto error;
	}

	uchan->handle = reply->ret_val;

	/* Add channel to session */
	cds_list_add(&uchan->list, &session->channels.head);
	session->channels.count++;

	free(reply);

	return 0;

error:
	free(reply);
	return -1;
}

/*
 * Enable UST channel.
 */
int ustctl_enable_channel(int sock, struct ltt_ust_session *session,
		struct ltt_ust_channel *chan)
{
	struct lttcomm_ust_msg command;
	struct lttcomm_ust_reply *reply = NULL;

	memset(&command, 0, sizeof(command));

	command.cmd = LTTNG_UST_ENABLE;
	command.handle = chan->handle;

	reply = ustcomm_send_command(sock, &command);
	if (reply == NULL) {
		goto error;
	}

	if (reply->ret_code != USTCOMM_OK) {
		DBG("Return code (%d): %s", reply->ret_code,
				ustcomm_get_readable_code(reply->ret_code));
		goto error;
	} else if (reply->handle != chan->handle) {
		ERR("Receive wrong handle from UST reply on enable channel");
		goto error;
	}

	chan->enabled = 1;
	free(reply);

	DBG2("ustctl enable channel successful for sock %d", sock);
	return 0;

error:
	free(reply);
	return -1;
}

/*
 * Disable UST channel.
 */
int ustctl_disable_channel(int sock, struct ltt_ust_session *session,
		struct ltt_ust_channel *chan)
{
	struct lttcomm_ust_msg command;
	struct lttcomm_ust_reply *reply = NULL;

	memset(&command, 0, sizeof(command));

	command.cmd = LTTNG_UST_DISABLE;
	command.handle = chan->handle;

	reply = ustcomm_send_command(sock, &command);
	if (reply == NULL) {
		goto error;
	}

	if (reply->ret_code != USTCOMM_OK) {
		DBG("Return code (%d): %s", reply->ret_code,
				ustcomm_get_readable_code(reply->ret_code));
		goto error;
	} else if (reply->handle != chan->handle) {
		ERR("Receive wrong handle from UST reply on enable channel");
		goto error;
	}

	chan->enabled = 1;
	free(reply);

	DBG2("ustctl disable channel successful for sock %d", sock);
	return 0;

error:
	free(reply);
	return -1;
}
