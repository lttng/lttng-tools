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
#include "../hashtable/hash.h"

/*
 * Init command for tracer with cmd type and correct handle.
 */
static void init_command(int cmd, int handle, struct lttcomm_ust_msg *command)
{
	memset(command, 0, sizeof(struct lttcomm_ust_msg));

	command->cmd = cmd;
	command->handle = handle;
}

/*
 * Generic send command to ust tracer. Caller must free reply.
 */
static struct lttcomm_ust_reply *send_command(int sock,
		struct lttcomm_ust_msg *command)
{
	struct lttcomm_ust_reply *reply;

	reply = ustcomm_send_command(sock, command);
	if (reply == NULL) {
		goto error;
	}

	if (reply->ret_code != LTTCOMM_OK) {
		ERR("Return code (%d): %s", reply->ret_code,
				lttcomm_get_readable_code(reply->ret_code));
		goto error;
	}

	return reply;

error:
	return NULL;
}

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
 *
 * Return handle if success else negative value.
 */
int ustctl_create_session(int sock, struct ltt_ust_session *session)
{
	int ret;
	struct lttcomm_ust_msg command;
	struct lttcomm_ust_reply *reply = NULL;

	command.cmd = LTTNG_UST_SESSION;
	command.handle = LTTNG_UST_ROOT_HANDLE;

	reply = ustcomm_send_command(sock, &command);
	if (reply == NULL) {
		goto error;
	}

	/* Save session handle */
	ret = reply->ret_val;
	free(reply);

	DBG2("ustctl create session command successful with handle %d", ret);

	return ret;

error:
	free(reply);
	return -1;
}

/*
 * Create UST channel to the tracer.
 *
 * Return handle if success else negative value.
 */
int ustctl_create_channel(int sock, struct ltt_ust_session *session,
		struct lttng_ust_channel *channel)
{
	int ret;
	struct lttcomm_ust_msg command;
	struct lttcomm_ust_reply *reply = NULL;

	init_command(LTTNG_UST_CHANNEL, session->handle, &command);
	/* Copy channel attributes to command */
	memcpy(&command.u.channel, channel, sizeof(command.u.channel));

	/* Send command to tracer */
	reply = send_command(sock, &command);
	if (reply == NULL) {
		goto error;
	}

	ret = reply->ret_val;
	free(reply);

	return ret;

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

	init_command(LTTNG_UST_ENABLE, chan->handle, &command);

	reply = ustcomm_send_command(sock, &command);
	if (reply == NULL) {
		goto error;
	}

	if (reply->handle != chan->handle) {
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

	if (reply->handle != chan->handle) {
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
