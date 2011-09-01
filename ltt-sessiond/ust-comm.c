/*
 * Copyright (C)  2011 - David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; only version 2
 * of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#include <stdlib.h>

#include <lttngerr.h>

#include "ust-comm.h"

/*
 * Send msg containing a command to an UST application via sock and wait for
 * the reply.
 *
 * Return the replied structure or NULL.
 */
struct lttcomm_ust_reply *ustcomm_send_command(int sock,
		struct lttcomm_ust_msg *msg)
{
	ssize_t len;
	struct lttcomm_ust_reply *reply;

	/* Extra safety */
	if (msg == NULL || sock < 0) {
		goto error;
	}

	DBG("Sending UST command %d to sock %d", msg->cmd, sock);

	/* Send UST msg */
	len = lttcomm_send_unix_sock(sock, msg, sizeof(*msg));
	if (len < 0) {
		goto error;
	}

	reply = malloc(sizeof(struct lttcomm_ust_reply));
	if (reply == NULL) {
		perror("malloc ust reply");
		goto error;
	}

	DBG("Receiving UST reply on sock %d", sock);

	/* Get UST reply */
	len = lttcomm_recv_unix_sock(sock, reply, sizeof(*reply));
	if (len < 0 || len < sizeof(*reply)) {
		goto error;
	}

	return reply;

error:
	return NULL;
}
