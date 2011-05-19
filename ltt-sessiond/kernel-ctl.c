/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
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

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>

#include "ltt-sessiond.h"
#include "libkernelctl.h"
#include "kernel-ctl.h"
#include "trace.h"

/*
 *  kernel_create_session
 *
 *  Create a new kernel session using the command context session.
 */
int kernel_create_session(struct command_ctx *cmd_ctx, int tracer_fd)
{
	int ret;
	struct ltt_kernel_session *lks;

	/* Allocate a new kernel session */
	lks = malloc(sizeof(struct ltt_kernel_session));
	if (lks == NULL) {
		perror("kernel session malloc");
		ret = -errno;
		goto error;
	}

	ret = kernctl_create_session(tracer_fd);
	if (ret < 0) {
		goto error;
	}

	/* Assigning session fd and to the command context */
	lks->fd = ret;
	cmd_ctx->session->kernel_session = lks;
	cmd_ctx->session->kern_session_count++;

	return 0;

error:
	return ret;
}

/*
 *  kernel_create_channel
 *
 *  Create a kernel channel within the kernel session.
 */
int kernel_create_channel(struct command_ctx *cmd_ctx)
{
	int ret;
	struct ltt_kernel_channel *lkc;
	struct lttng_channel *chan;

	lkc = malloc(sizeof(struct ltt_kernel_channel));
	chan = malloc(sizeof(struct lttng_channel));

	if (lkc == NULL || chan == NULL) {
		perror("kernel channel malloc");
		ret = -errno;
		goto error;
	}

	chan->overwrite = DEFAULT_KERNEL_OVERWRITE;
	chan->subbuf_size = DEFAULT_KERNEL_SUBBUF_SIZE;
	chan->num_subbuf = DEFAULT_KERNEL_SUBBUF_NUM;
	chan->switch_timer_interval = DEFAULT_KERNEL_SWITCH_TIMER;
	chan->read_timer_interval = DEFAULT_KERNEL_READ_TIMER;

	ret = kernctl_create_channel(cmd_ctx->session->kernel_session->fd, chan);
	if (ret < 0) {
		goto error;
	}

	lkc->fd = ret;
	lkc->channel = chan;
	CDS_INIT_LIST_HEAD(&lkc->events_list.head);

	cmd_ctx->session->kernel_session->channel = lkc;

	return 0;

error:
	return ret;
}
