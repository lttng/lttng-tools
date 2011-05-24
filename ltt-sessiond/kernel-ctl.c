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
#include <string.h>

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
	struct lttng_kernel_channel *chan;

	lkc = malloc(sizeof(struct ltt_kernel_channel));
	chan = malloc(sizeof(struct lttng_kernel_channel));

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
		perror("ioctl create channel");
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

/*
 *  kernel_enable_event
 *
 *  Enable kernel event.
 */
int kernel_enable_event(struct ltt_kernel_channel *channel, char *name)
{
	int ret;
	struct ltt_kernel_event *event;
	struct lttng_kernel_event *lke;

	event = malloc(sizeof(struct ltt_kernel_event));
	lke = malloc(sizeof(struct lttng_kernel_event));

	if (event == NULL || lke == NULL) {
		perror("kernel enable event malloc");
		ret = -errno;
		goto error;
	}

	/* Setting up a kernel event */
	strncpy(lke->name, name, LTTNG_SYM_NAME_LEN);
	lke->instrumentation = LTTNG_KERNEL_TRACEPOINTS;
	event->event = lke;

	ret = kernctl_create_event(channel->fd, lke);
	if (ret < 0) {
		goto error;
	}

	/* Add event to event list */
	cds_list_add(&event->list, &channel->events_list.head);

	return 0;

error:
	return ret;
}

/*
 *  kernel_open_metadata
 *
 *  Open metadata stream.
 */
int kernel_open_metadata(struct ltt_kernel_session *session)
{
	int ret;
	struct ltt_kernel_metadata *lkm;
	struct lttng_kernel_channel *conf;

	lkm = malloc(sizeof(struct ltt_kernel_metadata));
	conf = malloc(sizeof(struct lttng_kernel_channel));

	if (lkm == NULL || conf == NULL) {
		perror("kernel open metadata malloc");
		ret = -errno;
		goto error;
	}

	conf->overwrite = DEFAULT_KERNEL_OVERWRITE;
	conf->subbuf_size = DEFAULT_KERNEL_SUBBUF_SIZE;
	conf->num_subbuf = DEFAULT_KERNEL_SUBBUF_NUM;
	conf->switch_timer_interval = DEFAULT_KERNEL_SWITCH_TIMER;
	conf->read_timer_interval = DEFAULT_KERNEL_READ_TIMER;

	ret = kernctl_open_metadata(session->fd, conf);
	if (ret < 0) {
		goto error;
	}

	session->metadata = lkm;
	session->metadata->fd = ret;
	session->metadata->conf = conf;

	return 0;

error:
	return ret;
}
