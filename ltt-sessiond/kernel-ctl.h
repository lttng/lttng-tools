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

#ifndef _LTT_KERNEL_CTL_H
#define _LTT_KERNEL_CTL_H

#include "session.h"
#include "trace.h"

int kernel_create_session(struct ltt_session *session, int tracer_fd);
int kernel_create_channel(struct ltt_kernel_session *session);
int kernel_enable_event(struct ltt_kernel_session *session, char *name);
int kernel_open_metadata(struct ltt_kernel_session *session);
int kernel_create_metadata_stream(struct ltt_kernel_session *session);
int kernel_create_channel_stream(struct ltt_kernel_channel *channel);
int kernel_start_session(struct ltt_kernel_session *session);
int kernel_stop_session(struct ltt_kernel_session *session);

#endif /* _LTT_KERNEL_CTL_H */
