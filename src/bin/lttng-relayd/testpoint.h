#ifndef RELAYD_TESTPOINT_H
#define RELAYD_TESTPOINT_H

/*
 * Copyright (C) 2012 - Christian Babeux <christian.babeux@efficios.com>
 * Copyright (C) 2014 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <common/testpoint/testpoint.h>

/* Testpoints, internal use only */
TESTPOINT_DECL(relayd_thread_dispatcher);
TESTPOINT_DECL(relayd_thread_worker);
TESTPOINT_DECL(relayd_thread_listener);
TESTPOINT_DECL(relayd_thread_live_dispatcher);
TESTPOINT_DECL(relayd_thread_live_worker);
TESTPOINT_DECL(relayd_thread_live_listener);

#endif /* SESSIOND_TESTPOINT_H */
