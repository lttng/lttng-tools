/*
 * Copyright (C) 2012 - Christian Babeux <christian.babeux@efficios.com>
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

#ifndef SESSIOND_TESTPOINT_H
#define SESSIOND_TESTPOINT_H

#include <common/testpoint/testpoint.h>

/* Testpoints, internal use only */
TESTPOINT_DECL(sessiond_thread_manage_clients);
TESTPOINT_DECL(sessiond_thread_manage_clients_before_loop);
TESTPOINT_DECL(sessiond_thread_registration_apps);
TESTPOINT_DECL(sessiond_thread_manage_apps);
TESTPOINT_DECL(sessiond_thread_manage_apps_before_loop);
TESTPOINT_DECL(sessiond_thread_manage_kernel);
TESTPOINT_DECL(sessiond_thread_manage_kernel_before_loop);
TESTPOINT_DECL(sessiond_thread_manage_consumer);
TESTPOINT_DECL(sessiond_thread_ht_cleanup);
TESTPOINT_DECL(sessiond_thread_app_manage_notify);
TESTPOINT_DECL(sessiond_thread_app_reg_dispatch);

#endif /* SESSIOND_TESTPOINT_H */
