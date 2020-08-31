/*
 * Copyright (C) 2012 Christian Babeux <christian.babeux@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
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
TESTPOINT_DECL(sessiond_thread_notification);
TESTPOINT_DECL(sessiond_handle_notifier_event_pipe);

#endif /* SESSIOND_TESTPOINT_H */
