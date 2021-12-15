/*
 * Copyright (C) 2013 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef SAVE_H
#define SAVE_H

#include <lttng/save.h>
#include <common/compat/socket.hpp>

int cmd_save_sessions(struct lttng_save_session_attr *attr,
	lttng_sock_cred *creds);

#endif /* SAVE_H */
