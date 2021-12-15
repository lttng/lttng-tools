/*
 * Copyright (C) 2019 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef CLEAR_H
#define CLEAR_H

#include "session.hpp"

int cmd_clear_session(struct ltt_session *session, int *sock_fd);

#endif /* CLEAT_H */
