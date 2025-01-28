/*
 * SPDX-FileCopyrightText: 2019 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef CLEAR_H
#define CLEAR_H

#include "session.hpp"

int cmd_clear_session(const ltt_session::locked_ref& session, int *sock_fd);

#endif /* CLEAT_H */
