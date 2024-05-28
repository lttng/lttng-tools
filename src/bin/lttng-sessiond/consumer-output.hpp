/*
 * Copyright (C) 2024 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_CONSUMER_OUTPUT_HPP
#define LTTNG_CONSUMER_OUTPUT_HPP

#include "session.hpp"

int consumer_set_network_uri(const ltt_session::locked_ref& session,
			     struct consumer_output *obj,
			     struct lttng_uri *uri);

#endif /* LTTNG_CONSUMER_OUTPUT_HPP */
