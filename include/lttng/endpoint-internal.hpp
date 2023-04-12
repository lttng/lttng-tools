/*
 * Copyright (C) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_ENDPOINT_INTERNAL_H
#define LTTNG_ENDPOINT_INTERNAL_H

#include <common/macros.hpp>

#include <lttng/endpoint.h>

enum lttng_endpoint_type {
	LTTNG_ENDPOINT_TYPE_DEFAULT_SESSIOND_NOTIFICATION = 0,
	LTTNG_ENDPOINT_TYPE_DEFAULT_SESSIOND_COMMAND = 1,
};

struct lttng_endpoint {
	enum lttng_endpoint_type type;
};

#endif /* LTTNG_ENDPOINT_INTERNAL_H */
