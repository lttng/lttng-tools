/*
 * Copyright (C) 2017 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License, version 2.1 only,
 * as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef LTTNG_ENDPOINT_INTERNAL_H
#define LTTNG_ENDPOINT_INTERNAL_H

#include <lttng/endpoint.h>
#include <common/macros.h>

enum lttng_endpoint_type {
	LTTNG_ENDPOINT_TYPE_DEFAULT_SESSIOND_NOTIFICATION = 0,
};

struct lttng_endpoint {
	enum lttng_endpoint_type type;
};

#endif /* LTTNG_ENDPOINT_INTERNAL_H */
