/*
 * SPDX-FileCopyrightText: 2019 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_SESSION_INTERNAL_H
#define LTTNG_SESSION_INTERNAL_H

#include <common/macros.hpp>
#include <common/make-unique-wrapper.hpp>

#include <lttng/constant.h>

struct lttng_session;

struct lttng_session_extended {
	struct {
		uint64_t value;
		uint8_t is_set;
	} LTTNG_PACKED creation_time;
	struct {
		char value[LTTNG_PATH_MAX];
	} LTTNG_PACKED shm_path;

	/* enum lttng_trace_format */
	uint8_t trace_format;
} LTTNG_PACKED;

#endif /* LTTNG_SESSION_INTERNAL_H */
