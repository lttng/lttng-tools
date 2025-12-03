/*
 * SPDX-FileCopyrightText: 2025 EfficiOS Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef RELAYD_CMD_2_15_H
#define RELAYD_CMD_2_15_H

#include <common/buffer-view.hpp>
#include <common/uuid.hpp>

#include <lttng/session.h>

#include <inttypes.h>
#include <stdbool.h>

int cmd_create_session_2_15(const struct lttng_buffer_view *payload,
			    char *session_name,
			    char *hostname,
			    char *base_path,
			    uint32_t *live_timer,
			    bool *snapshot,
			    uint64_t *id_sessiond,
			    lttng_uuid& sessiond_uuid,
			    bool *has_current_chunk,
			    uint64_t *current_chunk_id,
			    time_t *creation_time,
			    bool *session_name_contains_creation_time,
			    enum lttng_trace_format *trace_format);

#endif /* RELAYD_CMD_2_15_H */
