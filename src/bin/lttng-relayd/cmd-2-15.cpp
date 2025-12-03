/*
 * SPDX-FileCopyrightText: 2025 EfficiOS Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include "cmd-2-11.hpp"
#include "cmd-2-15.hpp"
#include "utils.hpp"

#include <common/common.hpp>
#include <common/compat/endian.hpp>
#include <common/compat/string.hpp>
#include <common/sessiond-comm/relayd.hpp>

#include <lttng/constant.h>

#include <inttypes.h>

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
			    enum lttng_trace_format *trace_format)
{
	int ret;
	struct lttcomm_relayd_create_session_2_15 header;
	const size_t header_len = sizeof(header);

	if (payload->size < header_len) {
		ERR("Unexpected payload size in \"cmd_create_session_2_15\": expected >= %zu bytes, got %zu bytes",
		    header_len,
		    payload->size);
		return -1;
	}
	memcpy(&header, payload->data, header_len);

	/* Convert trace_format to host byte order. */
	header.trace_format = be32toh(header.trace_format);

	if (header.trace_format != LTTNG_TRACE_FORMAT_CTF_1_8 &&
	    header.trace_format != LTTNG_TRACE_FORMAT_CTF_2) {
		ERR_FMT("Invalid trace format value: trace_format={}",
			static_cast<unsigned int>(header.trace_format));
		return -1;
	}

	const auto names_view = lttng_buffer_view_from_view(payload, header_len, -1);

	/* Use the common base parsing logic shared with 2.11. */
	ret = cmd_create_session_2_11_base_common(&header.base,
						  &names_view,
						  session_name,
						  hostname,
						  base_path,
						  live_timer,
						  snapshot,
						  id_sessiond,
						  sessiond_uuid,
						  has_current_chunk,
						  current_chunk_id,
						  creation_time,
						  session_name_contains_creation_time);
	if (ret < 0) {
		return ret;
	}

	/* Extract the 2.15-specific trace format field. */
	*trace_format = static_cast<enum lttng_trace_format>(header.trace_format);

	return 0;
}
