/*
 * SPDX-FileCopyrightText: 2025 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#define _LGPL_SOURCE
#include "lttng-ctl-helper.hpp"

#include <common/macros.hpp>
#include <common/sessiond-comm/sessiond-comm.hpp>

#include <lttng/domain-internal.hpp>
#include <lttng/reclaim-internal.hpp>
#include <lttng/reclaim.h>

#include <string.h>

/*
 * Reclaim memory for a channel in a session.
 *
 * Return LTTNG_RECLAIM_CHANNEL_MEMORY_STATUS_OK on success else a negative value.
 */
enum lttng_reclaim_channel_memory_status
lttng_reclaim_channel_memory(const char *session_name,
			     const char *channel_name,
			     enum lttng_domain_type domain,
			     uint64_t older_than_us,
			     uint64_t *reclaimed_memory_size_bytes)
{
	enum lttng_reclaim_channel_memory_status status = LTTNG_RECLAIM_CHANNEL_MEMORY_STATUS_OK;
	struct lttcomm_session_msg lsm;
	struct lttng_reclaim_channel_memory_return *reclaim_return = nullptr;
	size_t channel_name_len;
	int ret;

	if (!session_name || !channel_name || !reclaimed_memory_size_bytes) {
		status = LTTNG_RECLAIM_CHANNEL_MEMORY_STATUS_INVALID_PARAMETER;
		goto end;
	}

	channel_name_len = strlen(channel_name);
	if (channel_name_len >= sizeof(lsm.u.reclaim_channel_memory.channel_name)) {
		status = LTTNG_RECLAIM_CHANNEL_MEMORY_STATUS_INVALID_PARAMETER;
		goto end;
	}

	/* Setup session message */
	memset(&lsm, 0, sizeof(lsm));
	lsm.cmd_type = LTTCOMM_SESSIOND_COMMAND_RECLAIM_CHANNEL_MEMORY;

	ret = lttng_strncpy(lsm.session.name, session_name, sizeof(lsm.session.name));
	if (ret) {
		status = LTTNG_RECLAIM_CHANNEL_MEMORY_STATUS_INVALID_PARAMETER;
		goto end;
	}

	/* Set domain */
	lsm.domain.type = domain;

	/* Set channel name and parameters */
	ret = lttng_strncpy(lsm.u.reclaim_channel_memory.channel_name,
			    channel_name,
			    sizeof(lsm.u.reclaim_channel_memory.channel_name));
	if (ret) {
		status = LTTNG_RECLAIM_CHANNEL_MEMORY_STATUS_INVALID_PARAMETER;
		goto end;
	}

	lsm.u.reclaim_channel_memory.older_than_us = older_than_us;

	/* Ask sessiond */
	ret = lttng_ctl_ask_sessiond(&lsm, (void **) &reclaim_return);
	if (ret < 0) {
		status = LTTNG_RECLAIM_CHANNEL_MEMORY_STATUS_ERROR;
		goto end;
	}

	/* Copy the result */
	*reclaimed_memory_size_bytes = reclaim_return->reclaimed_memory_size_bytes;

end:
	free(reclaim_return);
	return status;
}
