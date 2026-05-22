/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "trigger-utils.hpp"

#include <common/credentials.hpp>
#include <common/error.hpp>
#include <common/format.hpp>
#include <common/optional.hpp>

#include <lttng/trigger/trigger-internal.hpp>

namespace ls = lttng::sessiond;

bool ls::is_trigger_allowed_for_session(const lttng_trigger *trigger,
					const ltt_session::locked_ref& session)
{
	const struct lttng_credentials session_creds = {
		.uid = LTTNG_OPTIONAL_INIT_VALUE(session->uid),
		.gid = LTTNG_OPTIONAL_INIT_VALUE(session->gid),
	};
	const struct lttng_credentials *const trigger_creds =
		lttng_trigger_get_credentials(trigger);

	LTTNG_ASSERT(trigger_creds);

	const bool is_allowed = lttng_credentials_is_equal_uid(trigger_creds, &session_creds) ||
		(lttng_credentials_get_uid(trigger_creds) == 0);
	if (!is_allowed) {
		WARN_FMT(
			"Trigger is not allowed to interact with session `{}`: session uid={}, session gid={}, trigger uid={}",
			session->name,
			session->uid,
			session->gid,
			lttng_credentials_get_uid(trigger_creds));
	}

	return is_allowed;
}
