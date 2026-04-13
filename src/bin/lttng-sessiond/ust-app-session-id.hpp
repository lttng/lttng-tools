/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef LTTNG_SESSIOND_UST_APP_SESSION_ID_HPP
#define LTTNG_SESSIOND_UST_APP_SESSION_ID_HPP

#include "ust-application-abi.hpp"

#include <common/credentials.hpp>

#include <cstdint>

namespace lttng {
namespace sessiond {
namespace ust {

/*
 * Immutable identifying properties of an app_session. These are set
 * at creation time and never change, making them safe to read without
 * holding the app_session lock.
 *
 * Used by the notification handling thread to look up the trace_class
 * via the global trace_class_index.
 */
struct app_session_identifier {
	using application_abi = lttng::sessiond::ust::application_abi;
	enum class buffer_allocation_policy : std::uint8_t { PER_PID, PER_UID };

	/* Unique identifier of the app_session. */
	std::uint64_t app_session_id;
	/* Unique identifier of the ltt_session (recording session). */
	std::uint64_t recording_session_id;
	/* Credentials of the application which owns the app_session. */
	lttng_credentials app_credentials;
	application_abi abi;
	buffer_allocation_policy allocation_policy;
};

} /* namespace ust */
} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_SESSIOND_UST_APP_SESSION_ID_HPP */
