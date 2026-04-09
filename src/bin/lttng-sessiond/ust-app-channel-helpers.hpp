/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_UST_APP_CHANNEL_HELPERS_HPP
#define LTTNG_SESSIOND_UST_APP_CHANNEL_HELPERS_HPP

#include "ust-stream-group.hpp"
#include "ust-trace-class.hpp"

struct ust_app_channel;

/*
 * Low-level channel helpers shared between ust-app.cpp and
 * ust-domain-orchestrator.cpp.
 *
 * Declared here rather than in ust-app.hpp because their signatures
 * use types (stream_group, trace_class::locked_ref) that require full
 * definitions not available in the public header.
 */
int send_channel_uid_to_ust(lttng::sessiond::ust::stream_group& stream_group,
			    lttng::sessiond::ust::app *app,
			    lttng::sessiond::ust::app_session *ua_sess,
			    struct ust_app_channel *ua_chan);
void delete_ust_app_channel(int sock,
			    struct ust_app_channel *ua_chan,
			    lttng::sessiond::ust::app *app,
			    const lttng::sessiond::ust::trace_class::locked_ref& locked_registry);

#endif /* LTTNG_SESSIOND_UST_APP_CHANNEL_HELPERS_HPP */
