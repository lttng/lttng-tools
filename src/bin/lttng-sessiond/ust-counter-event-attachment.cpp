/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "ust-app.hpp"
#include "ust-counter-event-attachment.hpp"

#include <common/error.hpp>

#include <utility>

namespace lsu = lttng::sessiond::ust;

lsu::counter_event_attachment::counter_event_attachment(
	ust::app& app, lttng_ust_abi_object_data *event_handle) noexcept :
	_app(app), _event_handle(event_handle)
{
}

lsu::counter_event_attachment::counter_event_attachment(counter_event_attachment&& other) noexcept :
	_app(other._app), _event_handle(std::move(other._event_handle))
{
	other._moved_from = true;
}

lsu::counter_event_attachment::~counter_event_attachment()
{
	if (_moved_from) {
		return;
	}

	LTTNG_ASSERT(_event_handle.get());

	/*
	 * Release the app-side handle through the command socket.
	 *
	 * Communication failures are logged and ignored in destructor context.
	 * Local cleanup is performed by `ust_object_data`.
	 */
	try {
		auto guard = _app.command_socket.lock();

		try {
			guard.release_object(_event_handle.get());
		} catch (const app_communication_error& ex) {
			DBG_FMT("Application unreachable while releasing UST counter-event handle: error=`{}`",
				ex.what());
		} catch (const lttng::runtime_error& ex) {
			DBG_FMT("Failed to release UST counter-event handle: error=`{}`",
				ex.what());
		}
	} catch (const std::exception& ex) {
		ERR_FMT("Failed to release UST counter-event handle via app command socket: error=`{}`",
			ex.what());
	}
}
