/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_UST_COUNTER_EVENT_ATTACHMENT_HPP
#define LTTNG_SESSIOND_UST_COUNTER_EVENT_ATTACHMENT_HPP

#include "ust-object-data.hpp"

struct lttng_ust_abi_object_data;

namespace lttng {
namespace sessiond {
namespace ust {

struct app;

/*
 * RAII handle for one application's installation of one counter-event rule on
 * a map channel.
 *
 * Owns the lttng_ust_abi_object_data returned by
 * lttng_ust_ctl_counter_create_event and releases it via the application's
 * command socket on destruction.
 *
 * This relies on the same teardown ordering as ust::map_group::app_handle: the
 * owning app_session is destroyed while the referenced ust::app is still alive.
 */
class counter_event_attachment final {
public:
	/*
	 * Takes ownership of `event_handle` and stores it without issuing socket I/O.
	 */
	counter_event_attachment(ust::app& app, lttng_ust_abi_object_data *event_handle) noexcept;
	~counter_event_attachment();

	counter_event_attachment(counter_event_attachment&& other) noexcept;
	counter_event_attachment(const counter_event_attachment&) = delete;
	counter_event_attachment& operator=(const counter_event_attachment&) = delete;
	counter_event_attachment& operator=(counter_event_attachment&&) = delete;

private:
	ust::app& _app;
	bool _moved_from = false;
	ust_object_data _event_handle;
};

} /* namespace ust */
} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_SESSIOND_UST_COUNTER_EVENT_ATTACHMENT_HPP */
