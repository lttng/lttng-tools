/*
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 * SPDX-FileCopyrightText: 2016 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_UST_APP_CHANNEL_HPP
#define LTTNG_SESSIOND_UST_APP_CHANNEL_HPP

#include "lttng-ust-ctl.hpp"
#include "ust-app.hpp"
#include "ust-stream-group.hpp"
#include "ust-trace-class.hpp"

#include <common/defaults.hpp>
#include <common/hashtable/hashtable.hpp>

#include <vendor/optional.hpp>

#include <memory>
#include <stdint.h>
#include <unordered_map>
#include <vector>

namespace lttng {
namespace sessiond {
namespace ust {
class app_channel;
class app_context;
class app_event;
class app_stream;
} /* namespace ust */
} /* namespace sessiond */
} /* namespace lttng */

namespace lttng {
namespace sessiond {
namespace ust {

class app_channel {
public:
	explicit app_channel(lttng::sessiond::ust::app_session& session_,
			     const lttng::sessiond::config::channel_configuration& channel_config_);

	~app_channel();
	app_channel(const app_channel&) = delete;
	app_channel(app_channel&&) = delete;
	app_channel& operator=(const app_channel&) = delete;
	app_channel& operator=(app_channel&&) = delete;

	/* Enable channel on the UST tracer and update local state. */
	void enable();

	/* Disable channel on the UST tracer and update local state. */
	void disable();

	/*
	 * Initialize per-app channel attributes from its
	 * recording_channel_configuration. The trace_class_stream_class_handle
	 * and channel type are set by the caller.
	 */
	void init_from_config();

	/*
	 * Create a context on the UST tracer for this channel and register it in
	 * the local context map.
	 */
	void create_context(const lttng::sessiond::config::context_configuration& context_config,
			    const lttng_ust_context_attr *uctx = nullptr);

	/*
	 * Send channel and stream buffers to the application (per-PID mode).
	 * After a successful call, the channel's stream vector is empty:
	 * streams are discarded locally after being sent to the tracer.
	 */
	void send_to_app_per_pid();

	/*
	 * Send a per-UID stream group's channel and streams to the application
	 * by duplicating the master objects held by the stream group. Each
	 * application receives duplicated copies of the shared objects.
	 */
	void send_to_app_per_uid(lttng::sessiond::ust::stream_group& stream_group);

	bool enabled = false;
	int handle = 0;
	/*
	 * Unique key used to identify the channel on the consumer side.
	 * 0 is a reserved 'invalid' value used to indicate that the consumer
	 * does not know about this channel (i.e. an error occurred).
	 */
	uint64_t key = 0;
	/*
	 * Opaque handle for trace_class::channel() lookups. Copied from
	 * ltt_ust_channel::trace_class_stream_class_handle during per-app
	 * channel creation.
	 */
	uint64_t trace_class_stream_class_handle = 0;
	/* Number of stream that this channel is expected to receive. */
	unsigned int expected_stream_count = 0;
	struct lttng_ust_abi_object_data *obj = nullptr;
	struct lttng_ust_ctl_consumer_channel_attr attr = {};
	/* Owned streams. Order matters (matches CPU index). */
	std::vector<std::unique_ptr<lttng::sessiond::ust::app_stream>> streams;
	/* Session that owns this channel. */
	lttng::sessiond::ust::app_session& session;
	/*
	 * Per-app contexts indexed by their context configuration. The
	 * configuration pointer is stable for the lifetime of the recording
	 * session.
	 */
	std::unordered_map<const lttng::sessiond::config::context_configuration *,
			   std::unique_ptr<app_context>>
		contexts;
	/*
	 * Per-app events indexed by their event rule configuration. The
	 * configuration pointer is stable for the lifetime of the recording
	 * session.
	 */
	std::unordered_map<const lttng::sessiond::config::event_rule_configuration *,
			   std::unique_ptr<app_event>>
		events;
	/*
	 * RAII token: registers this channel's UST tracer-side handle
	 * in the owning app's objd_registry. Deregisters automatically
	 * when this channel is destroyed.
	 *
	 * Optional because the token is acquired after the channel
	 * handle is obtained from the tracer (not at construction time).
	 */
	nonstd::optional<lttng::sessiond::ust::app_objd_registry::registration_token> objd_token;
	/*
	 * Reference to the channel configuration from which this per-app
	 * channel was derived. Points to a recording_channel_configuration
	 * for data channels or a metadata_channel_configuration for the
	 * metadata channel. Use static_cast to the appropriate derived
	 * type as needed.
	 */
	const lttng::sessiond::config::channel_configuration& channel_config;
};

/*
 * Represents a single stream within a per-app channel.
 *
 * Streams are populated by the consumer daemon (ust_consumer_get_channel)
 * and either sent to the UST tracer (per-PID) or transferred to a
 * stream_group (per-UID). The destructor releases the UST object via
 * the owning app's locked command socket.
 */
class app_stream {
public:
	explicit app_stream(app_channel& channel);
	~app_stream();

	app_stream(const app_stream&) = delete;
	app_stream& operator=(const app_stream&) = delete;
	app_stream(app_stream&& other) noexcept;
	app_stream& operator=(app_stream&&) = delete;

	int handle = -1;
	::lttng_ust_abi_object_data *obj = nullptr;

	/*
	 * Transfer ownership of the UST object data to the caller.
	 * The caller assumes responsibility for the object's lifecycle,
	 * including releasing it and accounting for file descriptors.
	 *
	 * Returns the pointer and nullifies the internal reference.
	 */
	::lttng_ust_abi_object_data *release_obj() noexcept;

	/*
	 * Release local resources (close local FDs, free object memory,
	 * return FD budget) without sending a release command to the
	 * tracer. Used after the stream has been sent to the tracer
	 * and the session daemon no longer needs its local copy.
	 */
	void discard_locally() noexcept;

private:
	app_channel& _channel;
};

} /* namespace ust */
} /* namespace sessiond */
} /* namespace lttng */

#ifdef HAVE_LIBLTTNG_UST_CTL

int do_consumer_create_channel(struct consumer_output *consumer,
			       lttng::sessiond::ust::app_session *ua_sess,
			       lttng::sessiond::ust::app_channel *ua_chan,
			       int bitness,
			       lttng::sessiond::ust::trace_class *registry,
			       struct lttng_trace_chunk *current_trace_chunk,
			       enum lttng_trace_format trace_format,
			       unsigned int output_traces,
			       unsigned int live_timer_interval);
enum lttng_ust_abi_chan_type allocation_policy_to_ust_channel_type(
	lttng::sessiond::config::recording_channel_configuration::buffer_allocation_policy_t policy);
lttng::sessiond::config::recording_channel_configuration::buffer_allocation_policy_t
ust_channel_type_to_allocation_policy(enum lttng_ust_abi_chan_type type);

#endif /* HAVE_LIBLTTNG_UST_CTL */

#endif /* LTTNG_SESSIOND_UST_APP_CHANNEL_HPP */
