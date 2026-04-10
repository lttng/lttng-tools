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

#include <stdint.h>
#include <unordered_map>
#include <urcu/list.h>

/* Stream list containing lttng::sessiond::ust::app_stream. */
struct ust_app_stream_list {
	unsigned int count;
	struct cds_list_head head;
};

struct ust_app_channel {
	explicit ust_app_channel(
		const lttng::sessiond::config::channel_configuration& channel_config_) :
		channel_config(channel_config_)
	{
	}

	~ust_app_channel() = default;
	ust_app_channel(const ust_app_channel&) = delete;
	ust_app_channel(ust_app_channel&&) = delete;
	ust_app_channel& operator=(const ust_app_channel&) = delete;
	ust_app_channel& operator=(ust_app_channel&&) = delete;

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
	char name[LTTNG_UST_ABI_SYM_NAME_LEN] = {};
	struct lttng_ust_abi_object_data *obj = nullptr;
	struct lttng_ust_ctl_consumer_channel_attr attr = {};
	struct ust_app_stream_list streams = {};
	/* Session pointer that owns this object. */
	lttng::sessiond::ust::app_session *session = nullptr;
	/* Hashtable of ust_app_ctx instances. */
	struct lttng_ht *ctx = nullptr;
	/*
	 * Per-app events indexed by their event rule configuration. The
	 * configuration pointer is stable for the lifetime of the recording
	 * session.
	 */
	std::unordered_map<const lttng::sessiond::config::event_rule_configuration *,
			   ust_app_event *>
		events;
	/*
	 * Node indexed by channel name in the channels' hash table of a session.
	 */
	struct lttng_ht_node_str node = {};
	/*
	 * Node indexed by UST channel object descriptor (handle). Stored in the
	 * ust_objd hash table in the lttng::sessiond::ust::app object.
	 */
	struct lttng_ht_node_ulong ust_objd_node = {};
	/* For delayed reclaim */
	struct rcu_head rcu_head = {};
	/*
	 * Reference to the channel configuration from which this per-app
	 * channel was derived. Points to a recording_channel_configuration
	 * for data channels or a metadata_channel_configuration for the
	 * metadata channel. Use static_cast to the appropriate derived
	 * type as needed.
	 */
	const lttng::sessiond::config::channel_configuration& channel_config;
};

namespace lttng {
namespace sessiond {
namespace ust {

struct app_stream {
	int handle;
	char pathname[PATH_MAX];
	/* Format is %s_%d respectively channel name and CPU number. */
	char name[DEFAULT_STREAM_NAME_LEN];
	::lttng_ust_abi_object_data *obj;
	/* Using a list of streams to keep order. */
	cds_list_head list;
};

} /* namespace ust */
} /* namespace sessiond */
} /* namespace lttng */

#ifdef HAVE_LIBLTTNG_UST_CTL

struct ust_app_channel *
alloc_ust_app_channel(const char *name,
		      const lttng::sessiond::ust::app_session::locked_weak_ref& ua_sess,
		      struct lttng_ust_abi_channel_attr *attr,
		      const lttng::sessiond::config::recording_channel_configuration& config);
struct ust_app_channel *alloc_ust_app_metadata_channel(
	const char *name,
	const lttng::sessiond::ust::app_session::locked_weak_ref& ua_sess,
	const lttng::sessiond::config::metadata_channel_configuration& metadata_config);
void init_ust_app_channel_from_config(struct ust_app_channel *ua_chan);
void delete_ust_app_channel(int sock,
			    struct ust_app_channel *ua_chan,
			    lttng::sessiond::ust::app *app,
			    const lttng::sessiond::ust::trace_class::locked_ref& locked_registry);
int enable_ust_app_channel(const lttng::sessiond::ust::app_session::locked_weak_ref& ua_sess,
			   lttng::c_string_view channel_name,
			   lttng::sessiond::ust::app *app);
int disable_ust_app_channel(const lttng::sessiond::ust::app_session::locked_weak_ref& ua_sess,
			    struct ust_app_channel *ua_chan,
			    lttng::sessiond::ust::app *app);
int enable_ust_channel(lttng::sessiond::ust::app *app,
		       const lttng::sessiond::ust::app_session::locked_weak_ref& ua_sess,
		       struct ust_app_channel *ua_chan);
int disable_ust_channel(lttng::sessiond::ust::app *app,
			const lttng::sessiond::ust::app_session::locked_weak_ref& ua_sess,
			struct ust_app_channel *ua_chan);
lttng::sessiond::ust::app_stream *ust_app_alloc_stream();
int do_consumer_create_channel(struct consumer_output *consumer,
			       lttng::sessiond::ust::app_session *ua_sess,
			       struct ust_app_channel *ua_chan,
			       int bitness,
			       lttng::sessiond::ust::trace_class *registry,
			       struct lttng_trace_chunk *current_trace_chunk,
			       enum lttng_trace_format trace_format,
			       unsigned int output_traces,
			       unsigned int live_timer_interval);
int send_channel_pid_to_ust(lttng::sessiond::ust::app *app,
			    lttng::sessiond::ust::app_session *ua_sess,
			    struct ust_app_channel *ua_chan);
int send_channel_uid_to_ust(lttng::sessiond::ust::stream_group& stream_group,
			    lttng::sessiond::ust::app *app,
			    lttng::sessiond::ust::app_session *ua_sess,
			    struct ust_app_channel *ua_chan);
enum lttng_ust_abi_chan_type allocation_policy_to_ust_channel_type(
	lttng::sessiond::config::recording_channel_configuration::buffer_allocation_policy_t policy);
lttng::sessiond::config::recording_channel_configuration::buffer_allocation_policy_t
ust_channel_type_to_allocation_policy(enum lttng_ust_abi_chan_type type);

#endif /* HAVE_LIBLTTNG_UST_CTL */

#endif /* LTTNG_SESSIOND_UST_APP_CHANNEL_HPP */
