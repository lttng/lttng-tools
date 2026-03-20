/*
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 * SPDX-FileCopyrightText: 2016 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include "agent.hpp"
#include "channel.hpp"
#include "kernel.hpp"
#include "lttng-sessiond.hpp"
#include "utils.hpp"

#include <common/common.hpp>
#include <common/defaults.hpp>
#include <common/sessiond-comm/sessiond-comm.hpp>

#include <inttypes.h>
#include <string.h>
#include <unistd.h>

/*
 * Return allocated channel attributes.
 */
lttng::ctl::lttng_channel_uptr channel_new_default_attr(lttng_domain_type dom,
							enum lttng_buffer_type type)
{
	const char *channel_name = DEFAULT_CHANNEL_NAME;

	lttng::ctl::lttng_channel_uptr chan(lttng_channel_create_internal());
	if (!chan) {
		LTTNG_THROW_POSIX("Failed to allocate channel with default attributes", -ENOMEM);
	}

	struct lttng_channel_extended *extended_attr =
		static_cast<lttng_channel_extended *>(chan->attr.extended.ptr);

	chan->enabled = 1;

	/* Same for all domains. */
	chan->attr.overwrite = DEFAULT_CHANNEL_OVERWRITE;
	chan->attr.tracefile_size = DEFAULT_CHANNEL_TRACEFILE_SIZE;
	chan->attr.tracefile_count = DEFAULT_CHANNEL_TRACEFILE_COUNT;

	switch (dom) {
	case LTTNG_DOMAIN_KERNEL:
		LTTNG_ASSERT(type == LTTNG_BUFFER_GLOBAL);
		chan->attr.subbuf_size = default_get_kernel_channel_subbuf_size();
		chan->attr.num_subbuf = DEFAULT_KERNEL_CHANNEL_SUBBUF_NUM;
		chan->attr.output = DEFAULT_KERNEL_CHANNEL_OUTPUT;
		chan->attr.switch_timer_interval = DEFAULT_KERNEL_CHANNEL_SWITCH_TIMER;
		chan->attr.read_timer_interval = DEFAULT_KERNEL_CHANNEL_READ_TIMER;
		chan->attr.live_timer_interval = DEFAULT_KERNEL_CHANNEL_LIVE_TIMER;
		extended_attr->blocking_timeout = DEFAULT_KERNEL_CHANNEL_BLOCKING_TIMEOUT;
		extended_attr->monitor_timer_interval = DEFAULT_KERNEL_CHANNEL_MONITOR_TIMER;
		extended_attr->allocation_policy = DEFAULT_CHANNEL_ALLOCATION_POLICY;
		extended_attr->preallocation_policy = DEFAULT_CHANNEL_PREALLOCATION_POLICY;
		break;
	case LTTNG_DOMAIN_JUL:
		channel_name = DEFAULT_JUL_CHANNEL_NAME;
		goto common_ust;
	case LTTNG_DOMAIN_LOG4J:
		channel_name = DEFAULT_LOG4J_CHANNEL_NAME;
		goto common_ust;
	case LTTNG_DOMAIN_LOG4J2:
		channel_name = DEFAULT_LOG4J2_CHANNEL_NAME;
		goto common_ust;
	case LTTNG_DOMAIN_PYTHON:
		channel_name = DEFAULT_PYTHON_CHANNEL_NAME;
		goto common_ust;
	case LTTNG_DOMAIN_UST:
	common_ust:
		switch (type) {
		case LTTNG_BUFFER_PER_UID:
			chan->attr.subbuf_size = default_get_ust_uid_channel_subbuf_size();
			chan->attr.num_subbuf = DEFAULT_UST_UID_CHANNEL_SUBBUF_NUM;
			chan->attr.output = DEFAULT_UST_UID_CHANNEL_OUTPUT;
			chan->attr.switch_timer_interval = DEFAULT_UST_UID_CHANNEL_SWITCH_TIMER;
			chan->attr.read_timer_interval = DEFAULT_UST_UID_CHANNEL_READ_TIMER;
			chan->attr.live_timer_interval = DEFAULT_UST_UID_CHANNEL_LIVE_TIMER;
			extended_attr->blocking_timeout = DEFAULT_UST_UID_CHANNEL_BLOCKING_TIMEOUT;
			extended_attr->monitor_timer_interval =
				DEFAULT_UST_UID_CHANNEL_MONITOR_TIMER;
			LTTNG_OPTIONAL_SET(
				&extended_attr->watchdog_timer_interval,
				static_cast<uint64_t>(DEFAULT_UST_UID_CHANNEL_WATCHDOG_TIMER));
			extended_attr->allocation_policy = DEFAULT_CHANNEL_ALLOCATION_POLICY;
			extended_attr->preallocation_policy = DEFAULT_CHANNEL_PREALLOCATION_POLICY;
			break;
		case LTTNG_BUFFER_PER_PID:
		default:
			chan->attr.subbuf_size = default_get_ust_pid_channel_subbuf_size();
			chan->attr.num_subbuf = DEFAULT_UST_PID_CHANNEL_SUBBUF_NUM;
			chan->attr.output = DEFAULT_UST_PID_CHANNEL_OUTPUT;
			chan->attr.switch_timer_interval = DEFAULT_UST_PID_CHANNEL_SWITCH_TIMER;
			chan->attr.read_timer_interval = DEFAULT_UST_PID_CHANNEL_READ_TIMER;
			chan->attr.live_timer_interval = DEFAULT_UST_PID_CHANNEL_LIVE_TIMER;
			extended_attr->blocking_timeout = DEFAULT_UST_PID_CHANNEL_BLOCKING_TIMEOUT;
			extended_attr->monitor_timer_interval =
				DEFAULT_UST_PID_CHANNEL_MONITOR_TIMER;
			extended_attr->allocation_policy = DEFAULT_CHANNEL_ALLOCATION_POLICY;
			extended_attr->preallocation_policy = DEFAULT_CHANNEL_PREALLOCATION_POLICY;
			break;
		}
		break;
	default:
		return nullptr;
	}

	if (snprintf(chan->name, sizeof(chan->name), "%s", channel_name) < 0) {
		PERROR("snprintf default channel name");
		return nullptr;
	}

	return chan;
}

/* channel_ust_create() removed: logic moved to ust::domain_orchestrator::create_channel(). */
