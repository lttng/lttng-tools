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

static int channel_validate(struct lttng_channel *attr)
{
	/*
	 * The ringbuffer (both in user space and kernel) behaves badly
	 * in overwrite mode and with less than 2 subbuffers so block it
	 * right away and send back an invalid attribute error.
	 */
	if (attr->attr.overwrite && attr->attr.num_subbuf < 2) {
		return -1;
	}
	return 0;
}

/*
 * Create UST channel for session and domain.
 */
enum lttng_error_code channel_ust_create(struct ltt_ust_session *usess,
					 struct lttng_channel *attr,
					 enum lttng_buffer_type type)
{
	enum lttng_error_code ret_code = LTTNG_OK;
	struct ltt_ust_channel *uchan = nullptr;
	lttng::ctl::lttng_channel_uptr defattr;
	enum lttng_domain_type domain = LTTNG_DOMAIN_UST;
	bool chan_published = false;
	const lttng::urcu::read_lock_guard read_lock;

	LTTNG_ASSERT(usess);

	/* Creating channel attributes if needed */
	if (attr == nullptr) {
		defattr = channel_new_default_attr(LTTNG_DOMAIN_UST, type);
		attr = defattr.get();
	} else {
		/*
		 * HACK: Set the channel's subdomain (JUL, Log4j, Python, etc.)
		 * based on the default name.
		 */
		if (!strcmp(attr->name, DEFAULT_JUL_CHANNEL_NAME)) {
			domain = LTTNG_DOMAIN_JUL;
		} else if (!strcmp(attr->name, DEFAULT_LOG4J_CHANNEL_NAME)) {
			domain = LTTNG_DOMAIN_LOG4J;
		} else if (!strcmp(attr->name, DEFAULT_LOG4J2_CHANNEL_NAME)) {
			domain = LTTNG_DOMAIN_LOG4J2;
		} else if (!strcmp(attr->name, DEFAULT_PYTHON_CHANNEL_NAME)) {
			domain = LTTNG_DOMAIN_PYTHON;
		}
	}

	/*
	 * Set the overwrite mode for this channel based on the session
	 * type unless the client explicitly overrides the channel mode.
	 */
	if (attr->attr.overwrite == DEFAULT_CHANNEL_OVERWRITE) {
		attr->attr.overwrite = !!usess->snapshot_mode;
	}

	/* Enforce mmap output for snapshot sessions. */
	if (usess->snapshot_mode) {
		attr->attr.output = LTTNG_EVENT_MMAP;
	}

	/* Validate common channel properties. */
	if (channel_validate(attr) < 0) {
		ret_code = LTTNG_ERR_INVALID;
		goto error;
	}

	/*
	 * Validate UST buffer size and number of buffers: must both be power of 2
	 * and nonzero. We validate right here for UST, because applications will
	 * not report the error to the user (unlike kernel tracing).
	 */
	if (!attr->attr.subbuf_size || (attr->attr.subbuf_size & (attr->attr.subbuf_size - 1))) {
		ret_code = LTTNG_ERR_INVALID;
		goto error;
	}

	/*
	 * Invalid subbuffer size if it's lower then the page size.
	 */
	if (attr->attr.subbuf_size < the_page_size) {
		ret_code = LTTNG_ERR_INVALID;
		goto error;
	}

	if (!attr->attr.num_subbuf || (attr->attr.num_subbuf & (attr->attr.num_subbuf - 1))) {
		ret_code = LTTNG_ERR_INVALID;
		goto error;
	}

	if (attr->attr.output != LTTNG_EVENT_MMAP) {
		ret_code = LTTNG_ERR_NOT_SUPPORTED;
		goto error;
	}

	/*
	 * The tracefile_size should not be < to the subbuf_size, otherwise
	 * we won't be able to write the packets on disk
	 */
	if ((attr->attr.tracefile_size > 0) &&
	    (attr->attr.tracefile_size < attr->attr.subbuf_size)) {
		ret_code = LTTNG_ERR_INVALID;
		goto error;
	}

	/* Validate buffer type. */
	switch (type) {
	case LTTNG_BUFFER_PER_PID:
		break;
	case LTTNG_BUFFER_PER_UID:
		break;
	default:
		ret_code = LTTNG_ERR_BUFFER_NOT_SUPPORTED;
		goto error;
	}

	/* Create UST channel */
	uchan = trace_ust_create_channel(attr, domain);
	if (uchan == nullptr) {
		ret_code = LTTNG_ERR_FATAL;
		goto error;
	}

	uchan->enabled = true;
	if (trace_ust_is_max_id(usess->used_event_container_id)) {
		ret_code = LTTNG_ERR_UST_CHAN_FAIL;
		goto error;
	}

	uchan->trace_class_stream_class_handle = trace_ust_get_next_event_container_id(usess);

	DBG2("Channel %s is being created for UST with buffer %d and id %" PRIu64,
	     uchan->name,
	     type,
	     uchan->trace_class_stream_class_handle);

	/* Flag session buffer type. */
	if (!usess->buffer_type_changed) {
		usess->buffer_type = type;
		usess->buffer_type_changed = 1;
	} else if (usess->buffer_type != type) {
		/* Buffer type was already set. Refuse to create channel. */
		ret_code = LTTNG_ERR_BUFFER_TYPE_MISMATCH;
		goto error_free_chan;
	}

	/* Adding the channel to the channel hash table. */
	if (strncmp(uchan->name, DEFAULT_METADATA_NAME, sizeof(uchan->name)) != 0) {
		lttng_ht_add_unique_str(usess->domain_global.channels, &uchan->node);
		chan_published = true;
	} else {
		/*
		 * Copy channel attribute to session if this is metadata so if NO
		 * application exists we can access that data in the shadow copy during
		 * the global update of newly registered application.
		 */
		memcpy(&usess->metadata_attr, &uchan->attr, sizeof(usess->metadata_attr));
	}

	DBG2("Channel %s created successfully", uchan->name);
	if (domain != LTTNG_DOMAIN_UST) {
		struct agent *agt = trace_ust_find_agent(usess, domain);

		if (!agt) {
			agt = agent_create(domain);
			if (!agt) {
				ret_code = LTTNG_ERR_NOMEM;
				goto error_remove_chan;
			}

			/* Ownership of agt is transferred. */
			agent_add(agt, usess->agents);
		}
	}

	return LTTNG_OK;

error_remove_chan:
	if (chan_published) {
		trace_ust_delete_channel(usess->domain_global.channels, uchan);
	}
error_free_chan:
	trace_ust_destroy_channel(uchan);
error:
	return ret_code;
}
