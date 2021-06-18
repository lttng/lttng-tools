/*
 * Copyright (C) 2011 EfficiOS Inc.
 * Copyright (C) 2016 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include "agent.hpp"
#include "channel.hpp"
#include "kernel.hpp"
#include "lttng-sessiond.hpp"
#include "lttng-ust-ctl.hpp"
#include "lttng-ust-error.hpp"
#include "ust-app.hpp"
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
struct lttng_channel *channel_new_default_attr(int dom, enum lttng_buffer_type type)
{
	struct lttng_channel *chan;
	const char *channel_name = DEFAULT_CHANNEL_NAME;
	struct lttng_channel_extended *extended_attr = nullptr;

	chan = zmalloc<lttng_channel>();
	if (chan == nullptr) {
		PERROR("zmalloc channel init");
		goto error_alloc;
	}

	extended_attr = zmalloc<lttng_channel_extended>();
	if (!extended_attr) {
		PERROR("zmalloc channel extended init");
		goto error;
	}

	chan->attr.extended.ptr = extended_attr;

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
		break;
	case LTTNG_DOMAIN_JUL:
		channel_name = DEFAULT_JUL_CHANNEL_NAME;
		goto common_ust;
	case LTTNG_DOMAIN_LOG4J:
		channel_name = DEFAULT_LOG4J_CHANNEL_NAME;
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
			break;
		}
		break;
	default:
		goto error; /* Not implemented */
	}

	if (snprintf(chan->name, sizeof(chan->name), "%s", channel_name) < 0) {
		PERROR("snprintf default channel name");
		goto error;
	}
	return chan;

error:
	free(extended_attr);
	free(chan);
error_alloc:
	return nullptr;
}

void channel_attr_destroy(struct lttng_channel *channel)
{
	if (!channel) {
		return;
	}
	free(channel->attr.extended.ptr);
	free(channel);
}

/*
 * Disable kernel channel of the kernel session.
 */
int channel_kernel_disable(struct ltt_kernel_session *ksession, char *channel_name)
{
	int ret;
	struct ltt_kernel_channel *kchan;

	LTTNG_ASSERT(ksession);
	LTTNG_ASSERT(channel_name);

	kchan = trace_kernel_get_channel_by_name(channel_name, ksession);
	if (kchan == nullptr) {
		ret = LTTNG_ERR_KERN_CHAN_NOT_FOUND;
		goto error;
	}

	/* Only if channel is enabled disable it. */
	if (kchan->enabled) {
		ret = kernel_disable_channel(kchan);
		if (ret < 0 && ret != -EEXIST) {
			ret = LTTNG_ERR_KERN_CHAN_DISABLE_FAIL;
			goto error;
		}
	}

	ret = LTTNG_OK;

error:
	return ret;
}

/*
 * Enable kernel channel of the kernel session.
 */
enum lttng_error_code channel_kernel_enable(struct ltt_kernel_session *ksession,
					    struct ltt_kernel_channel *kchan)
{
	enum lttng_error_code ret_code;

	LTTNG_ASSERT(ksession);
	LTTNG_ASSERT(kchan);

	if (!kchan->enabled) {
		if (kernel_enable_channel(kchan) < 0) {
			ret_code = LTTNG_ERR_KERN_CHAN_ENABLE_FAIL;
			goto error;
		}
	} else {
		ret_code = LTTNG_ERR_KERN_CHAN_EXIST;
		goto error;
	}

	ret_code = LTTNG_OK;

error:
	return ret_code;
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

static int channel_validate_kernel(struct lttng_channel *attr)
{
	/* Kernel channels do not support blocking timeout. */
	if (((struct lttng_channel_extended *) attr->attr.extended.ptr)->blocking_timeout) {
		return -1;
	}
	return 0;
}

/*
 * Create kernel channel of the kernel session and notify kernel thread.
 */
enum lttng_error_code channel_kernel_create(struct ltt_kernel_session *ksession,
					    struct lttng_channel *attr,
					    int kernel_pipe)
{
	enum lttng_error_code ret_code;
	struct lttng_channel *defattr = nullptr;

	LTTNG_ASSERT(ksession);

	/* Creating channel attributes if needed */
	if (attr == nullptr) {
		defattr = channel_new_default_attr(LTTNG_DOMAIN_KERNEL, LTTNG_BUFFER_GLOBAL);
		if (defattr == nullptr) {
			ret_code = LTTNG_ERR_FATAL;
			goto error;
		}
		attr = defattr;
	}

	/*
	 * Set the overwrite mode for this channel based on the session
	 * type unless the client explicitly overrides the channel mode.
	 */
	if (attr->attr.overwrite == DEFAULT_CHANNEL_OVERWRITE) {
		attr->attr.overwrite = !!ksession->snapshot_mode;
	}

	/* Validate common channel properties. */
	if (channel_validate(attr) < 0) {
		ret_code = LTTNG_ERR_INVALID;
		goto error;
	}

	if (channel_validate_kernel(attr) < 0) {
		ret_code = LTTNG_ERR_INVALID;
		goto error;
	}

	/* Channel not found, creating it. */
	if (kernel_create_channel(ksession, attr) < 0) {
		ret_code = LTTNG_ERR_KERN_CHAN_FAIL;
		goto error;
	}

	/* Notify kernel thread that there is a new channel */
	if (notify_thread_pipe(kernel_pipe) < 0) {
		ret_code = LTTNG_ERR_FATAL;
		goto error;
	}

	ret_code = LTTNG_OK;
error:
	channel_attr_destroy(defattr);
	return ret_code;
}

/*
 * Enable UST channel for session and domain.
 */
enum lttng_error_code channel_ust_enable(struct ltt_ust_session *usess,
					 struct ltt_ust_channel *uchan)
{
	enum lttng_error_code ret_code = LTTNG_OK;

	LTTNG_ASSERT(usess);
	LTTNG_ASSERT(uchan);

	/* If already enabled, everything is OK */
	if (uchan->enabled) {
		DBG3("Channel %s already enabled. Skipping", uchan->name);
		ret_code = LTTNG_ERR_UST_CHAN_EXIST;
		goto end;
	} else {
		uchan->enabled = true;
		DBG2("Channel %s enabled successfully", uchan->name);
	}

	if (!usess->active) {
		/*
		 * The channel will be activated against the apps
		 * when the session is started as part of the
		 * application channel "synchronize" operation.
		 */
		goto end;
	}

	DBG2("Channel %s being enabled in UST domain", uchan->name);

	/*
	 * Enable channel for UST global domain on all applications. Ignore return
	 * value here since whatever error we got, it means that the channel was
	 * not created on one or many registered applications and we can not report
	 * this to the user yet. However, at this stage, the channel was
	 * successfully created on the session daemon side so the enable-channel
	 * command is a success.
	 */
	(void) ust_app_enable_channel_glb(usess, uchan);

end:
	return ret_code;
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
	struct lttng_channel *defattr = nullptr;
	enum lttng_domain_type domain = LTTNG_DOMAIN_UST;
	bool chan_published = false;
	lttng::urcu::read_lock_guard read_lock;

	LTTNG_ASSERT(usess);

	/* Creating channel attributes if needed */
	if (attr == nullptr) {
		defattr = channel_new_default_attr(LTTNG_DOMAIN_UST, type);
		if (defattr == nullptr) {
			ret_code = LTTNG_ERR_FATAL;
			goto error;
		}
		attr = defattr;
	} else {
		/*
		 * HACK: Set the channel's subdomain (JUL, Log4j, Python, etc.)
		 * based on the default name.
		 */
		if (!strcmp(attr->name, DEFAULT_JUL_CHANNEL_NAME)) {
			domain = LTTNG_DOMAIN_JUL;
		} else if (!strcmp(attr->name, DEFAULT_LOG4J_CHANNEL_NAME)) {
			domain = LTTNG_DOMAIN_LOG4J;
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

	uchan->id = trace_ust_get_next_event_container_id(usess);

	DBG2("Channel %s is being created for UST with buffer %d and id %" PRIu64,
	     uchan->name,
	     type,
	     uchan->id);

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
			agent_add(agt, usess->agents);
		}
	}

	channel_attr_destroy(defattr);
	return LTTNG_OK;

error_remove_chan:
	if (chan_published) {
		trace_ust_delete_channel(usess->domain_global.channels, uchan);
	}
error_free_chan:
	trace_ust_destroy_channel(uchan);
error:
	channel_attr_destroy(defattr);
	return ret_code;
}

/*
 * Disable UST channel for session and domain.
 */
int channel_ust_disable(struct ltt_ust_session *usess, struct ltt_ust_channel *uchan)
{
	int ret = LTTNG_OK;

	LTTNG_ASSERT(usess);
	LTTNG_ASSERT(uchan);

	/* Already disabled */
	if (!uchan->enabled) {
		DBG2("Channel UST %s already disabled", uchan->name);
		goto end;
	}

	uchan->enabled = false;

	/*
	 * If session is inactive we don't notify the tracer right away. We
	 * wait for the next synchronization.
	 */
	if (!usess->active) {
		goto end;
	}

	DBG2("Channel %s being disabled in UST global domain", uchan->name);
	/* Disable channel for global domain */
	ret = ust_app_disable_channel_glb(usess, uchan);
	if (ret < 0 && ret != -LTTNG_UST_ERR_EXIST) {
		ret = LTTNG_ERR_UST_CHAN_DISABLE_FAIL;
		goto error;
	}

	DBG2("Channel %s disabled successfully", uchan->name);

	return LTTNG_OK;

end:
error:
	return ret;
}

struct lttng_channel *trace_ust_channel_to_lttng_channel(const struct ltt_ust_channel *uchan)
{
	struct lttng_channel *channel = nullptr, *ret = nullptr;

	channel = lttng_channel_create_internal();
	if (!channel) {
		ERR("Failed to create lttng_channel during conversion from ltt_ust_channel to lttng_channel");
		goto end;
	}

	if (lttng_strncpy(channel->name, uchan->name, LTTNG_SYMBOL_NAME_LEN)) {
		ERR("Failed to set channel name during conversion from ltt_ust_channel to lttng_channel");
		goto end;
	}

	channel->attr.overwrite = uchan->attr.overwrite;
	channel->attr.subbuf_size = uchan->attr.subbuf_size;
	channel->attr.num_subbuf = uchan->attr.num_subbuf;
	channel->attr.switch_timer_interval = uchan->attr.switch_timer_interval;
	channel->attr.read_timer_interval = uchan->attr.read_timer_interval;
	channel->enabled = uchan->enabled;
	channel->attr.tracefile_size = uchan->tracefile_size;
	channel->attr.tracefile_count = uchan->tracefile_count;

	/*
	 * Map enum lttng_ust_output to enum lttng_event_output.
	 */
	switch (uchan->attr.output) {
	case LTTNG_UST_ABI_MMAP:
		channel->attr.output = LTTNG_EVENT_MMAP;
		break;
	default:
		/*
		 * LTTNG_UST_MMAP is the only supported UST
		 * output mode.
		 */
		abort();
		break;
	}

	lttng_channel_set_blocking_timeout(channel, uchan->attr.u.s.blocking_timeout);
	lttng_channel_set_monitor_timer_interval(channel, uchan->monitor_timer_interval);

	ret = channel;
	channel = nullptr;

end:
	lttng_channel_destroy(channel);
	return ret;
}
