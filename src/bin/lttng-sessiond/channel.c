/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define _GNU_SOURCE
#include <inttypes.h>
#include <string.h>
#include <unistd.h>

#include <common/common.h>
#include <common/defaults.h>
#include <common/sessiond-comm/sessiond-comm.h>

#include "channel.h"
#include "lttng-sessiond.h"
#include "kernel.h"
#include "ust-ctl.h"
#include "utils.h"
#include "ust-app.h"

/*
 * Return allocated channel attributes.
 */
struct lttng_channel *channel_new_default_attr(int dom,
		enum lttng_buffer_type type)
{
	struct lttng_channel *chan;

	chan = zmalloc(sizeof(struct lttng_channel));
	if (chan == NULL) {
		PERROR("zmalloc channel init");
		goto error_alloc;
	}

	if (snprintf(chan->name, sizeof(chan->name), "%s",
				DEFAULT_CHANNEL_NAME) < 0) {
		PERROR("snprintf default channel name");
		goto error;
	}

	/* Same for all domains. */
	chan->attr.overwrite = DEFAULT_CHANNEL_OVERWRITE;
	chan->attr.tracefile_size = DEFAULT_CHANNEL_TRACEFILE_SIZE;
	chan->attr.tracefile_count = DEFAULT_CHANNEL_TRACEFILE_COUNT;

	switch (dom) {
	case LTTNG_DOMAIN_KERNEL:
		assert(type == LTTNG_BUFFER_GLOBAL);
		chan->attr.subbuf_size =
			default_get_kernel_channel_subbuf_size();
		chan->attr.num_subbuf = DEFAULT_KERNEL_CHANNEL_SUBBUF_NUM;
		chan->attr.output = DEFAULT_KERNEL_CHANNEL_OUTPUT;
		chan->attr.switch_timer_interval = DEFAULT_KERNEL_CHANNEL_SWITCH_TIMER;
		chan->attr.read_timer_interval = DEFAULT_KERNEL_CHANNEL_READ_TIMER;
		chan->attr.live_timer_interval = DEFAULT_KERNEL_CHANNEL_LIVE_TIMER;
		break;
	case LTTNG_DOMAIN_UST:
		switch (type) {
		case LTTNG_BUFFER_PER_UID:
			chan->attr.subbuf_size = default_get_ust_uid_channel_subbuf_size();
			chan->attr.num_subbuf = DEFAULT_UST_UID_CHANNEL_SUBBUF_NUM;
			chan->attr.output = DEFAULT_UST_UID_CHANNEL_OUTPUT;
			chan->attr.switch_timer_interval =
				DEFAULT_UST_UID_CHANNEL_SWITCH_TIMER;
			chan->attr.read_timer_interval =
				DEFAULT_UST_UID_CHANNEL_READ_TIMER;
			chan->attr.live_timer_interval =
				DEFAULT_UST_UID_CHANNEL_LIVE_TIMER;
			break;
		case LTTNG_BUFFER_PER_PID:
		default:
			chan->attr.subbuf_size = default_get_ust_pid_channel_subbuf_size();
			chan->attr.num_subbuf = DEFAULT_UST_PID_CHANNEL_SUBBUF_NUM;
			chan->attr.output = DEFAULT_UST_PID_CHANNEL_OUTPUT;
			chan->attr.switch_timer_interval =
				DEFAULT_UST_PID_CHANNEL_SWITCH_TIMER;
			chan->attr.read_timer_interval =
				DEFAULT_UST_PID_CHANNEL_READ_TIMER;
			chan->attr.live_timer_interval =
				DEFAULT_UST_UID_CHANNEL_LIVE_TIMER;
			break;
		}
		break;
	default:
		goto error;	/* Not implemented */
	}

	return chan;

error:
	free(chan);
error_alloc:
	return NULL;
}

/*
 * Disable kernel channel of the kernel session.
 */
int channel_kernel_disable(struct ltt_kernel_session *ksession,
		char *channel_name)
{
	int ret;
	struct ltt_kernel_channel *kchan;

	assert(ksession);
	assert(channel_name);

	kchan = trace_kernel_get_channel_by_name(channel_name, ksession);
	if (kchan == NULL) {
		ret = LTTNG_ERR_KERN_CHAN_NOT_FOUND;
		goto error;
	}

	/* Only if channel is enabled disable it. */
	if (kchan->enabled == 1) {
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
int channel_kernel_enable(struct ltt_kernel_session *ksession,
		struct ltt_kernel_channel *kchan)
{
	int ret;

	assert(ksession);
	assert(kchan);

	if (kchan->enabled == 0) {
		ret = kernel_enable_channel(kchan);
		if (ret < 0) {
			ret = LTTNG_ERR_KERN_CHAN_ENABLE_FAIL;
			goto error;
		}
	} else {
		ret = LTTNG_ERR_KERN_CHAN_EXIST;
		goto error;
	}

	ret = LTTNG_OK;

error:
	return ret;
}

/*
 * Create kernel channel of the kernel session and notify kernel thread.
 */
int channel_kernel_create(struct ltt_kernel_session *ksession,
		struct lttng_channel *attr, int kernel_pipe)
{
	int ret;
	struct lttng_channel *defattr = NULL;

	assert(ksession);

	/* Creating channel attributes if needed */
	if (attr == NULL) {
		defattr = channel_new_default_attr(LTTNG_DOMAIN_KERNEL,
				LTTNG_BUFFER_GLOBAL);
		if (defattr == NULL) {
			ret = LTTNG_ERR_FATAL;
			goto error;
		}
		attr = defattr;
	}

	if (ksession->snapshot_mode) {
		/* Force channel attribute for snapshot mode. */
		attr->attr.overwrite = 1;
		attr->attr.output = LTTNG_EVENT_MMAP;
	}

	/* Channel not found, creating it */
	ret = kernel_create_channel(ksession, attr);
	if (ret < 0) {
		ret = LTTNG_ERR_KERN_CHAN_FAIL;
		goto error;
	}

	/* Notify kernel thread that there is a new channel */
	ret = notify_thread_pipe(kernel_pipe);
	if (ret < 0) {
		ret = LTTNG_ERR_FATAL;
		goto error;
	}

	ret = LTTNG_OK;
error:
	free(defattr);
	return ret;
}

/*
 * Enable UST channel for session and domain.
 */
int channel_ust_enable(struct ltt_ust_session *usess,
		struct ltt_ust_channel *uchan)
{
	int ret = LTTNG_OK;

	assert(usess);
	assert(uchan);

	/* If already enabled, everything is OK */
	if (uchan->enabled) {
		DBG3("Channel %s already enabled. Skipping", uchan->name);
		ret = LTTNG_ERR_UST_CHAN_EXIST;
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

	uchan->enabled = 1;
	DBG2("Channel %s enabled successfully", uchan->name);

end:
	return ret;
}

/*
 * Create UST channel for session and domain.
 */
int channel_ust_create(struct ltt_ust_session *usess,
		struct lttng_channel *attr, enum lttng_buffer_type type)
{
	int ret = LTTNG_OK;
	struct ltt_ust_channel *uchan = NULL;
	struct lttng_channel *defattr = NULL;

	assert(usess);

	/* Creating channel attributes if needed */
	if (attr == NULL) {
		defattr = channel_new_default_attr(LTTNG_DOMAIN_UST, type);
		if (defattr == NULL) {
			ret = LTTNG_ERR_FATAL;
			goto error;
		}
		attr = defattr;
	}

	if (usess->snapshot_mode) {
		/* Force channel attribute for snapshot mode. */
		attr->attr.overwrite = 1;
		attr->attr.output = LTTNG_EVENT_MMAP;
	}

	/*
	 * Validate UST buffer size and number of buffers: must both be power of 2
	 * and nonzero. We validate right here for UST, because applications will
	 * not report the error to the user (unlike kernel tracing).
	 */
	if (!attr->attr.subbuf_size ||
			(attr->attr.subbuf_size & (attr->attr.subbuf_size - 1))) {
		ret = LTTNG_ERR_INVALID;
		goto error;
	}

	/*
	 * Invalid subbuffer size if it's lower then the page size.
	 */
	if (attr->attr.subbuf_size < page_size) {
		ret = LTTNG_ERR_INVALID;
		goto error;
	}

	if (!attr->attr.num_subbuf ||
			(attr->attr.num_subbuf & (attr->attr.num_subbuf - 1))) {
		ret = LTTNG_ERR_INVALID;
		goto error;
	}

	if (attr->attr.output != LTTNG_EVENT_MMAP) {
		ret = LTTNG_ERR_NOT_SUPPORTED;
		goto error;
	}

	/*
	 * The tracefile_size should not be < to the subbuf_size, otherwise
	 * we won't be able to write the packets on disk
	 */
	if ((attr->attr.tracefile_size > 0) &&
			(attr->attr.tracefile_size < attr->attr.subbuf_size)) {
		ret = LTTNG_ERR_INVALID;
		goto error;
	}

	/* Validate buffer type. */
	switch (type) {
	case LTTNG_BUFFER_PER_PID:
		break;
	case LTTNG_BUFFER_PER_UID:
		break;
	default:
		ret = LTTNG_ERR_BUFFER_NOT_SUPPORTED;
		goto error;
	}

	/* Create UST channel */
	uchan = trace_ust_create_channel(attr);
	if (uchan == NULL) {
		ret = LTTNG_ERR_FATAL;
		goto error;
	}
	uchan->enabled = 1;
	if (trace_ust_is_max_id(usess->used_channel_id)) {
		ret = LTTNG_ERR_UST_CHAN_FAIL;
		goto error;
	}
	uchan->id = trace_ust_get_next_chan_id(usess);

	DBG2("Channel %s is being created for UST with buffer %d and id %" PRIu64,
			uchan->name, type, uchan->id);

	/* Flag session buffer type. */
	if (!usess->buffer_type_changed) {
		usess->buffer_type = type;
		usess->buffer_type_changed = 1;
	} else if (usess->buffer_type != type) {
		/* Buffer type was already set. Refuse to create channel. */
		ret = LTTNG_ERR_BUFFER_TYPE_MISMATCH;
		goto error_free_chan;
	}

	/* Enable channel for global domain */
	ret = ust_app_create_channel_glb(usess, uchan);
	if (ret < 0 && ret != -LTTNG_UST_ERR_EXIST) {
		ret = LTTNG_ERR_UST_CHAN_FAIL;
		goto error_free_chan;
	}

	/* Adding the channel to the channel hash table. */
	rcu_read_lock();
	lttng_ht_add_unique_str(usess->domain_global.channels, &uchan->node);
	rcu_read_unlock();

	DBG2("Channel %s created successfully", uchan->name);

	free(defattr);
	return LTTNG_OK;

error_free_chan:
	/*
	 * No need to remove the channel from the hash table because at this point
	 * it was not added hence the direct call and no call_rcu().
	 */
	trace_ust_destroy_channel(uchan);
error:
	free(defattr);
	return ret;
}

/*
 * Disable UST channel for session and domain.
 */
int channel_ust_disable(struct ltt_ust_session *usess,
		struct ltt_ust_channel *uchan)
{
	int ret = LTTNG_OK;

	assert(usess);
	assert(uchan);

	/* Already disabled */
	if (uchan->enabled == 0) {
		DBG2("Channel UST %s already disabled", uchan->name);
		goto end;
	}

	DBG2("Channel %s being disabled in UST global domain", uchan->name);
	/* Disable channel for global domain */
	ret = ust_app_disable_channel_glb(usess, uchan);
	if (ret < 0 && ret != -LTTNG_UST_ERR_EXIST) {
		ret = LTTNG_ERR_UST_CHAN_DISABLE_FAIL;
		goto error;
	}

	uchan->enabled = 0;

	DBG2("Channel %s disabled successfully", uchan->name);

	return LTTNG_OK;

end:
error:
	return ret;
}
