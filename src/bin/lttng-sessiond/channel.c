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
#include <string.h>
#include <unistd.h>

#include <common/common.h>
#include <common/defaults.h>
#include <common/sessiond-comm/sessiond-comm.h>

#include "channel.h"
#include "kernel.h"
#include "ust-ctl.h"
#include "utils.h"
#include "ust-app.h"

/*
 * Return allocated channel attributes.
 */
struct lttng_channel *channel_new_default_attr(int dom)
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

	chan->attr.overwrite = DEFAULT_CHANNEL_OVERWRITE;
	chan->attr.switch_timer_interval = DEFAULT_CHANNEL_SWITCH_TIMER;
	chan->attr.read_timer_interval = DEFAULT_CHANNEL_READ_TIMER;

	switch (dom) {
	case LTTNG_DOMAIN_KERNEL:
		chan->attr.subbuf_size =
			default_get_kernel_channel_subbuf_size();
		chan->attr.num_subbuf = DEFAULT_KERNEL_CHANNEL_SUBBUF_NUM;
		chan->attr.output = DEFAULT_KERNEL_CHANNEL_OUTPUT;
		break;
	case LTTNG_DOMAIN_UST:
#if 0
	case LTTNG_DOMAIN_UST_PID:
	case LTTNG_DOMAIN_UST_PID_FOLLOW_CHILDREN:
	case LTTNG_DOMAIN_UST_EXEC_NAME:
#endif
		chan->attr.subbuf_size = default_get_ust_channel_subbuf_size();
		chan->attr.num_subbuf = DEFAULT_UST_CHANNEL_SUBBUF_NUM;
		chan->attr.output = DEFAULT_UST_CHANNEL_OUTPUT;
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

	kchan = trace_kernel_get_channel_by_name(channel_name, ksession);
	if (kchan == NULL) {
		ret = LTTCOMM_KERN_CHAN_NOT_FOUND;
		goto error;
	} else if (kchan->enabled == 1) {
		ret = kernel_disable_channel(kchan);
		if (ret < 0 && ret != -EEXIST) {
			ret = LTTCOMM_KERN_CHAN_DISABLE_FAIL;
			goto error;
		}
	}

	ret = LTTCOMM_OK;

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

	if (kchan->enabled == 0) {
		ret = kernel_enable_channel(kchan);
		if (ret < 0) {
			ret = LTTCOMM_KERN_CHAN_ENABLE_FAIL;
			goto error;
		}
	} else {
		ret = LTTCOMM_KERN_CHAN_EXIST;
		goto error;
	}

	ret = LTTCOMM_OK;

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

	/* Creating channel attributes if needed */
	if (attr == NULL) {
		defattr = channel_new_default_attr(LTTNG_DOMAIN_KERNEL);
		if (defattr == NULL) {
			ret = LTTCOMM_FATAL;
			goto error;
		}
		attr = defattr;
	}

	/* Channel not found, creating it */
	ret = kernel_create_channel(ksession, attr, ksession->trace_path);
	if (ret < 0) {
		ret = LTTCOMM_KERN_CHAN_FAIL;
		goto error;
	}

	/* Notify kernel thread that there is a new channel */
	ret = notify_thread_pipe(kernel_pipe);
	if (ret < 0) {
		ret = LTTCOMM_FATAL;
		goto error;
	}

	ret = LTTCOMM_OK;
error:
	free(defattr);
	return ret;
}

/*
 * Enable UST channel for session and domain.
 */
int channel_ust_enable(struct ltt_ust_session *usess, int domain,
		struct ltt_ust_channel *uchan)
{
	int ret = LTTCOMM_OK;

	/* If already enabled, everything is OK */
	if (uchan->enabled) {
		DBG3("Channel %s already enabled. Skipping", uchan->name);
		ret = LTTCOMM_UST_CHAN_EXIST;
		goto end;
	}

	switch (domain) {
	case LTTNG_DOMAIN_UST:
		DBG2("Channel %s being enabled in UST global domain", uchan->name);
		/* Enable channel for global domain */
		ret = ust_app_enable_channel_glb(usess, uchan);
		break;
#if 0
	case LTTNG_DOMAIN_UST_PID:
	case LTTNG_DOMAIN_UST_PID_FOLLOW_CHILDREN:
	case LTTNG_DOMAIN_UST_EXEC_NAME:
#endif
	default:
		ret = LTTCOMM_UND;
		goto error;
	}

	if (ret < 0) {
		if (ret != -EEXIST) {
			ret = LTTCOMM_UST_CHAN_ENABLE_FAIL;
			goto error;
		} else {
			ret = LTTCOMM_OK;
		}
	}

	uchan->enabled = 1;
	DBG2("Channel %s enabled successfully", uchan->name);

end:
error:
	return ret;
}

/*
 * Create UST channel for session and domain.
 */
int channel_ust_create(struct ltt_ust_session *usess, int domain,
		struct lttng_channel *attr)
{
	int ret = LTTCOMM_OK;
	struct ltt_ust_channel *uchan = NULL;
	struct lttng_channel *defattr = NULL;

	/* Creating channel attributes if needed */
	if (attr == NULL) {
		defattr = channel_new_default_attr(domain);
		if (defattr == NULL) {
			ret = LTTCOMM_FATAL;
			goto error;
		}
		attr = defattr;
	}

	/*
	 * Validate UST buffer size and number of buffers: must both be
	 * power of 2 and nonzero. We validate right here for UST,
	 * because applications will not report the error to the user
	 * (unlike kernel tracing).
	 */
	if (!attr->attr.subbuf_size || (attr->attr.subbuf_size & (attr->attr.subbuf_size - 1))) {
		ret = LTTCOMM_INVALID;
		goto error;
	}
	if (!attr->attr.num_subbuf || (attr->attr.num_subbuf & (attr->attr.num_subbuf - 1))) {
		ret = LTTCOMM_INVALID;
		goto error;
	}

	/* Create UST channel */
	uchan = trace_ust_create_channel(attr, usess->pathname);
	if (uchan == NULL) {
		ret = LTTCOMM_FATAL;
		goto error;
	}
	uchan->enabled = 1;

	switch (domain) {
	case LTTNG_DOMAIN_UST:
		DBG2("Channel %s being created in UST global domain", uchan->name);

		/* Enable channel for global domain */
		ret = ust_app_create_channel_glb(usess, uchan);
		break;
#if 0
	case LTTNG_DOMAIN_UST_PID:
	case LTTNG_DOMAIN_UST_PID_FOLLOW_CHILDREN:
	case LTTNG_DOMAIN_UST_EXEC_NAME:
#endif
	default:
		ret = LTTCOMM_UND;
		goto error_free_chan;
	}

	if (ret < 0 && ret != -EEXIST) {
		ret = LTTCOMM_UST_CHAN_ENABLE_FAIL;
		goto error_free_chan;
	}

	/* Adding the channel to the channel hash table. */
	rcu_read_lock();
	lttng_ht_add_unique_str(usess->domain_global.channels, &uchan->node);
	rcu_read_unlock();

	DBG2("Channel %s created successfully", uchan->name);

	free(defattr);
	return LTTCOMM_OK;

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
int channel_ust_disable(struct ltt_ust_session *usess, int domain,
		struct ltt_ust_channel *uchan)
{
	int ret = LTTCOMM_OK;

	/* Already disabled */
	if (uchan->enabled == 0) {
		DBG2("Channel UST %s already disabled", uchan->name);
		goto end;
	}

	/* Get the right channel's hashtable */
	switch (domain) {
	case LTTNG_DOMAIN_UST:
		DBG2("Channel %s being disabled in UST global domain", uchan->name);
		/* Disable channel for global domain */
		ret = ust_app_disable_channel_glb(usess, uchan);
		break;
#if 0
	case LTTNG_DOMAIN_UST_PID_FOLLOW_CHILDREN:
	case LTTNG_DOMAIN_UST_EXEC_NAME:
	case LTTNG_DOMAIN_UST_PID:
#endif
	default:
		ret = LTTCOMM_UND;
		goto error;
	}

	if (ret < 0 && ret != -EEXIST) {
		ret = LTTCOMM_UST_DISABLE_FAIL;
		goto error;
	}

	uchan->enabled = 0;

	DBG2("Channel %s disabled successfully", uchan->name);

	return LTTCOMM_OK;

end:
error:
	return ret;
}
