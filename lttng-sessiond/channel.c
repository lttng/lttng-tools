/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; only version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#include <string.h>
#include <unistd.h>

#include <lttng/lttng.h>
#include <lttng-sessiond-comm.h>
#include <lttngerr.h>

#include "channel.h"
#include "hashtable.h"
#include "kernel-ctl.h"
#include "ust-ctl.h"
#include "utils.h"

/*
 * Return allocated channel attributes.
 */
struct lttng_channel *channel_new_default_attr(int dom)
{
	struct lttng_channel *chan;

	chan = zmalloc(sizeof(struct lttng_channel));
	if (chan == NULL) {
		perror("zmalloc channel init");
		goto error_alloc;
	}

	if (snprintf(chan->name, sizeof(chan->name), "%s",
				DEFAULT_CHANNEL_NAME) < 0) {
		perror("snprintf default channel name");
		goto error;
	}

	chan->attr.overwrite = DEFAULT_CHANNEL_OVERWRITE;
	chan->attr.switch_timer_interval = DEFAULT_CHANNEL_SWITCH_TIMER;
	chan->attr.read_timer_interval = DEFAULT_CHANNEL_READ_TIMER;

	switch (dom) {
	case LTTNG_DOMAIN_KERNEL:
		chan->attr.subbuf_size = DEFAULT_KERNEL_CHANNEL_SUBBUF_SIZE;
		chan->attr.num_subbuf = DEFAULT_KERNEL_CHANNEL_SUBBUF_NUM;
		chan->attr.output = DEFAULT_KERNEL_CHANNEL_OUTPUT;
		break;
	case LTTNG_DOMAIN_UST:
	case LTTNG_DOMAIN_UST_PID:
		chan->attr.subbuf_size = DEFAULT_UST_CHANNEL_SUBBUF_SIZE;
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
 * Copy two ltt ust channel. Dst and src must be already allocated.
 */
int channel_ust_copy(struct ltt_ust_channel *dst,
		struct ltt_ust_channel *src)
{
	//struct ltt_ust_event *uevent, *new_uevent;

	memcpy(dst, src, sizeof(struct ltt_ust_channel));
	dst->events = hashtable_new_str(0);

	/*
	cds_list_for_each_entry(uevent, &src->events.head, list) {
		new_uevent = zmalloc(sizeof(struct ltt_ust_event));
		if (new_uevent == NULL) {
			perror("zmalloc ltt_ust_event");
			goto error;
		}

		memcpy(new_uevent, uevent, sizeof(struct ltt_ust_event));
		cds_list_add(&new_uevent->list, &dst->events.head);
		dst->events.count++;
	}
	*/

	return 0;

//error:
//	return -1;
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
		if (ret < 0) {
			if (ret != EEXIST) {
				ret = LTTCOMM_KERN_CHAN_DISABLE_FAIL;
			}
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
 * Create UST channel and enable it on the tracer.
 */
int channel_ust_create(struct ltt_ust_session *usess,
		struct lttng_channel *attr)
{
	int ret;
	struct ltt_ust_channel *uchan;
	//struct lttng_ust_channel_attr uattr;
	//struct object_data *obj;

	uchan = trace_ust_find_channel_by_name(usess->domain_global.channels,
			attr->name);
	if (uchan == NULL) {
		uchan = trace_ust_create_channel(attr, usess->pathname);
		if (uchan == NULL) {
			ret = LTTCOMM_UST_CHAN_FAIL;
			goto error;
		}
		rcu_read_lock();
		hashtable_add_unique(usess->domain_global.channels, &uchan->node);
		rcu_read_unlock();
	} else {
		ret = LTTCOMM_UST_CHAN_EXIST;
		goto error;
	}

	/* TODO: NOTIFY ust application to update */
	/*
	ret = ustctl_create_channel(sock, usession->handle, &uattr, &obj);
	if (ret < 0) {
		ret = LTTCOMM_UST_CHAN_FAIL;
		goto error;
	}
	*/

	/*
	uchan->attr.overwrite = uattr.overwrite;
	uchan->attr.subbuf_size = uattr.subbuf_size;
	uchan->attr.num_subbuf = uattr.num_subbuf;
	uchan->attr.switch_timer_interval = uattr.switch_timer_interval;
	uchan->attr.read_timer_interval = uattr.read_timer_interval;
	uchan->attr.output = uattr.output;
	uchan->handle = obj->handle;
	uchan->attr.shm_fd = obj->shm_fd;
	uchan->attr.wait_fd = obj->wait_fd;
	uchan->attr.memory_map_size = obj->memory_map_size;
	uchan->obj = obj;
	*/

	/* Add channel to session */
	//rcu_read_lock();
	//cds_list_add(&uchan->list, &usession->channels.head);
	//usession->channels.count++;
	//rcu_read_unlock();

	//DBG2("Channel %s UST create successfully for sock:%d", uchan->name, sock);

	ret = LTTCOMM_OK;

error:
	return ret;
}

/*
 * Enable UST channel on the tracer.
 */
int channel_ust_enable(struct ltt_ust_session *usession,
		struct ltt_ust_channel *uchan, int sock)
{
	int ret = LTTCOMM_OK;
#ifdef DISABLE
	struct object_data obj;

	obj.shm_fd = uchan->attr.shm_fd;
	obj.wait_fd = uchan->attr.wait_fd;
	obj.memory_map_size = uchan->attr.memory_map_size;
	ret = ustctl_enable(sock, &obj);
	if (ret < 0) {
		ret = LTTCOMM_UST_CHAN_FAIL;
		goto end;
	}
	ret = LTTCOMM_OK;
end:
#endif
	return ret;
}

/*
 * Disable UST channel on the tracer.
 */
int channel_ust_disable(struct ltt_ust_session *usession,
		struct ltt_ust_channel *uchan, int sock)
{
	int ret = LTTCOMM_OK;
#ifdef DISABLE
	struct object_data obj;

	obj.shm_fd = uchan->attr.shm_fd;
	obj.wait_fd = uchan->attr.wait_fd;
	obj.memory_map_size = uchan->attr.memory_map_size;
	ret = ustctl_disable(sock, &obj);
	if (ret < 0) {
		ret = LTTCOMM_UST_CHAN_FAIL;
		goto end;
	}
	ret = LTTCOMM_OK;
end:
#endif
	return ret;
}
