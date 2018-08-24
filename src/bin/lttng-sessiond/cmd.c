/*
 * Copyright (C) 2012 - David Goulet <dgoulet@efficios.com>
 * Copyright (C) 2016 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define _LGPL_SOURCE
#include <assert.h>
#include <inttypes.h>
#include <urcu/list.h>
#include <urcu/uatomic.h>
#include <sys/stat.h>

#include <common/defaults.h>
#include <common/common.h>
#include <common/sessiond-comm/sessiond-comm.h>
#include <common/relayd/relayd.h>
#include <common/utils.h>
#include <common/compat/string.h>
#include <common/kernel-ctl/kernel-ctl.h>
#include <common/dynamic-buffer.h>
#include <common/buffer-view.h>
#include <lttng/trigger/trigger-internal.h>
#include <lttng/condition/condition.h>
#include <lttng/action/action.h>
#include <lttng/channel.h>
#include <lttng/channel-internal.h>
#include <lttng/rotate-internal.h>
#include <lttng/location-internal.h>
#include <lttng/userspace-probe-internal.h>
#include <common/string-utils/string-utils.h>

#include "channel.h"
#include "consumer.h"
#include "event.h"
#include "health-sessiond.h"
#include "kernel.h"
#include "kernel-consumer.h"
#include "lttng-sessiond.h"
#include "utils.h"
#include "lttng-syscall.h"
#include "agent.h"
#include "buffer-registry.h"
#include "notification-thread.h"
#include "notification-thread-commands.h"
#include "rotate.h"
#include "rotation-thread.h"
#include "sessiond-timer.h"
#include "agent-thread.h"

#include "cmd.h"

/* Sleep for 100ms between each check for the shm path's deletion. */
#define SESSION_DESTROY_SHM_PATH_CHECK_DELAY_US 100000

static enum lttng_error_code wait_on_path(void *path);

/*
 * Command completion handler that is used by the destroy command
 * when a session that has a non-default shm_path is being destroyed.
 *
 * See comment in cmd_destroy_session() for the rationale.
 */
static struct destroy_completion_handler {
	struct cmd_completion_handler handler;
	char shm_path[member_sizeof(struct ltt_session, shm_path)];
} destroy_completion_handler = {
	.handler = {
		.run = wait_on_path,
		.data = destroy_completion_handler.shm_path
	},
	.shm_path = { 0 },
};

static struct cmd_completion_handler *current_completion_handler;

/*
 * Used to keep a unique index for each relayd socket created where this value
 * is associated with streams on the consumer so it can match the right relayd
 * to send to. It must be accessed with the relayd_net_seq_idx_lock
 * held.
 */
static pthread_mutex_t relayd_net_seq_idx_lock = PTHREAD_MUTEX_INITIALIZER;
static uint64_t relayd_net_seq_idx;

static int validate_ust_event_name(const char *);
static int cmd_enable_event_internal(struct ltt_session *session,
		struct lttng_domain *domain,
		char *channel_name, struct lttng_event *event,
		char *filter_expression,
		struct lttng_filter_bytecode *filter,
		struct lttng_event_exclusion *exclusion,
		int wpipe);

/*
 * Create a session path used by list_lttng_sessions for the case that the
 * session consumer is on the network.
 */
static int build_network_session_path(char *dst, size_t size,
		struct ltt_session *session)
{
	int ret, kdata_port, udata_port;
	struct lttng_uri *kuri = NULL, *uuri = NULL, *uri = NULL;
	char tmp_uurl[PATH_MAX], tmp_urls[PATH_MAX];

	assert(session);
	assert(dst);

	memset(tmp_urls, 0, sizeof(tmp_urls));
	memset(tmp_uurl, 0, sizeof(tmp_uurl));

	kdata_port = udata_port = DEFAULT_NETWORK_DATA_PORT;

	if (session->kernel_session && session->kernel_session->consumer) {
		kuri = &session->kernel_session->consumer->dst.net.control;
		kdata_port = session->kernel_session->consumer->dst.net.data.port;
	}

	if (session->ust_session && session->ust_session->consumer) {
		uuri = &session->ust_session->consumer->dst.net.control;
		udata_port = session->ust_session->consumer->dst.net.data.port;
	}

	if (uuri == NULL && kuri == NULL) {
		uri = &session->consumer->dst.net.control;
		kdata_port = session->consumer->dst.net.data.port;
	} else if (kuri && uuri) {
		ret = uri_compare(kuri, uuri);
		if (ret) {
			/* Not Equal */
			uri = kuri;
			/* Build uuri URL string */
			ret = uri_to_str_url(uuri, tmp_uurl, sizeof(tmp_uurl));
			if (ret < 0) {
				goto error;
			}
		} else {
			uri = kuri;
		}
	} else if (kuri && uuri == NULL) {
		uri = kuri;
	} else if (uuri && kuri == NULL) {
		uri = uuri;
	}

	ret = uri_to_str_url(uri, tmp_urls, sizeof(tmp_urls));
	if (ret < 0) {
		goto error;
	}

	/*
	 * Do we have a UST url set. If yes, this means we have both kernel and UST
	 * to print.
	 */
	if (*tmp_uurl != '\0') {
		ret = snprintf(dst, size, "[K]: %s [data: %d] -- [U]: %s [data: %d]",
				tmp_urls, kdata_port, tmp_uurl, udata_port);
	} else {
		int dport;
		if (kuri || (!kuri && !uuri)) {
			dport = kdata_port;
		} else {
			/* No kernel URI, use the UST port. */
			dport = udata_port;
		}
		ret = snprintf(dst, size, "%s [data: %d]", tmp_urls, dport);
	}

error:
	return ret;
}

/*
 * Get run-time attributes if the session has been started (discarded events,
 * lost packets).
 */
static int get_kernel_runtime_stats(struct ltt_session *session,
		struct ltt_kernel_channel *kchan, uint64_t *discarded_events,
		uint64_t *lost_packets)
{
	int ret;

	if (!session->has_been_started) {
		ret = 0;
		*discarded_events = 0;
		*lost_packets = 0;
		goto end;
	}

	ret = consumer_get_discarded_events(session->id, kchan->key,
			session->kernel_session->consumer,
			discarded_events);
	if (ret < 0) {
		goto end;
	}

	ret = consumer_get_lost_packets(session->id, kchan->key,
			session->kernel_session->consumer,
			lost_packets);
	if (ret < 0) {
		goto end;
	}

end:
	return ret;
}

/*
 * Get run-time attributes if the session has been started (discarded events,
 * lost packets).
 */
static int get_ust_runtime_stats(struct ltt_session *session,
		struct ltt_ust_channel *uchan, uint64_t *discarded_events,
		uint64_t *lost_packets)
{
	int ret;
	struct ltt_ust_session *usess;

	if (!discarded_events || !lost_packets) {
		ret = -1;
		goto end;
	}

	usess = session->ust_session;
	assert(discarded_events);
	assert(lost_packets);

	if (!usess || !session->has_been_started) {
		*discarded_events = 0;
		*lost_packets = 0;
		ret = 0;
		goto end;
	}

	if (usess->buffer_type == LTTNG_BUFFER_PER_UID) {
		ret = ust_app_uid_get_channel_runtime_stats(usess->id,
				&usess->buffer_reg_uid_list,
				usess->consumer, uchan->id,
				uchan->attr.overwrite,
				discarded_events,
				lost_packets);
	} else if (usess->buffer_type == LTTNG_BUFFER_PER_PID) {
		ret = ust_app_pid_get_channel_runtime_stats(usess,
				uchan, usess->consumer,
				uchan->attr.overwrite,
				discarded_events,
				lost_packets);
		if (ret < 0) {
			goto end;
		}
		*discarded_events += uchan->per_pid_closed_app_discarded;
		*lost_packets += uchan->per_pid_closed_app_lost;
	} else {
		ERR("Unsupported buffer type");
		assert(0);
		ret = -1;
		goto end;
	}

end:
	return ret;
}

/*
 * Fill lttng_channel array of all channels.
 */
static ssize_t list_lttng_channels(enum lttng_domain_type domain,
		struct ltt_session *session, struct lttng_channel *channels,
		struct lttng_channel_extended *chan_exts)
{
	int i = 0, ret = 0;
	struct ltt_kernel_channel *kchan;

	DBG("Listing channels for session %s", session->name);

	switch (domain) {
	case LTTNG_DOMAIN_KERNEL:
		/* Kernel channels */
		if (session->kernel_session != NULL) {
			cds_list_for_each_entry(kchan,
					&session->kernel_session->channel_list.head, list) {
				uint64_t discarded_events, lost_packets;
				struct lttng_channel_extended *extended;

				extended = (struct lttng_channel_extended *)
						kchan->channel->attr.extended.ptr;

				ret = get_kernel_runtime_stats(session, kchan,
						&discarded_events, &lost_packets);
				if (ret < 0) {
					goto end;
				}
				/* Copy lttng_channel struct to array */
				memcpy(&channels[i], kchan->channel, sizeof(struct lttng_channel));
				channels[i].enabled = kchan->enabled;
				chan_exts[i].discarded_events =
						discarded_events;
				chan_exts[i].lost_packets = lost_packets;
				chan_exts[i].monitor_timer_interval =
						extended->monitor_timer_interval;
				chan_exts[i].blocking_timeout = 0;
				i++;
			}
		}
		break;
	case LTTNG_DOMAIN_UST:
	{
		struct lttng_ht_iter iter;
		struct ltt_ust_channel *uchan;

		rcu_read_lock();
		cds_lfht_for_each_entry(session->ust_session->domain_global.channels->ht,
				&iter.iter, uchan, node.node) {
			uint64_t discarded_events = 0, lost_packets = 0;

			if (lttng_strncpy(channels[i].name, uchan->name,
					LTTNG_SYMBOL_NAME_LEN)) {
				break;
			}
			channels[i].attr.overwrite = uchan->attr.overwrite;
			channels[i].attr.subbuf_size = uchan->attr.subbuf_size;
			channels[i].attr.num_subbuf = uchan->attr.num_subbuf;
			channels[i].attr.switch_timer_interval =
				uchan->attr.switch_timer_interval;
			channels[i].attr.read_timer_interval =
				uchan->attr.read_timer_interval;
			channels[i].enabled = uchan->enabled;
			channels[i].attr.tracefile_size = uchan->tracefile_size;
			channels[i].attr.tracefile_count = uchan->tracefile_count;

			/*
			 * Map enum lttng_ust_output to enum lttng_event_output.
			 */
			switch (uchan->attr.output) {
			case LTTNG_UST_MMAP:
				channels[i].attr.output = LTTNG_EVENT_MMAP;
				break;
			default:
				/*
				 * LTTNG_UST_MMAP is the only supported UST
				 * output mode.
				 */
				assert(0);
				break;
			}

			chan_exts[i].monitor_timer_interval =
					uchan->monitor_timer_interval;
			chan_exts[i].blocking_timeout =
				uchan->attr.u.s.blocking_timeout;

			ret = get_ust_runtime_stats(session, uchan,
					&discarded_events, &lost_packets);
			if (ret < 0) {
				break;
			}
			chan_exts[i].discarded_events = discarded_events;
			chan_exts[i].lost_packets = lost_packets;
			i++;
		}
		rcu_read_unlock();
		break;
	}
	default:
		break;
	}

end:
	if (ret < 0) {
		return -LTTNG_ERR_FATAL;
	} else {
		return LTTNG_OK;
	}
}

static int increment_extended_len(const char *filter_expression,
		struct lttng_event_exclusion *exclusion,
		const struct lttng_userspace_probe_location *probe_location,
		size_t *extended_len)
{
	int ret = 0;

	*extended_len += sizeof(struct lttcomm_event_extended_header);

	if (filter_expression) {
		*extended_len += strlen(filter_expression) + 1;
	}

	if (exclusion) {
		*extended_len += exclusion->count * LTTNG_SYMBOL_NAME_LEN;
	}

	if (probe_location) {
		ret = lttng_userspace_probe_location_serialize(probe_location,
				NULL, NULL);
		if (ret < 0) {
			goto end;
		}
		*extended_len += ret;
	}
	ret = 0;
end:
	return ret;
}

static int append_extended_info(const char *filter_expression,
		struct lttng_event_exclusion *exclusion,
		struct lttng_userspace_probe_location *probe_location,
		void **extended_at)
{
	int ret = 0;
	size_t filter_len = 0;
	size_t nb_exclusions = 0;
	size_t userspace_probe_location_len = 0;
	struct lttng_dynamic_buffer location_buffer;
	struct lttcomm_event_extended_header extended_header;

	if (filter_expression) {
		filter_len = strlen(filter_expression) + 1;
	}

	if (exclusion) {
		nb_exclusions = exclusion->count;
	}

	if (probe_location) {
		lttng_dynamic_buffer_init(&location_buffer);
		ret = lttng_userspace_probe_location_serialize(probe_location,
				&location_buffer, NULL);
		if (ret < 0) {
			ret = -1;
			goto end;
		}
		userspace_probe_location_len = location_buffer.size;
	}

	/* Set header fields */
	extended_header.filter_len = filter_len;
	extended_header.nb_exclusions = nb_exclusions;
	extended_header.userspace_probe_location_len = userspace_probe_location_len;

	/* Copy header */
	memcpy(*extended_at, &extended_header, sizeof(extended_header));
	*extended_at += sizeof(extended_header);

	/* Copy filter string */
	if (filter_expression) {
		memcpy(*extended_at, filter_expression, filter_len);
		*extended_at += filter_len;
	}

	/* Copy exclusion names */
	if (exclusion) {
		size_t len = nb_exclusions * LTTNG_SYMBOL_NAME_LEN;

		memcpy(*extended_at, &exclusion->names, len);
		*extended_at += len;
	}

	if (probe_location) {
		memcpy(*extended_at, location_buffer.data, location_buffer.size);
		*extended_at += location_buffer.size;
		lttng_dynamic_buffer_reset(&location_buffer);
	}
	ret = 0;
end:
	return ret;
}

/*
 * Create a list of agent domain events.
 *
 * Return number of events in list on success or else a negative value.
 */
static int list_lttng_agent_events(struct agent *agt,
		struct lttng_event **events, size_t *total_size)
{
	int i = 0, ret = 0;
	unsigned int nb_event = 0;
	struct agent_event *event;
	struct lttng_event *tmp_events;
	struct lttng_ht_iter iter;
	size_t extended_len = 0;
	void *extended_at;

	assert(agt);
	assert(events);

	DBG3("Listing agent events");

	rcu_read_lock();
	nb_event = lttng_ht_get_count(agt->events);
	rcu_read_unlock();
	if (nb_event == 0) {
		ret = nb_event;
		*total_size = 0;
		goto error;
	}

	/* Compute required extended infos size */
	extended_len = nb_event * sizeof(struct lttcomm_event_extended_header);

	/*
	 * This is only valid because the commands which add events are
	 * processed in the same thread as the listing.
	 */
	rcu_read_lock();
	cds_lfht_for_each_entry(agt->events->ht, &iter.iter, event, node.node) {
		ret = increment_extended_len(event->filter_expression, NULL, NULL,
				&extended_len);
		if (ret) {
			DBG("Error computing the length of extended info message");
			ret = -LTTNG_ERR_FATAL;
			goto error;
		}
	}
	rcu_read_unlock();

	*total_size = nb_event * sizeof(*tmp_events) + extended_len;
	tmp_events = zmalloc(*total_size);
	if (!tmp_events) {
		PERROR("zmalloc agent events session");
		ret = -LTTNG_ERR_FATAL;
		goto error;
	}

	extended_at = ((uint8_t *) tmp_events) +
		nb_event * sizeof(struct lttng_event);

	rcu_read_lock();
	cds_lfht_for_each_entry(agt->events->ht, &iter.iter, event, node.node) {
		strncpy(tmp_events[i].name, event->name, sizeof(tmp_events[i].name));
		tmp_events[i].name[sizeof(tmp_events[i].name) - 1] = '\0';
		tmp_events[i].enabled = event->enabled;
		tmp_events[i].loglevel = event->loglevel_value;
		tmp_events[i].loglevel_type = event->loglevel_type;
		i++;

		/* Append extended info */
		ret = append_extended_info(event->filter_expression, NULL, NULL,
				&extended_at);
		if (ret) {
			DBG("Error appending extended info message");
			ret = -LTTNG_ERR_FATAL;
			goto error;
		}
	}

	*events = tmp_events;
	ret = nb_event;
	assert(nb_event == i);

error:
	rcu_read_unlock();
	return ret;
}

/*
 * Create a list of ust global domain events.
 */
static int list_lttng_ust_global_events(char *channel_name,
		struct ltt_ust_domain_global *ust_global,
		struct lttng_event **events, size_t *total_size)
{
	int i = 0, ret = 0;
	unsigned int nb_event = 0;
	struct lttng_ht_iter iter;
	struct lttng_ht_node_str *node;
	struct ltt_ust_channel *uchan;
	struct ltt_ust_event *uevent;
	struct lttng_event *tmp;
	size_t extended_len = 0;
	void *extended_at;

	DBG("Listing UST global events for channel %s", channel_name);

	rcu_read_lock();

	lttng_ht_lookup(ust_global->channels, (void *)channel_name, &iter);
	node = lttng_ht_iter_get_node_str(&iter);
	if (node == NULL) {
		ret = LTTNG_ERR_UST_CHAN_NOT_FOUND;
		goto end;
	}

	uchan = caa_container_of(&node->node, struct ltt_ust_channel, node.node);

	nb_event = lttng_ht_get_count(uchan->events);
	if (nb_event == 0) {
		ret = nb_event;
		*total_size = 0;
		goto end;
	}

	DBG3("Listing UST global %d events", nb_event);

	/* Compute required extended infos size */
	cds_lfht_for_each_entry(uchan->events->ht, &iter.iter, uevent, node.node) {
		if (uevent->internal) {
			nb_event--;
			continue;
		}

		ret = increment_extended_len(uevent->filter_expression,
			uevent->exclusion, NULL, &extended_len);
		if (ret) {
			DBG("Error computing the length of extended info message");
			ret = -LTTNG_ERR_FATAL;
			goto end;
		}
	}
	if (nb_event == 0) {
		/* All events are internal, skip. */
		ret = 0;
		*total_size = 0;
		goto end;
	}

	*total_size = nb_event * sizeof(struct lttng_event) + extended_len;
	tmp = zmalloc(*total_size);
	if (tmp == NULL) {
		ret = -LTTNG_ERR_FATAL;
		goto end;
	}

	extended_at = ((uint8_t *) tmp) + nb_event * sizeof(struct lttng_event);

	cds_lfht_for_each_entry(uchan->events->ht, &iter.iter, uevent, node.node) {
		if (uevent->internal) {
			/* This event should remain hidden from clients */
			continue;
		}
		strncpy(tmp[i].name, uevent->attr.name, LTTNG_SYMBOL_NAME_LEN);
		tmp[i].name[LTTNG_SYMBOL_NAME_LEN - 1] = '\0';
		tmp[i].enabled = uevent->enabled;

		switch (uevent->attr.instrumentation) {
		case LTTNG_UST_TRACEPOINT:
			tmp[i].type = LTTNG_EVENT_TRACEPOINT;
			break;
		case LTTNG_UST_PROBE:
			tmp[i].type = LTTNG_EVENT_PROBE;
			break;
		case LTTNG_UST_FUNCTION:
			tmp[i].type = LTTNG_EVENT_FUNCTION;
			break;
		}

		tmp[i].loglevel = uevent->attr.loglevel;
		switch (uevent->attr.loglevel_type) {
		case LTTNG_UST_LOGLEVEL_ALL:
			tmp[i].loglevel_type = LTTNG_EVENT_LOGLEVEL_ALL;
			break;
		case LTTNG_UST_LOGLEVEL_RANGE:
			tmp[i].loglevel_type = LTTNG_EVENT_LOGLEVEL_RANGE;
			break;
		case LTTNG_UST_LOGLEVEL_SINGLE:
			tmp[i].loglevel_type = LTTNG_EVENT_LOGLEVEL_SINGLE;
			break;
		}
		if (uevent->filter) {
			tmp[i].filter = 1;
		}
		if (uevent->exclusion) {
			tmp[i].exclusion = 1;
		}
		i++;

		/* Append extended info */
		ret = append_extended_info(uevent->filter_expression,
			uevent->exclusion, NULL, &extended_at);
		if (ret) {
			DBG("Error appending extended info message");
			ret = -LTTNG_ERR_FATAL;
			goto end;
		}
	}

	ret = nb_event;
	*events = tmp;
end:
	rcu_read_unlock();
	return ret;
}

/*
 * Fill lttng_event array of all kernel events in the channel.
 */
static int list_lttng_kernel_events(char *channel_name,
		struct ltt_kernel_session *kernel_session,
		struct lttng_event **events, size_t *total_size)
{
	int i = 0, ret;
	unsigned int nb_event;
	struct ltt_kernel_event *event;
	struct ltt_kernel_channel *kchan;
	size_t extended_len = 0;
	void *extended_at;

	kchan = trace_kernel_get_channel_by_name(channel_name, kernel_session);
	if (kchan == NULL) {
		ret = LTTNG_ERR_KERN_CHAN_NOT_FOUND;
		goto error;
	}

	nb_event = kchan->event_count;

	DBG("Listing events for channel %s", kchan->channel->name);

	if (nb_event == 0) {
		*total_size = 0;
		*events = NULL;
		goto end;
	}

	/* Compute required extended infos size */
	cds_list_for_each_entry(event, &kchan->events_list.head, list) {
		ret = increment_extended_len(event->filter_expression, NULL,
			event->userspace_probe_location,
			&extended_len);
		if (ret) {
			DBG("Error computing the length of extended info message");
			ret = -LTTNG_ERR_FATAL;
			goto error;
		}
	}

	*total_size = nb_event * sizeof(struct lttng_event) + extended_len;
	*events = zmalloc(*total_size);
	if (*events == NULL) {
		ret = -LTTNG_ERR_FATAL;
		goto error;
	}

	extended_at = ((void *) *events) +
		nb_event * sizeof(struct lttng_event);

	/* Kernel channels */
	cds_list_for_each_entry(event, &kchan->events_list.head , list) {
		strncpy((*events)[i].name, event->event->name, LTTNG_SYMBOL_NAME_LEN);
		(*events)[i].name[LTTNG_SYMBOL_NAME_LEN - 1] = '\0';
		(*events)[i].enabled = event->enabled;
		(*events)[i].filter =
				(unsigned char) !!event->filter_expression;

		switch (event->event->instrumentation) {
		case LTTNG_KERNEL_TRACEPOINT:
			(*events)[i].type = LTTNG_EVENT_TRACEPOINT;
			break;
		case LTTNG_KERNEL_KRETPROBE:
			(*events)[i].type = LTTNG_EVENT_FUNCTION;
			memcpy(&(*events)[i].attr.probe, &event->event->u.kprobe,
					sizeof(struct lttng_kernel_kprobe));
			break;
		case LTTNG_KERNEL_KPROBE:
			(*events)[i].type = LTTNG_EVENT_PROBE;
			memcpy(&(*events)[i].attr.probe, &event->event->u.kprobe,
					sizeof(struct lttng_kernel_kprobe));
			break;
		case LTTNG_KERNEL_UPROBE:
			(*events)[i].type = LTTNG_EVENT_USERSPACE_PROBE;
			break;
		case LTTNG_KERNEL_FUNCTION:
			(*events)[i].type = LTTNG_EVENT_FUNCTION;
			memcpy(&((*events)[i].attr.ftrace), &event->event->u.ftrace,
					sizeof(struct lttng_kernel_function));
			break;
		case LTTNG_KERNEL_NOOP:
			(*events)[i].type = LTTNG_EVENT_NOOP;
			break;
		case LTTNG_KERNEL_SYSCALL:
			(*events)[i].type = LTTNG_EVENT_SYSCALL;
			break;
		case LTTNG_KERNEL_ALL:
			/* fall-through. */
		default:
			assert(0);
			break;
		}
		i++;

		/* Append extended info */
		ret = append_extended_info(event->filter_expression, NULL,
			event->userspace_probe_location, &extended_at);
		if (ret) {
			DBG("Error appending extended info message");
			ret = -LTTNG_ERR_FATAL;
			goto error;
		}
	}

end:
	return nb_event;

error:
	/* Negate the error code to differentiate the size from an error */
	return -ret;
}

/*
 * Add URI so the consumer output object. Set the correct path depending on the
 * domain adding the default trace directory.
 */
static int add_uri_to_consumer(struct consumer_output *consumer,
		struct lttng_uri *uri, enum lttng_domain_type domain,
		const char *session_name)
{
	int ret = LTTNG_OK;
	const char *default_trace_dir;

	assert(uri);

	if (consumer == NULL) {
		DBG("No consumer detected. Don't add URI. Stopping.");
		ret = LTTNG_ERR_NO_CONSUMER;
		goto error;
	}

	switch (domain) {
	case LTTNG_DOMAIN_KERNEL:
		default_trace_dir = DEFAULT_KERNEL_TRACE_DIR;
		break;
	case LTTNG_DOMAIN_UST:
		default_trace_dir = DEFAULT_UST_TRACE_DIR;
		break;
	default:
		/*
		 * This case is possible is we try to add the URI to the global tracing
		 * session consumer object which in this case there is no subdir.
		 */
		default_trace_dir = "";
	}

	switch (uri->dtype) {
	case LTTNG_DST_IPV4:
	case LTTNG_DST_IPV6:
		DBG2("Setting network URI to consumer");

		if (consumer->type == CONSUMER_DST_NET) {
			if ((uri->stype == LTTNG_STREAM_CONTROL &&
				consumer->dst.net.control_isset) ||
				(uri->stype == LTTNG_STREAM_DATA &&
				consumer->dst.net.data_isset)) {
				ret = LTTNG_ERR_URL_EXIST;
				goto error;
			}
		} else {
			memset(&consumer->dst.net, 0, sizeof(consumer->dst.net));
		}

		consumer->type = CONSUMER_DST_NET;

		/* Set URI into consumer output object */
		ret = consumer_set_network_uri(consumer, uri);
		if (ret < 0) {
			ret = -ret;
			goto error;
		} else if (ret == 1) {
			/*
			 * URI was the same in the consumer so we do not append the subdir
			 * again so to not duplicate output dir.
			 */
			ret = LTTNG_OK;
			goto error;
		}

		if (uri->stype == LTTNG_STREAM_CONTROL && strlen(uri->subdir) == 0) {
			ret = consumer_set_subdir(consumer, session_name);
			if (ret < 0) {
				ret = LTTNG_ERR_FATAL;
				goto error;
			}
		}

		if (uri->stype == LTTNG_STREAM_CONTROL) {
			/* On a new subdir, reappend the default trace dir. */
			strncat(consumer->subdir, default_trace_dir,
					sizeof(consumer->subdir) - strlen(consumer->subdir) - 1);
			DBG3("Append domain trace name to subdir %s", consumer->subdir);
		}

		break;
	case LTTNG_DST_PATH:
		DBG2("Setting trace directory path from URI to %s", uri->dst.path);
		memset(consumer->dst.session_root_path, 0,
				sizeof(consumer->dst.session_root_path));
		/* Explicit length checks for strcpy and strcat. */
		if (strlen(uri->dst.path) + strlen(default_trace_dir)
				>= sizeof(consumer->dst.session_root_path)) {
			ret = LTTNG_ERR_FATAL;
			goto error;
		}
		strcpy(consumer->dst.session_root_path, uri->dst.path);
		/* Append default trace dir */
		strcat(consumer->dst.session_root_path, default_trace_dir);
		/* Flag consumer as local. */
		consumer->type = CONSUMER_DST_LOCAL;
		break;
	}

	ret = LTTNG_OK;

error:
	return ret;
}

/*
 * Init tracing by creating trace directory and sending fds kernel consumer.
 */
static int init_kernel_tracing(struct ltt_kernel_session *session)
{
	int ret = 0;
	struct lttng_ht_iter iter;
	struct consumer_socket *socket;

	assert(session);

	rcu_read_lock();

	if (session->consumer_fds_sent == 0 && session->consumer != NULL) {
		cds_lfht_for_each_entry(session->consumer->socks->ht, &iter.iter,
				socket, node.node) {
			pthread_mutex_lock(socket->lock);
			ret = kernel_consumer_send_session(socket, session);
			pthread_mutex_unlock(socket->lock);
			if (ret < 0) {
				ret = LTTNG_ERR_KERN_CONSUMER_FAIL;
				goto error;
			}
		}
	}

error:
	rcu_read_unlock();
	return ret;
}

/*
 * Create a socket to the relayd using the URI.
 *
 * On success, the relayd_sock pointer is set to the created socket.
 * Else, it's stays untouched and a lttcomm error code is returned.
 */
static int create_connect_relayd(struct lttng_uri *uri,
		struct lttcomm_relayd_sock **relayd_sock,
		struct consumer_output *consumer)
{
	int ret;
	struct lttcomm_relayd_sock *rsock;

	rsock = lttcomm_alloc_relayd_sock(uri, RELAYD_VERSION_COMM_MAJOR,
			RELAYD_VERSION_COMM_MINOR);
	if (!rsock) {
		ret = LTTNG_ERR_FATAL;
		goto error;
	}

	/*
	 * Connect to relayd so we can proceed with a session creation. This call
	 * can possibly block for an arbitrary amount of time to set the health
	 * state to be in poll execution.
	 */
	health_poll_entry();
	ret = relayd_connect(rsock);
	health_poll_exit();
	if (ret < 0) {
		ERR("Unable to reach lttng-relayd");
		ret = LTTNG_ERR_RELAYD_CONNECT_FAIL;
		goto free_sock;
	}

	/* Create socket for control stream. */
	if (uri->stype == LTTNG_STREAM_CONTROL) {
		DBG3("Creating relayd stream socket from URI");

		/* Check relayd version */
		ret = relayd_version_check(rsock);
		if (ret == LTTNG_ERR_RELAYD_VERSION_FAIL) {
			goto close_sock;
		} else if (ret < 0) {
			ERR("Unable to reach lttng-relayd");
			ret = LTTNG_ERR_RELAYD_CONNECT_FAIL;
			goto close_sock;
		}
		consumer->relay_major_version = rsock->major;
		consumer->relay_minor_version = rsock->minor;
	} else if (uri->stype == LTTNG_STREAM_DATA) {
		DBG3("Creating relayd data socket from URI");
	} else {
		/* Command is not valid */
		ERR("Relayd invalid stream type: %d", uri->stype);
		ret = LTTNG_ERR_INVALID;
		goto close_sock;
	}

	*relayd_sock = rsock;

	return LTTNG_OK;

close_sock:
	/* The returned value is not useful since we are on an error path. */
	(void) relayd_close(rsock);
free_sock:
	free(rsock);
error:
	return ret;
}

/*
 * Connect to the relayd using URI and send the socket to the right consumer.
 *
 * The consumer socket lock must be held by the caller.
 */
static int send_consumer_relayd_socket(unsigned int session_id,
		struct lttng_uri *relayd_uri,
		struct consumer_output *consumer,
		struct consumer_socket *consumer_sock,
		char *session_name, char *hostname, int session_live_timer)
{
	int ret;
	struct lttcomm_relayd_sock *rsock = NULL;

	/* Connect to relayd and make version check if uri is the control. */
	ret = create_connect_relayd(relayd_uri, &rsock, consumer);
	if (ret != LTTNG_OK) {
		goto relayd_comm_error;
	}
	assert(rsock);

	/* Set the network sequence index if not set. */
	if (consumer->net_seq_index == (uint64_t) -1ULL) {
		pthread_mutex_lock(&relayd_net_seq_idx_lock);
		/*
		 * Increment net_seq_idx because we are about to transfer the
		 * new relayd socket to the consumer.
		 * Assign unique key so the consumer can match streams.
		 */
		consumer->net_seq_index = ++relayd_net_seq_idx;
		pthread_mutex_unlock(&relayd_net_seq_idx_lock);
	}

	/* Send relayd socket to consumer. */
	ret = consumer_send_relayd_socket(consumer_sock, rsock, consumer,
			relayd_uri->stype, session_id,
			session_name, hostname, session_live_timer);
	if (ret < 0) {
		ret = LTTNG_ERR_ENABLE_CONSUMER_FAIL;
		goto close_sock;
	}

	/* Flag that the corresponding socket was sent. */
	if (relayd_uri->stype == LTTNG_STREAM_CONTROL) {
		consumer_sock->control_sock_sent = 1;
	} else if (relayd_uri->stype == LTTNG_STREAM_DATA) {
		consumer_sock->data_sock_sent = 1;
	}

	ret = LTTNG_OK;

	/*
	 * Close socket which was dup on the consumer side. The session daemon does
	 * NOT keep track of the relayd socket(s) once transfer to the consumer.
	 */

close_sock:
	if (ret != LTTNG_OK) {
		/*
		 * The consumer output for this session should not be used anymore
		 * since the relayd connection failed thus making any tracing or/and
		 * streaming not usable.
		 */
		consumer->enabled = 0;
	}
	(void) relayd_close(rsock);
	free(rsock);

relayd_comm_error:
	return ret;
}

/*
 * Send both relayd sockets to a specific consumer and domain.  This is a
 * helper function to facilitate sending the information to the consumer for a
 * session.
 *
 * The consumer socket lock must be held by the caller.
 */
static int send_consumer_relayd_sockets(enum lttng_domain_type domain,
		unsigned int session_id, struct consumer_output *consumer,
		struct consumer_socket *sock, char *session_name,
		char *hostname, int session_live_timer)
{
	int ret = LTTNG_OK;

	assert(consumer);
	assert(sock);

	/* Sending control relayd socket. */
	if (!sock->control_sock_sent) {
		ret = send_consumer_relayd_socket(session_id,
				&consumer->dst.net.control, consumer, sock,
				session_name, hostname, session_live_timer);
		if (ret != LTTNG_OK) {
			goto error;
		}
	}

	/* Sending data relayd socket. */
	if (!sock->data_sock_sent) {
		ret = send_consumer_relayd_socket(session_id,
				&consumer->dst.net.data, consumer, sock,
				session_name, hostname, session_live_timer);
		if (ret != LTTNG_OK) {
			goto error;
		}
	}

error:
	return ret;
}

/*
 * Setup relayd connections for a tracing session. First creates the socket to
 * the relayd and send them to the right domain consumer. Consumer type MUST be
 * network.
 */
int cmd_setup_relayd(struct ltt_session *session)
{
	int ret = LTTNG_OK;
	struct ltt_ust_session *usess;
	struct ltt_kernel_session *ksess;
	struct consumer_socket *socket;
	struct lttng_ht_iter iter;

	assert(session);

	usess = session->ust_session;
	ksess = session->kernel_session;

	DBG("Setting relayd for session %s", session->name);

	rcu_read_lock();

	if (usess && usess->consumer && usess->consumer->type == CONSUMER_DST_NET
			&& usess->consumer->enabled) {
		/* For each consumer socket, send relayd sockets */
		cds_lfht_for_each_entry(usess->consumer->socks->ht, &iter.iter,
				socket, node.node) {
			pthread_mutex_lock(socket->lock);
			ret = send_consumer_relayd_sockets(LTTNG_DOMAIN_UST, session->id,
					usess->consumer, socket,
					session->name, session->hostname,
					session->live_timer);
			pthread_mutex_unlock(socket->lock);
			if (ret != LTTNG_OK) {
				goto error;
			}
			/* Session is now ready for network streaming. */
			session->net_handle = 1;
		}
		session->consumer->relay_major_version =
			usess->consumer->relay_major_version;
		session->consumer->relay_minor_version =
			usess->consumer->relay_minor_version;
	}

	if (ksess && ksess->consumer && ksess->consumer->type == CONSUMER_DST_NET
			&& ksess->consumer->enabled) {
		cds_lfht_for_each_entry(ksess->consumer->socks->ht, &iter.iter,
				socket, node.node) {
			pthread_mutex_lock(socket->lock);
			ret = send_consumer_relayd_sockets(LTTNG_DOMAIN_KERNEL, session->id,
					ksess->consumer, socket,
					session->name, session->hostname,
					session->live_timer);
			pthread_mutex_unlock(socket->lock);
			if (ret != LTTNG_OK) {
				goto error;
			}
			/* Session is now ready for network streaming. */
			session->net_handle = 1;
		}
		session->consumer->relay_major_version =
			ksess->consumer->relay_major_version;
		session->consumer->relay_minor_version =
			ksess->consumer->relay_minor_version;
	}

error:
	rcu_read_unlock();
	return ret;
}

/*
 * Start a kernel session by opening all necessary streams.
 */
static int start_kernel_session(struct ltt_kernel_session *ksess, int wpipe)
{
	int ret;
	struct ltt_kernel_channel *kchan;

	/* Open kernel metadata */
	if (ksess->metadata == NULL && ksess->output_traces) {
		ret = kernel_open_metadata(ksess);
		if (ret < 0) {
			ret = LTTNG_ERR_KERN_META_FAIL;
			goto error;
		}
	}

	/* Open kernel metadata stream */
	if (ksess->metadata && ksess->metadata_stream_fd < 0) {
		ret = kernel_open_metadata_stream(ksess);
		if (ret < 0) {
			ERR("Kernel create metadata stream failed");
			ret = LTTNG_ERR_KERN_STREAM_FAIL;
			goto error;
		}
	}

	/* For each channel */
	cds_list_for_each_entry(kchan, &ksess->channel_list.head, list) {
		if (kchan->stream_count == 0) {
			ret = kernel_open_channel_stream(kchan);
			if (ret < 0) {
				ret = LTTNG_ERR_KERN_STREAM_FAIL;
				goto error;
			}
			/* Update the stream global counter */
			ksess->stream_count_global += ret;
		}
	}

	/* Setup kernel consumer socket and send fds to it */
	ret = init_kernel_tracing(ksess);
	if (ret != 0) {
		ret = LTTNG_ERR_KERN_START_FAIL;
		goto error;
	}

	/* This start the kernel tracing */
	ret = kernel_start_session(ksess);
	if (ret < 0) {
		ret = LTTNG_ERR_KERN_START_FAIL;
		goto error;
	}

	/* Quiescent wait after starting trace */
	kernel_wait_quiescent(wpipe);

	ksess->active = 1;

	ret = LTTNG_OK;

error:
	return ret;
}

/*
 * Command LTTNG_DISABLE_CHANNEL processed by the client thread.
 */
int cmd_disable_channel(struct ltt_session *session,
		enum lttng_domain_type domain, char *channel_name)
{
	int ret;
	struct ltt_ust_session *usess;

	usess = session->ust_session;

	rcu_read_lock();

	switch (domain) {
	case LTTNG_DOMAIN_KERNEL:
	{
		ret = channel_kernel_disable(session->kernel_session,
				channel_name);
		if (ret != LTTNG_OK) {
			goto error;
		}

		kernel_wait_quiescent(kernel_tracer_fd);
		break;
	}
	case LTTNG_DOMAIN_UST:
	{
		struct ltt_ust_channel *uchan;
		struct lttng_ht *chan_ht;

		chan_ht = usess->domain_global.channels;

		uchan = trace_ust_find_channel_by_name(chan_ht, channel_name);
		if (uchan == NULL) {
			ret = LTTNG_ERR_UST_CHAN_NOT_FOUND;
			goto error;
		}

		ret = channel_ust_disable(usess, uchan);
		if (ret != LTTNG_OK) {
			goto error;
		}
		break;
	}
	default:
		ret = LTTNG_ERR_UNKNOWN_DOMAIN;
		goto error;
	}

	ret = LTTNG_OK;

error:
	rcu_read_unlock();
	return ret;
}

/*
 * Command LTTNG_TRACK_PID processed by the client thread.
 *
 * Called with session lock held.
 */
int cmd_track_pid(struct ltt_session *session, enum lttng_domain_type domain,
		int pid)
{
	int ret;

	rcu_read_lock();

	switch (domain) {
	case LTTNG_DOMAIN_KERNEL:
	{
		struct ltt_kernel_session *ksess;

		ksess = session->kernel_session;

		ret = kernel_track_pid(ksess, pid);
		if (ret != LTTNG_OK) {
			goto error;
		}

		kernel_wait_quiescent(kernel_tracer_fd);
		break;
	}
	case LTTNG_DOMAIN_UST:
	{
		struct ltt_ust_session *usess;

		usess = session->ust_session;

		ret = trace_ust_track_pid(usess, pid);
		if (ret != LTTNG_OK) {
			goto error;
		}
		break;
	}
	default:
		ret = LTTNG_ERR_UNKNOWN_DOMAIN;
		goto error;
	}

	ret = LTTNG_OK;

error:
	rcu_read_unlock();
	return ret;
}

/*
 * Command LTTNG_UNTRACK_PID processed by the client thread.
 *
 * Called with session lock held.
 */
int cmd_untrack_pid(struct ltt_session *session, enum lttng_domain_type domain,
		int pid)
{
	int ret;

	rcu_read_lock();

	switch (domain) {
	case LTTNG_DOMAIN_KERNEL:
	{
		struct ltt_kernel_session *ksess;

		ksess = session->kernel_session;

		ret = kernel_untrack_pid(ksess, pid);
		if (ret != LTTNG_OK) {
			goto error;
		}

		kernel_wait_quiescent(kernel_tracer_fd);
		break;
	}
	case LTTNG_DOMAIN_UST:
	{
		struct ltt_ust_session *usess;

		usess = session->ust_session;

		ret = trace_ust_untrack_pid(usess, pid);
		if (ret != LTTNG_OK) {
			goto error;
		}
		break;
	}
	default:
		ret = LTTNG_ERR_UNKNOWN_DOMAIN;
		goto error;
	}

	ret = LTTNG_OK;

error:
	rcu_read_unlock();
	return ret;
}

/*
 * Command LTTNG_ENABLE_CHANNEL processed by the client thread.
 *
 * The wpipe arguments is used as a notifier for the kernel thread.
 */
int cmd_enable_channel(struct ltt_session *session,
		struct lttng_domain *domain, struct lttng_channel *attr, int wpipe)
{
	int ret;
	struct ltt_ust_session *usess = session->ust_session;
	struct lttng_ht *chan_ht;
	size_t len;

	assert(session);
	assert(attr);
	assert(domain);

	len = lttng_strnlen(attr->name, sizeof(attr->name));

	/* Validate channel name */
	if (attr->name[0] == '.' ||
		memchr(attr->name, '/', len) != NULL) {
		ret = LTTNG_ERR_INVALID_CHANNEL_NAME;
		goto end;
	}

	DBG("Enabling channel %s for session %s", attr->name, session->name);

	rcu_read_lock();

	/*
	 * Don't try to enable a channel if the session has been started at
	 * some point in time before. The tracer does not allow it.
	 */
	if (session->has_been_started) {
		ret = LTTNG_ERR_TRACE_ALREADY_STARTED;
		goto error;
	}

	/*
	 * If the session is a live session, remove the switch timer, the
	 * live timer does the same thing but sends also synchronisation
	 * beacons for inactive streams.
	 */
	if (session->live_timer > 0) {
		attr->attr.live_timer_interval = session->live_timer;
		attr->attr.switch_timer_interval = 0;
	}

	/* Check for feature support */
	switch (domain->type) {
	case LTTNG_DOMAIN_KERNEL:
	{
		if (kernel_supports_ring_buffer_snapshot_sample_positions(kernel_tracer_fd) != 1) {
			/* Sampling position of buffer is not supported */
			WARN("Kernel tracer does not support buffer monitoring. "
					"Setting the monitor interval timer to 0 "
					"(disabled) for channel '%s' of session '%s'",
					attr-> name, session->name);
			lttng_channel_set_monitor_timer_interval(attr, 0);
		}
		break;
	}
	case LTTNG_DOMAIN_UST:
		break;
	case LTTNG_DOMAIN_JUL:
	case LTTNG_DOMAIN_LOG4J:
	case LTTNG_DOMAIN_PYTHON:
		if (!agent_tracing_is_enabled()) {
			DBG("Attempted to enable a channel in an agent domain but the agent thread is not running");
			ret = LTTNG_ERR_AGENT_TRACING_DISABLED;
			goto error;
		}
		break;
	default:
		ret = LTTNG_ERR_UNKNOWN_DOMAIN;
		goto error;
	}

	switch (domain->type) {
	case LTTNG_DOMAIN_KERNEL:
	{
		struct ltt_kernel_channel *kchan;

		kchan = trace_kernel_get_channel_by_name(attr->name,
				session->kernel_session);
		if (kchan == NULL) {
			ret = channel_kernel_create(session->kernel_session, attr, wpipe);
			if (attr->name[0] != '\0') {
				session->kernel_session->has_non_default_channel = 1;
			}
		} else {
			ret = channel_kernel_enable(session->kernel_session, kchan);
		}

		if (ret != LTTNG_OK) {
			goto error;
		}

		kernel_wait_quiescent(kernel_tracer_fd);
		break;
	}
	case LTTNG_DOMAIN_UST:
	case LTTNG_DOMAIN_JUL:
	case LTTNG_DOMAIN_LOG4J:
	case LTTNG_DOMAIN_PYTHON:
	{
		struct ltt_ust_channel *uchan;

		/*
		 * FIXME
		 *
		 * Current agent implementation limitations force us to allow
		 * only one channel at once in "agent" subdomains. Each
		 * subdomain has a default channel name which must be strictly
		 * adhered to.
		 */
		if (domain->type == LTTNG_DOMAIN_JUL) {
			if (strncmp(attr->name, DEFAULT_JUL_CHANNEL_NAME,
					LTTNG_SYMBOL_NAME_LEN)) {
				ret = LTTNG_ERR_INVALID_CHANNEL_NAME;
				goto error;
			}
		} else if (domain->type == LTTNG_DOMAIN_LOG4J) {
			if (strncmp(attr->name, DEFAULT_LOG4J_CHANNEL_NAME,
					LTTNG_SYMBOL_NAME_LEN)) {
				ret = LTTNG_ERR_INVALID_CHANNEL_NAME;
				goto error;
			}
		} else if (domain->type == LTTNG_DOMAIN_PYTHON) {
			if (strncmp(attr->name, DEFAULT_PYTHON_CHANNEL_NAME,
					LTTNG_SYMBOL_NAME_LEN)) {
				ret = LTTNG_ERR_INVALID_CHANNEL_NAME;
				goto error;
			}
		}

		chan_ht = usess->domain_global.channels;

		uchan = trace_ust_find_channel_by_name(chan_ht, attr->name);
		if (uchan == NULL) {
			ret = channel_ust_create(usess, attr, domain->buf_type);
			if (attr->name[0] != '\0') {
				usess->has_non_default_channel = 1;
			}
		} else {
			ret = channel_ust_enable(usess, uchan);
		}
		break;
	}
	default:
		ret = LTTNG_ERR_UNKNOWN_DOMAIN;
		goto error;
	}

error:
	rcu_read_unlock();
end:
	return ret;
}

/*
 * Command LTTNG_DISABLE_EVENT processed by the client thread.
 */
int cmd_disable_event(struct ltt_session *session,
		enum lttng_domain_type domain, char *channel_name,
		struct lttng_event *event)
{
	int ret;
	char *event_name;

	DBG("Disable event command for event \'%s\'", event->name);

	event_name = event->name;

	/* Error out on unhandled search criteria */
	if (event->loglevel_type || event->loglevel != -1 || event->enabled
			|| event->pid || event->filter || event->exclusion) {
		ret = LTTNG_ERR_UNK;
		goto error;
	}

	rcu_read_lock();

	switch (domain) {
	case LTTNG_DOMAIN_KERNEL:
	{
		struct ltt_kernel_channel *kchan;
		struct ltt_kernel_session *ksess;

		ksess = session->kernel_session;

		/*
		 * If a non-default channel has been created in the
		 * session, explicitely require that -c chan_name needs
		 * to be provided.
		 */
		if (ksess->has_non_default_channel && channel_name[0] == '\0') {
			ret = LTTNG_ERR_NEED_CHANNEL_NAME;
			goto error_unlock;
		}

		kchan = trace_kernel_get_channel_by_name(channel_name, ksess);
		if (kchan == NULL) {
			ret = LTTNG_ERR_KERN_CHAN_NOT_FOUND;
			goto error_unlock;
		}

		switch (event->type) {
		case LTTNG_EVENT_ALL:
		case LTTNG_EVENT_TRACEPOINT:
		case LTTNG_EVENT_SYSCALL:
		case LTTNG_EVENT_PROBE:
		case LTTNG_EVENT_FUNCTION:
		case LTTNG_EVENT_FUNCTION_ENTRY:/* fall-through */
			if (event_name[0] == '\0') {
				ret = event_kernel_disable_event(kchan,
					NULL, event->type);
			} else {
				ret = event_kernel_disable_event(kchan,
					event_name, event->type);
			}
			if (ret != LTTNG_OK) {
				goto error_unlock;
			}
			break;
		default:
			ret = LTTNG_ERR_UNK;
			goto error_unlock;
		}

		kernel_wait_quiescent(kernel_tracer_fd);
		break;
	}
	case LTTNG_DOMAIN_UST:
	{
		struct ltt_ust_channel *uchan;
		struct ltt_ust_session *usess;

		usess = session->ust_session;

		if (validate_ust_event_name(event_name)) {
			ret = LTTNG_ERR_INVALID_EVENT_NAME;
			goto error_unlock;
		}

		/*
		 * If a non-default channel has been created in the
		 * session, explicitly require that -c chan_name needs
		 * to be provided.
		 */
		if (usess->has_non_default_channel && channel_name[0] == '\0') {
			ret = LTTNG_ERR_NEED_CHANNEL_NAME;
			goto error_unlock;
		}

		uchan = trace_ust_find_channel_by_name(usess->domain_global.channels,
				channel_name);
		if (uchan == NULL) {
			ret = LTTNG_ERR_UST_CHAN_NOT_FOUND;
			goto error_unlock;
		}

		switch (event->type) {
		case LTTNG_EVENT_ALL:
			/*
			 * An empty event name means that everything
			 * should be disabled.
			 */
			if (event->name[0] == '\0') {
				ret = event_ust_disable_all_tracepoints(usess, uchan);
			} else {
				ret = event_ust_disable_tracepoint(usess, uchan,
						event_name);
			}
			if (ret != LTTNG_OK) {
				goto error_unlock;
			}
			break;
		default:
			ret = LTTNG_ERR_UNK;
			goto error_unlock;
		}

		DBG3("Disable UST event %s in channel %s completed", event_name,
				channel_name);
		break;
	}
	case LTTNG_DOMAIN_LOG4J:
	case LTTNG_DOMAIN_JUL:
	case LTTNG_DOMAIN_PYTHON:
	{
		struct agent *agt;
		struct ltt_ust_session *usess = session->ust_session;

		assert(usess);

		switch (event->type) {
		case LTTNG_EVENT_ALL:
			break;
		default:
			ret = LTTNG_ERR_UNK;
			goto error_unlock;
		}

		agt = trace_ust_find_agent(usess, domain);
		if (!agt) {
			ret = -LTTNG_ERR_UST_EVENT_NOT_FOUND;
			goto error_unlock;
		}
		/*
		 * An empty event name means that everything
		 * should be disabled.
		 */
		if (event->name[0] == '\0') {
			ret = event_agent_disable_all(usess, agt);
		} else {
			ret = event_agent_disable(usess, agt, event_name);
		}
		if (ret != LTTNG_OK) {
			goto error_unlock;
		}

		break;
	}
	default:
		ret = LTTNG_ERR_UND;
		goto error_unlock;
	}

	ret = LTTNG_OK;

error_unlock:
	rcu_read_unlock();
error:
	return ret;
}

/*
 * Command LTTNG_ADD_CONTEXT processed by the client thread.
 */
int cmd_add_context(struct ltt_session *session, enum lttng_domain_type domain,
		char *channel_name, struct lttng_event_context *ctx, int kwpipe)
{
	int ret, chan_kern_created = 0, chan_ust_created = 0;
	char *app_ctx_provider_name = NULL, *app_ctx_name = NULL;

	/*
	 * Don't try to add a context if the session has been started at
	 * some point in time before. The tracer does not allow it and would
	 * result in a corrupted trace.
	 */
	if (session->has_been_started) {
		ret = LTTNG_ERR_TRACE_ALREADY_STARTED;
		goto end;
	}

	if (ctx->ctx == LTTNG_EVENT_CONTEXT_APP_CONTEXT) {
		app_ctx_provider_name = ctx->u.app_ctx.provider_name;
		app_ctx_name = ctx->u.app_ctx.ctx_name;
	}

	switch (domain) {
	case LTTNG_DOMAIN_KERNEL:
		assert(session->kernel_session);

		if (session->kernel_session->channel_count == 0) {
			/* Create default channel */
			ret = channel_kernel_create(session->kernel_session, NULL, kwpipe);
			if (ret != LTTNG_OK) {
				goto error;
			}
			chan_kern_created = 1;
		}
		/* Add kernel context to kernel tracer */
		ret = context_kernel_add(session->kernel_session, ctx, channel_name);
		if (ret != LTTNG_OK) {
			goto error;
		}
		break;
	case LTTNG_DOMAIN_JUL:
	case LTTNG_DOMAIN_LOG4J:
	{
		/*
		 * Validate channel name.
		 * If no channel name is given and the domain is JUL or LOG4J,
		 * set it to the appropriate domain-specific channel name. If
		 * a name is provided but does not match the expexted channel
		 * name, return an error.
		 */
		if (domain == LTTNG_DOMAIN_JUL && *channel_name &&
				strcmp(channel_name,
				DEFAULT_JUL_CHANNEL_NAME)) {
			ret = LTTNG_ERR_UST_CHAN_NOT_FOUND;
			goto error;
		} else if (domain == LTTNG_DOMAIN_LOG4J && *channel_name &&
				strcmp(channel_name,
				DEFAULT_LOG4J_CHANNEL_NAME)) {
			ret = LTTNG_ERR_UST_CHAN_NOT_FOUND;
			goto error;
		}
		/* break is _not_ missing here. */
	}
	case LTTNG_DOMAIN_UST:
	{
		struct ltt_ust_session *usess = session->ust_session;
		unsigned int chan_count;

		assert(usess);

		chan_count = lttng_ht_get_count(usess->domain_global.channels);
		if (chan_count == 0) {
			struct lttng_channel *attr;
			/* Create default channel */
			attr = channel_new_default_attr(domain, usess->buffer_type);
			if (attr == NULL) {
				ret = LTTNG_ERR_FATAL;
				goto error;
			}

			ret = channel_ust_create(usess, attr, usess->buffer_type);
			if (ret != LTTNG_OK) {
				free(attr);
				goto error;
			}
			channel_attr_destroy(attr);
			chan_ust_created = 1;
		}

		ret = context_ust_add(usess, domain, ctx, channel_name);
		free(app_ctx_provider_name);
		free(app_ctx_name);
		app_ctx_name = NULL;
		app_ctx_provider_name = NULL;
		if (ret != LTTNG_OK) {
			goto error;
		}
		break;
	}
	default:
		ret = LTTNG_ERR_UND;
		goto error;
	}

	ret = LTTNG_OK;
	goto end;

error:
	if (chan_kern_created) {
		struct ltt_kernel_channel *kchan =
			trace_kernel_get_channel_by_name(DEFAULT_CHANNEL_NAME,
					session->kernel_session);
		/* Created previously, this should NOT fail. */
		assert(kchan);
		kernel_destroy_channel(kchan);
	}

	if (chan_ust_created) {
		struct ltt_ust_channel *uchan =
			trace_ust_find_channel_by_name(
					session->ust_session->domain_global.channels,
					DEFAULT_CHANNEL_NAME);
		/* Created previously, this should NOT fail. */
		assert(uchan);
		/* Remove from the channel list of the session. */
		trace_ust_delete_channel(session->ust_session->domain_global.channels,
				uchan);
		trace_ust_destroy_channel(uchan);
	}
end:
	free(app_ctx_provider_name);
	free(app_ctx_name);
	return ret;
}

static inline bool name_starts_with(const char *name, const char *prefix)
{
	const size_t max_cmp_len = min(strlen(prefix), LTTNG_SYMBOL_NAME_LEN);

	return !strncmp(name, prefix, max_cmp_len);
}

/* Perform userspace-specific event name validation */
static int validate_ust_event_name(const char *name)
{
	int ret = 0;

	if (!name) {
		ret = -1;
		goto end;
	}

	/*
	 * Check name against all internal UST event component namespaces used
	 * by the agents.
	 */
	if (name_starts_with(name, DEFAULT_JUL_EVENT_COMPONENT) ||
		name_starts_with(name, DEFAULT_LOG4J_EVENT_COMPONENT) ||
		name_starts_with(name, DEFAULT_PYTHON_EVENT_COMPONENT)) {
		ret = -1;
	}

end:
	return ret;
}

/*
 * Internal version of cmd_enable_event() with a supplemental
 * "internal_event" flag which is used to enable internal events which should
 * be hidden from clients. Such events are used in the agent implementation to
 * enable the events through which all "agent" events are funeled.
 */
static int _cmd_enable_event(struct ltt_session *session,
		struct lttng_domain *domain,
		char *channel_name, struct lttng_event *event,
		char *filter_expression,
		struct lttng_filter_bytecode *filter,
		struct lttng_event_exclusion *exclusion,
		int wpipe, bool internal_event)
{
	int ret = 0, channel_created = 0;
	struct lttng_channel *attr = NULL;

	assert(session);
	assert(event);
	assert(channel_name);

	/* If we have a filter, we must have its filter expression */
	assert(!(!!filter_expression ^ !!filter));

	/* Normalize event name as a globbing pattern */
	strutils_normalize_star_glob_pattern(event->name);

	/* Normalize exclusion names as globbing patterns */
	if (exclusion) {
		size_t i;

		for (i = 0; i < exclusion->count; i++) {
			char *name = LTTNG_EVENT_EXCLUSION_NAME_AT(exclusion, i);

			strutils_normalize_star_glob_pattern(name);
		}
	}

	DBG("Enable event command for event \'%s\'", event->name);

	rcu_read_lock();

	switch (domain->type) {
	case LTTNG_DOMAIN_KERNEL:
	{
		struct ltt_kernel_channel *kchan;

		/*
		 * If a non-default channel has been created in the
		 * session, explicitely require that -c chan_name needs
		 * to be provided.
		 */
		if (session->kernel_session->has_non_default_channel
				&& channel_name[0] == '\0') {
			ret = LTTNG_ERR_NEED_CHANNEL_NAME;
			goto error;
		}

		kchan = trace_kernel_get_channel_by_name(channel_name,
				session->kernel_session);
		if (kchan == NULL) {
			attr = channel_new_default_attr(LTTNG_DOMAIN_KERNEL,
					LTTNG_BUFFER_GLOBAL);
			if (attr == NULL) {
				ret = LTTNG_ERR_FATAL;
				goto error;
			}
			if (lttng_strncpy(attr->name, channel_name,
					sizeof(attr->name))) {
				ret = LTTNG_ERR_INVALID;
				goto error;
			}

			ret = cmd_enable_channel(session, domain, attr, wpipe);
			if (ret != LTTNG_OK) {
				goto error;
			}
			channel_created = 1;
		}

		/* Get the newly created kernel channel pointer */
		kchan = trace_kernel_get_channel_by_name(channel_name,
				session->kernel_session);
		if (kchan == NULL) {
			/* This sould not happen... */
			ret = LTTNG_ERR_FATAL;
			goto error;
		}

		switch (event->type) {
		case LTTNG_EVENT_ALL:
		{
			char *filter_expression_a = NULL;
			struct lttng_filter_bytecode *filter_a = NULL;

			/*
			 * We need to duplicate filter_expression and filter,
			 * because ownership is passed to first enable
			 * event.
			 */
			if (filter_expression) {
				filter_expression_a = strdup(filter_expression);
				if (!filter_expression_a) {
					ret = LTTNG_ERR_FATAL;
					goto error;
				}
			}
			if (filter) {
				filter_a = zmalloc(sizeof(*filter_a) + filter->len);
				if (!filter_a) {
					free(filter_expression_a);
					ret = LTTNG_ERR_FATAL;
					goto error;
				}
				memcpy(filter_a, filter, sizeof(*filter_a) + filter->len);
			}
			event->type = LTTNG_EVENT_TRACEPOINT;	/* Hack */
			ret = event_kernel_enable_event(kchan, event,
				filter_expression, filter);
			/* We have passed ownership */
			filter_expression = NULL;
			filter = NULL;
			if (ret != LTTNG_OK) {
				if (channel_created) {
					/* Let's not leak a useless channel. */
					kernel_destroy_channel(kchan);
				}
				free(filter_expression_a);
				free(filter_a);
				goto error;
			}
			event->type = LTTNG_EVENT_SYSCALL;	/* Hack */
			ret = event_kernel_enable_event(kchan, event,
				filter_expression_a, filter_a);
			/* We have passed ownership */
			filter_expression_a = NULL;
			filter_a = NULL;
			if (ret != LTTNG_OK) {
				goto error;
			}
			break;
		}
		case LTTNG_EVENT_PROBE:
		case LTTNG_EVENT_USERSPACE_PROBE:
		case LTTNG_EVENT_FUNCTION:
		case LTTNG_EVENT_FUNCTION_ENTRY:
		case LTTNG_EVENT_TRACEPOINT:
			ret = event_kernel_enable_event(kchan, event,
				filter_expression, filter);
			/* We have passed ownership */
			filter_expression = NULL;
			filter = NULL;
			if (ret != LTTNG_OK) {
				if (channel_created) {
					/* Let's not leak a useless channel. */
					kernel_destroy_channel(kchan);
				}
				goto error;
			}
			break;
		case LTTNG_EVENT_SYSCALL:
			ret = event_kernel_enable_event(kchan, event,
				filter_expression, filter);
			/* We have passed ownership */
			filter_expression = NULL;
			filter = NULL;
			if (ret != LTTNG_OK) {
				goto error;
			}
			break;
		default:
			ret = LTTNG_ERR_UNK;
			goto error;
		}

		kernel_wait_quiescent(kernel_tracer_fd);
		break;
	}
	case LTTNG_DOMAIN_UST:
	{
		struct ltt_ust_channel *uchan;
		struct ltt_ust_session *usess = session->ust_session;

		assert(usess);

		/*
		 * If a non-default channel has been created in the
		 * session, explicitely require that -c chan_name needs
		 * to be provided.
		 */
		if (usess->has_non_default_channel && channel_name[0] == '\0') {
			ret = LTTNG_ERR_NEED_CHANNEL_NAME;
			goto error;
		}

		/* Get channel from global UST domain */
		uchan = trace_ust_find_channel_by_name(usess->domain_global.channels,
				channel_name);
		if (uchan == NULL) {
			/* Create default channel */
			attr = channel_new_default_attr(LTTNG_DOMAIN_UST,
					usess->buffer_type);
			if (attr == NULL) {
				ret = LTTNG_ERR_FATAL;
				goto error;
			}
			if (lttng_strncpy(attr->name, channel_name,
					sizeof(attr->name))) {
				ret = LTTNG_ERR_INVALID;
				goto error;
			}

			ret = cmd_enable_channel(session, domain, attr, wpipe);
			if (ret != LTTNG_OK) {
				goto error;
			}

			/* Get the newly created channel reference back */
			uchan = trace_ust_find_channel_by_name(
					usess->domain_global.channels, channel_name);
			assert(uchan);
		}

		if (uchan->domain != LTTNG_DOMAIN_UST && !internal_event) {
			/*
			 * Don't allow users to add UST events to channels which
			 * are assigned to a userspace subdomain (JUL, Log4J,
			 * Python, etc.).
			 */
			ret = LTTNG_ERR_INVALID_CHANNEL_DOMAIN;
			goto error;
		}

		if (!internal_event) {
			/*
			 * Ensure the event name is not reserved for internal
			 * use.
			 */
			ret = validate_ust_event_name(event->name);
			if (ret) {
			        WARN("Userspace event name %s failed validation.",
						event->name);
				ret = LTTNG_ERR_INVALID_EVENT_NAME;
				goto error;
			}
		}

		/* At this point, the session and channel exist on the tracer */
		ret = event_ust_enable_tracepoint(usess, uchan, event,
				filter_expression, filter, exclusion,
				internal_event);
		/* We have passed ownership */
		filter_expression = NULL;
		filter = NULL;
		exclusion = NULL;
		if (ret == LTTNG_ERR_UST_EVENT_ENABLED) {
			goto already_enabled;
		} else if (ret != LTTNG_OK) {
			goto error;
		}
		break;
	}
	case LTTNG_DOMAIN_LOG4J:
	case LTTNG_DOMAIN_JUL:
	case LTTNG_DOMAIN_PYTHON:
	{
		const char *default_event_name, *default_chan_name;
		struct agent *agt;
		struct lttng_event uevent;
		struct lttng_domain tmp_dom;
		struct ltt_ust_session *usess = session->ust_session;

		assert(usess);

		if (!agent_tracing_is_enabled()) {
			DBG("Attempted to enable an event in an agent domain but the agent thread is not running");
			ret = LTTNG_ERR_AGENT_TRACING_DISABLED;
			goto error;
		}

		agt = trace_ust_find_agent(usess, domain->type);
		if (!agt) {
			agt = agent_create(domain->type);
			if (!agt) {
				ret = LTTNG_ERR_NOMEM;
				goto error;
			}
			agent_add(agt, usess->agents);
		}

		/* Create the default tracepoint. */
		memset(&uevent, 0, sizeof(uevent));
		uevent.type = LTTNG_EVENT_TRACEPOINT;
		uevent.loglevel_type = LTTNG_EVENT_LOGLEVEL_ALL;
		default_event_name = event_get_default_agent_ust_name(
				domain->type);
		if (!default_event_name) {
			ret = LTTNG_ERR_FATAL;
			goto error;
		}
		strncpy(uevent.name, default_event_name, sizeof(uevent.name));
		uevent.name[sizeof(uevent.name) - 1] = '\0';

		/*
		 * The domain type is changed because we are about to enable the
		 * default channel and event for the JUL domain that are hardcoded.
		 * This happens in the UST domain.
		 */
		memcpy(&tmp_dom, domain, sizeof(tmp_dom));
		tmp_dom.type = LTTNG_DOMAIN_UST;

		switch (domain->type) {
		case LTTNG_DOMAIN_LOG4J:
			default_chan_name = DEFAULT_LOG4J_CHANNEL_NAME;
			break;
		case LTTNG_DOMAIN_JUL:
			default_chan_name = DEFAULT_JUL_CHANNEL_NAME;
			break;
		case LTTNG_DOMAIN_PYTHON:
			default_chan_name = DEFAULT_PYTHON_CHANNEL_NAME;
			break;
		default:
			/* The switch/case we are in makes this impossible */
			assert(0);
		}

		{
			char *filter_expression_copy = NULL;
			struct lttng_filter_bytecode *filter_copy = NULL;

			if (filter) {
				const size_t filter_size = sizeof(
						struct lttng_filter_bytecode)
						+ filter->len;

				filter_copy = zmalloc(filter_size);
				if (!filter_copy) {
					ret = LTTNG_ERR_NOMEM;
					goto error;
				}
				memcpy(filter_copy, filter, filter_size);

				filter_expression_copy =
						strdup(filter_expression);
				if (!filter_expression) {
					ret = LTTNG_ERR_NOMEM;
				}

				if (!filter_expression_copy || !filter_copy) {
					free(filter_expression_copy);
					free(filter_copy);
					goto error;
				}
			}

			ret = cmd_enable_event_internal(session, &tmp_dom,
					(char *) default_chan_name,
					&uevent, filter_expression_copy,
					filter_copy, NULL, wpipe);
		}

		if (ret == LTTNG_ERR_UST_EVENT_ENABLED) {
			goto already_enabled;
		} else if (ret != LTTNG_OK) {
			goto error;
		}

		/* The wild card * means that everything should be enabled. */
		if (strncmp(event->name, "*", 1) == 0 && strlen(event->name) == 1) {
			ret = event_agent_enable_all(usess, agt, event, filter,
					filter_expression);
		} else {
			ret = event_agent_enable(usess, agt, event, filter,
					filter_expression);
		}
		filter = NULL;
		filter_expression = NULL;
		if (ret != LTTNG_OK) {
			goto error;
		}

		break;
	}
	default:
		ret = LTTNG_ERR_UND;
		goto error;
	}

	ret = LTTNG_OK;

already_enabled:
error:
	free(filter_expression);
	free(filter);
	free(exclusion);
	channel_attr_destroy(attr);
	rcu_read_unlock();
	return ret;
}

/*
 * Command LTTNG_ENABLE_EVENT processed by the client thread.
 * We own filter, exclusion, and filter_expression.
 */
int cmd_enable_event(struct ltt_session *session, struct lttng_domain *domain,
		char *channel_name, struct lttng_event *event,
		char *filter_expression,
		struct lttng_filter_bytecode *filter,
		struct lttng_event_exclusion *exclusion,
		int wpipe)
{
	return _cmd_enable_event(session, domain, channel_name, event,
			filter_expression, filter, exclusion, wpipe, false);
}

/*
 * Enable an event which is internal to LTTng. An internal should
 * never be made visible to clients and are immune to checks such as
 * reserved names.
 */
static int cmd_enable_event_internal(struct ltt_session *session,
		struct lttng_domain *domain,
		char *channel_name, struct lttng_event *event,
		char *filter_expression,
		struct lttng_filter_bytecode *filter,
		struct lttng_event_exclusion *exclusion,
		int wpipe)
{
	return _cmd_enable_event(session, domain, channel_name, event,
			filter_expression, filter, exclusion, wpipe, true);
}

/*
 * Command LTTNG_LIST_TRACEPOINTS processed by the client thread.
 */
ssize_t cmd_list_tracepoints(enum lttng_domain_type domain,
		struct lttng_event **events)
{
	int ret;
	ssize_t nb_events = 0;

	switch (domain) {
	case LTTNG_DOMAIN_KERNEL:
		nb_events = kernel_list_events(kernel_tracer_fd, events);
		if (nb_events < 0) {
			ret = LTTNG_ERR_KERN_LIST_FAIL;
			goto error;
		}
		break;
	case LTTNG_DOMAIN_UST:
		nb_events = ust_app_list_events(events);
		if (nb_events < 0) {
			ret = LTTNG_ERR_UST_LIST_FAIL;
			goto error;
		}
		break;
	case LTTNG_DOMAIN_LOG4J:
	case LTTNG_DOMAIN_JUL:
	case LTTNG_DOMAIN_PYTHON:
		nb_events = agent_list_events(events, domain);
		if (nb_events < 0) {
			ret = LTTNG_ERR_UST_LIST_FAIL;
			goto error;
		}
		break;
	default:
		ret = LTTNG_ERR_UND;
		goto error;
	}

	return nb_events;

error:
	/* Return negative value to differentiate return code */
	return -ret;
}

/*
 * Command LTTNG_LIST_TRACEPOINT_FIELDS processed by the client thread.
 */
ssize_t cmd_list_tracepoint_fields(enum lttng_domain_type domain,
		struct lttng_event_field **fields)
{
	int ret;
	ssize_t nb_fields = 0;

	switch (domain) {
	case LTTNG_DOMAIN_UST:
		nb_fields = ust_app_list_event_fields(fields);
		if (nb_fields < 0) {
			ret = LTTNG_ERR_UST_LIST_FAIL;
			goto error;
		}
		break;
	case LTTNG_DOMAIN_KERNEL:
	default:	/* fall-through */
		ret = LTTNG_ERR_UND;
		goto error;
	}

	return nb_fields;

error:
	/* Return negative value to differentiate return code */
	return -ret;
}

ssize_t cmd_list_syscalls(struct lttng_event **events)
{
	return syscall_table_list(events);
}

/*
 * Command LTTNG_LIST_TRACKER_PIDS processed by the client thread.
 *
 * Called with session lock held.
 */
ssize_t cmd_list_tracker_pids(struct ltt_session *session,
		enum lttng_domain_type domain, int32_t **pids)
{
	int ret;
	ssize_t nr_pids = 0;

	switch (domain) {
	case LTTNG_DOMAIN_KERNEL:
	{
		struct ltt_kernel_session *ksess;

		ksess = session->kernel_session;
		nr_pids = kernel_list_tracker_pids(ksess, pids);
		if (nr_pids < 0) {
			ret = LTTNG_ERR_KERN_LIST_FAIL;
			goto error;
		}
		break;
	}
	case LTTNG_DOMAIN_UST:
	{
		struct ltt_ust_session *usess;

		usess = session->ust_session;
		nr_pids = trace_ust_list_tracker_pids(usess, pids);
		if (nr_pids < 0) {
			ret = LTTNG_ERR_UST_LIST_FAIL;
			goto error;
		}
		break;
	}
	case LTTNG_DOMAIN_LOG4J:
	case LTTNG_DOMAIN_JUL:
	case LTTNG_DOMAIN_PYTHON:
	default:
		ret = LTTNG_ERR_UND;
		goto error;
	}

	return nr_pids;

error:
	/* Return negative value to differentiate return code */
	return -ret;
}

static
int domain_mkdir(const struct consumer_output *output,
		const struct ltt_session *session,
		uid_t uid, gid_t gid)
{
	struct consumer_socket *socket;
	struct lttng_ht_iter iter;
	int ret;
	char *path = NULL;

	if (!output || !output->socks) {
		ERR("No consumer output found");
		ret = -1;
		goto end;
	}

	path = zmalloc(LTTNG_PATH_MAX * sizeof(char));
	if (!path) {
		ERR("Cannot allocate mkdir path");
		ret = -1;
		goto end;
	}

	ret = snprintf(path, LTTNG_PATH_MAX, "%s%s%s",
			session_get_base_path(session),
			output->chunk_path, output->subdir);
	if (ret < 0 || ret >= LTTNG_PATH_MAX) {
		ERR("Format path");
		ret = -1;
		goto end;
	}

	DBG("Domain mkdir %s for session %" PRIu64, path, session->id);
	rcu_read_lock();
	/*
	 * We have to iterate to find a socket, but we only need to send the
	 * rename command to one consumer, so we break after the first one.
	 */
	cds_lfht_for_each_entry(output->socks->ht, &iter.iter, socket, node.node) {
		pthread_mutex_lock(socket->lock);
		ret = consumer_mkdir(socket, session->id, output, path, uid, gid);
		pthread_mutex_unlock(socket->lock);
		if (ret) {
			ERR("Consumer mkdir");
			ret = -1;
			goto end_unlock;
		}
		break;
	}

	ret = 0;

end_unlock:
	rcu_read_unlock();
end:
	free(path);
	return ret;
}

static
int session_mkdir(const struct ltt_session *session)
{
	int ret;
	struct consumer_output *output;
	uid_t uid;
	gid_t gid;

	/*
	 * Unsupported feature in lttng-relayd before 2.11, not an error since it
	 * is only needed for session rotation and the user will get an error
	 * on rotate.
	 */
	if (session->consumer->type == CONSUMER_DST_NET &&
			session->consumer->relay_major_version == 2 &&
			session->consumer->relay_minor_version < 11) {
		ret = 0;
		goto end;
	}

	if (session->kernel_session) {
		output = session->kernel_session->consumer;
		uid = session->kernel_session->uid;
		gid = session->kernel_session->gid;
		ret = domain_mkdir(output, session, uid, gid);
		if (ret) {
			ERR("Mkdir kernel");
			goto end;
		}
	}

	if (session->ust_session) {
		output = session->ust_session->consumer;
		uid = session->ust_session->uid;
		gid = session->ust_session->gid;
		ret = domain_mkdir(output, session, uid, gid);
		if (ret) {
			ERR("Mkdir UST");
			goto end;
		}
	}

	ret = 0;

end:
	return ret;
}

/*
 * Command LTTNG_START_TRACE processed by the client thread.
 *
 * Called with session mutex held.
 */
int cmd_start_trace(struct ltt_session *session)
{
	int ret;
	unsigned long nb_chan = 0;
	struct ltt_kernel_session *ksession;
	struct ltt_ust_session *usess;

	assert(session);

	/* Ease our life a bit ;) */
	ksession = session->kernel_session;
	usess = session->ust_session;

	/* Is the session already started? */
	if (session->active) {
		ret = LTTNG_ERR_TRACE_ALREADY_STARTED;
		goto error;
	}

	/*
	 * Starting a session without channel is useless since after that it's not
	 * possible to enable channel thus inform the client.
	 */
	if (usess && usess->domain_global.channels) {
		nb_chan += lttng_ht_get_count(usess->domain_global.channels);
	}
	if (ksession) {
		nb_chan += ksession->channel_count;
	}
	if (!nb_chan) {
		ret = LTTNG_ERR_NO_CHANNEL;
		goto error;
	}

	/*
	 * Record the timestamp of the first time the session is started for
	 * an eventual session rotation call.
	 */
	if (!session->has_been_started) {
		session->current_chunk_start_ts = time(NULL);
		if (session->current_chunk_start_ts == (time_t) -1) {
			PERROR("Failed to retrieve the \"%s\" session's start time",
					session->name);
			ret = LTTNG_ERR_FATAL;
			goto error;
		}
		if (!session->snapshot_mode && session->output_traces) {
			ret = session_mkdir(session);
			if (ret) {
				ERR("Failed to create the session directories");
				ret = LTTNG_ERR_CREATE_DIR_FAIL;
				goto error;
			}
		}
	}

	/* Kernel tracing */
	if (ksession != NULL) {
		DBG("Start kernel tracing session %s", session->name);
		ret = start_kernel_session(ksession, kernel_tracer_fd);
		if (ret != LTTNG_OK) {
			goto error;
		}
	}

	/* Flag session that trace should start automatically */
	if (usess) {
		/*
		 * Even though the start trace might fail, flag this session active so
		 * other application coming in are started by default.
		 */
		usess->active = 1;

		ret = ust_app_start_trace_all(usess);
		if (ret < 0) {
			ret = LTTNG_ERR_UST_START_FAIL;
			goto error;
		}
	}

	/* Flag this after a successful start. */
	session->has_been_started = 1;
	session->active = 1;

	/*
	 * Clear the flag that indicates that a rotation was done while the
	 * session was stopped.
	 */
	session->rotated_after_last_stop = false;

	if (session->rotate_timer_period) {
		ret = sessiond_rotate_timer_start(session,
				session->rotate_timer_period);
		if (ret < 0) {
			ERR("Failed to enable rotate timer");
			ret = LTTNG_ERR_UNK;
			goto error;
		}
	}

	ret = LTTNG_OK;

error:
	return ret;
}

static
int rename_active_chunk(struct ltt_session *session)
{
	int ret;

	session->current_archive_id++;

	/*
	 * The currently active tracing path is now the folder we
	 * want to rename.
	 */
	ret = lttng_strncpy(session->rotation_chunk.current_rotate_path,
			session->rotation_chunk.active_tracing_path,
			sizeof(session->rotation_chunk.current_rotate_path));
	if (ret) {
		ERR("Failed to copy active tracing path");
		goto end;
	}

	ret = rename_complete_chunk(session, time(NULL));
	if (ret < 0) {
		ERR("Failed to rename current rotate path");
		goto end;
	}

	/*
	 * We just renamed, the folder, we didn't do an actual rotation, so
	 * the active tracing path is now the renamed folder and we have to
	 * restore the rotate count.
	 */
	ret = lttng_strncpy(session->rotation_chunk.active_tracing_path,
			session->rotation_chunk.current_rotate_path,
			sizeof(session->rotation_chunk.active_tracing_path));
	if (ret) {
		ERR("Failed to rename active session chunk tracing path");
		goto end;
	}
end:
	session->current_archive_id--;
	return ret;
}

/*
 * Command LTTNG_STOP_TRACE processed by the client thread.
 */
int cmd_stop_trace(struct ltt_session *session)
{
	int ret;
	struct ltt_kernel_channel *kchan;
	struct ltt_kernel_session *ksession;
	struct ltt_ust_session *usess;
	bool error_occured = false;

	assert(session);

	DBG("Begin stop session %s (id %" PRIu64 ")", session->name, session->id);
	/* Short cut */
	ksession = session->kernel_session;
	usess = session->ust_session;

	/* Session is not active. Skip everythong and inform the client. */
	if (!session->active) {
		ret = LTTNG_ERR_TRACE_ALREADY_STOPPED;
		goto error;
	}

	if (session->rotate_relay_pending_timer_enabled) {
		sessiond_timer_rotate_pending_stop(session);
	}

	if (session->rotate_timer_enabled) {
		sessiond_rotate_timer_stop(session);
	}

	if (session->current_archive_id > 0 && !session->rotate_pending) {
		ret = rename_active_chunk(session);
		if (ret) {
			/*
			 * This error should not prevent the user from stopping
			 * the session. However, it will be reported at the end.
			 */
			error_occured = true;
		}
	}

	/* Kernel tracer */
	if (ksession && ksession->active) {
		DBG("Stop kernel tracing");

		ret = kernel_stop_session(ksession);
		if (ret < 0) {
			ret = LTTNG_ERR_KERN_STOP_FAIL;
			goto error;
		}

		kernel_wait_quiescent(kernel_tracer_fd);

		/* Flush metadata after stopping (if exists) */
		if (ksession->metadata_stream_fd >= 0) {
			ret = kernel_metadata_flush_buffer(ksession->metadata_stream_fd);
			if (ret < 0) {
				ERR("Kernel metadata flush failed");
			}
		}

		/* Flush all buffers after stopping */
		cds_list_for_each_entry(kchan, &ksession->channel_list.head, list) {
			ret = kernel_flush_buffer(kchan);
			if (ret < 0) {
				ERR("Kernel flush buffer error");
			}
		}

		ksession->active = 0;
		DBG("Kernel session stopped %s (id %" PRIu64 ")", session->name,
				session->id);
	}

	if (usess && usess->active) {
		/*
		 * Even though the stop trace might fail, flag this session inactive so
		 * other application coming in are not started by default.
		 */
		usess->active = 0;

		ret = ust_app_stop_trace_all(usess);
		if (ret < 0) {
			ret = LTTNG_ERR_UST_STOP_FAIL;
			goto error;
		}
	}

	/* Flag inactive after a successful stop. */
	session->active = 0;
	ret = !error_occured ? LTTNG_OK : LTTNG_ERR_UNK;

error:
	return ret;
}

/*
 * Command LTTNG_SET_CONSUMER_URI processed by the client thread.
 */
int cmd_set_consumer_uri(struct ltt_session *session, size_t nb_uri,
		struct lttng_uri *uris)
{
	int ret, i;
	struct ltt_kernel_session *ksess = session->kernel_session;
	struct ltt_ust_session *usess = session->ust_session;

	assert(session);
	assert(uris);
	assert(nb_uri > 0);

	/* Can't set consumer URI if the session is active. */
	if (session->active) {
		ret = LTTNG_ERR_TRACE_ALREADY_STARTED;
		goto error;
	}

	/* Set the "global" consumer URIs */
	for (i = 0; i < nb_uri; i++) {
		ret = add_uri_to_consumer(session->consumer,
				&uris[i], 0, session->name);
		if (ret != LTTNG_OK) {
			goto error;
		}
	}

	/* Set UST session URIs */
	if (session->ust_session) {
		for (i = 0; i < nb_uri; i++) {
			ret = add_uri_to_consumer(
					session->ust_session->consumer,
					&uris[i], LTTNG_DOMAIN_UST,
					session->name);
			if (ret != LTTNG_OK) {
				goto error;
			}
		}
	}

	/* Set kernel session URIs */
	if (session->kernel_session) {
		for (i = 0; i < nb_uri; i++) {
			ret = add_uri_to_consumer(
					session->kernel_session->consumer,
					&uris[i], LTTNG_DOMAIN_KERNEL,
					session->name);
			if (ret != LTTNG_OK) {
				goto error;
			}
		}
	}

	/*
	 * Make sure to set the session in output mode after we set URI since a
	 * session can be created without URL (thus flagged in no output mode).
	 */
	session->output_traces = 1;
	if (ksess) {
		ksess->output_traces = 1;
	}

	if (usess) {
		usess->output_traces = 1;
	}

	/* All good! */
	ret = LTTNG_OK;

error:
	return ret;
}

/*
 * Command LTTNG_CREATE_SESSION processed by the client thread.
 */
int cmd_create_session_uri(char *name, struct lttng_uri *uris,
		size_t nb_uri, lttng_sock_cred *creds, unsigned int live_timer)
{
	int ret;
	struct ltt_session *session;

	assert(name);
	assert(creds);

	/*
	 * Verify if the session already exist
	 *
	 * XXX: There is no need for the session lock list here since the caller
	 * (process_client_msg) is holding it. We might want to change that so a
	 * single command does not lock the entire session list.
	 */
	session = session_find_by_name(name);
	if (session != NULL) {
		ret = LTTNG_ERR_EXIST_SESS;
		goto find_error;
	}

	/* Create tracing session in the registry */
	ret = session_create(name, LTTNG_SOCK_GET_UID_CRED(creds),
			LTTNG_SOCK_GET_GID_CRED(creds));
	if (ret != LTTNG_OK) {
		goto session_error;
	}

	/*
	 * Get the newly created session pointer back
	 *
	 * XXX: There is no need for the session lock list here since the caller
	 * (process_client_msg) is holding it. We might want to change that so a
	 * single command does not lock the entire session list.
	 */
	session = session_find_by_name(name);
	assert(session);

	session->live_timer = live_timer;
	/* Create default consumer output for the session not yet created. */
	session->consumer = consumer_create_output(CONSUMER_DST_LOCAL);
	if (session->consumer == NULL) {
		ret = LTTNG_ERR_FATAL;
		goto consumer_error;
	}

	if (uris) {
		ret = cmd_set_consumer_uri(session, nb_uri, uris);
		if (ret != LTTNG_OK) {
			goto consumer_error;
		}
		session->output_traces = 1;
	} else {
		session->output_traces = 0;
		DBG2("Session %s created with no output", session->name);
	}

	session->consumer->enabled = 1;

	return LTTNG_OK;

consumer_error:
	session_destroy(session);
session_error:
find_error:
	return ret;
}

/*
 * Command LTTNG_CREATE_SESSION_SNAPSHOT processed by the client thread.
 */
int cmd_create_session_snapshot(char *name, struct lttng_uri *uris,
		size_t nb_uri, lttng_sock_cred *creds)
{
	int ret;
	struct ltt_session *session;
	struct snapshot_output *new_output = NULL;

	assert(name);
	assert(creds);

	/*
	 * Create session in no output mode with URIs set to NULL. The uris we've
	 * received are for a default snapshot output if one.
	 */
	ret = cmd_create_session_uri(name, NULL, 0, creds, 0);
	if (ret != LTTNG_OK) {
		goto error;
	}

	/* Get the newly created session pointer back. This should NEVER fail. */
	session = session_find_by_name(name);
	assert(session);

	/* Flag session for snapshot mode. */
	session->snapshot_mode = 1;

	/* Skip snapshot output creation if no URI is given. */
	if (nb_uri == 0) {
		goto end;
	}

	new_output = snapshot_output_alloc();
	if (!new_output) {
		ret = LTTNG_ERR_NOMEM;
		goto error_snapshot_alloc;
	}

	ret = snapshot_output_init_with_uri(DEFAULT_SNAPSHOT_MAX_SIZE, NULL,
			uris, nb_uri, session->consumer, new_output, &session->snapshot);
	if (ret < 0) {
		if (ret == -ENOMEM) {
			ret = LTTNG_ERR_NOMEM;
		} else {
			ret = LTTNG_ERR_INVALID;
		}
		goto error_snapshot;
	}

	rcu_read_lock();
	snapshot_add_output(&session->snapshot, new_output);
	rcu_read_unlock();

end:
	return LTTNG_OK;

error_snapshot:
	snapshot_output_destroy(new_output);
error_snapshot_alloc:
	session_destroy(session);
error:
	return ret;
}

/*
 * Command LTTNG_DESTROY_SESSION processed by the client thread.
 *
 * Called with session lock held.
 */
int cmd_destroy_session(struct ltt_session *session, int wpipe,
		struct notification_thread_handle *notification_thread_handle)
{
	int ret;
	struct ltt_ust_session *usess;
	struct ltt_kernel_session *ksess;

	/* Safety net */
	assert(session);

	usess = session->ust_session;
	ksess = session->kernel_session;

	DBG("Begin destroy session %s (id %" PRIu64 ")", session->name, session->id);

	if (session->rotate_relay_pending_timer_enabled) {
		sessiond_timer_rotate_pending_stop(session);
	}

	if (session->rotate_timer_enabled) {
		sessiond_rotate_timer_stop(session);
	}

	if (session->rotate_size) {
		unsubscribe_session_consumed_size_rotation(session, notification_thread_handle);
		session->rotate_size = 0;
	}

	/*
	 * The rename of the current chunk is performed at stop, but if we rotated
	 * the session after the previous stop command, we need to rename the
	 * new (and empty) chunk that was started in between.
	 */
	if (session->rotated_after_last_stop) {
		rename_active_chunk(session);
	}

	/* Clean kernel session teardown */
	kernel_destroy_session(ksess);

	/* UST session teardown */
	if (usess) {
		/* Close any relayd session */
		consumer_output_send_destroy_relayd(usess->consumer);

		/* Destroy every UST application related to this session. */
		ret = ust_app_destroy_trace_all(usess);
		if (ret) {
			ERR("Error in ust_app_destroy_trace_all");
		}

		/* Clean up the rest. */
		trace_ust_destroy_session(usess);
	}

	/*
	 * Must notify the kernel thread here to update it's poll set in order to
	 * remove the channel(s)' fd just destroyed.
	 */
	ret = notify_thread_pipe(wpipe);
	if (ret < 0) {
		PERROR("write kernel poll pipe");
	}

	if (session->shm_path[0]) {
		/*
		 * When a session is created with an explicit shm_path,
		 * the consumer daemon will create its shared memory files
		 * at that location and will *not* unlink them. This is normal
		 * as the intention of that feature is to make it possible
		 * to retrieve the content of those files should a crash occur.
		 *
		 * To ensure the content of those files can be used, the
		 * sessiond daemon will replicate the content of the metadata
		 * cache in a metadata file.
		 *
		 * On clean-up, it is expected that the consumer daemon will
		 * unlink the shared memory files and that the session daemon
		 * will unlink the metadata file. Then, the session's directory
		 * in the shm path can be removed.
		 *
		 * Unfortunately, a flaw in the design of the sessiond's and
		 * consumerd's tear down of channels makes it impossible to
		 * determine when the sessiond _and_ the consumerd have both
		 * destroyed their representation of a channel. For one, the
		 * unlinking, close, and rmdir happen in deferred 'call_rcu'
		 * callbacks in both daemons.
		 *
		 * However, it is also impossible for the sessiond to know when
		 * the consumer daemon is done destroying its channel(s) since
		 * it occurs as a reaction to the closing of the channel's file
		 * descriptor. There is no resulting communication initiated
		 * from the consumerd to the sessiond to confirm that the
		 * operation is completed (and was successful).
		 *
		 * Until this is all fixed, the session daemon checks for the
		 * removal of the session's shm path which makes it possible
		 * to safely advertise a session as having been destroyed.
		 *
		 * Prior to this fix, it was not possible to reliably save
		 * a session making use of the --shm-path option, destroy it,
		 * and load it again. This is because the creation of the
		 * session would fail upon seeing the session's shm path
		 * already in existence.
		 *
		 * Note that none of the error paths in the check for the
		 * directory's existence return an error. This is normal
		 * as there isn't much that can be done. The session will
		 * be destroyed properly, except that we can't offer the
		 * guarantee that the same session can be re-created.
		 */
		current_completion_handler = &destroy_completion_handler.handler;
		ret = lttng_strncpy(destroy_completion_handler.shm_path,
				session->shm_path,
				sizeof(destroy_completion_handler.shm_path));
		assert(!ret);
	}
	ret = session_destroy(session);

	return ret;
}

/*
 * Command LTTNG_REGISTER_CONSUMER processed by the client thread.
 */
int cmd_register_consumer(struct ltt_session *session,
		enum lttng_domain_type domain, const char *sock_path,
		struct consumer_data *cdata)
{
	int ret, sock;
	struct consumer_socket *socket = NULL;

	assert(session);
	assert(cdata);
	assert(sock_path);

	switch (domain) {
	case LTTNG_DOMAIN_KERNEL:
	{
		struct ltt_kernel_session *ksess = session->kernel_session;

		assert(ksess);

		/* Can't register a consumer if there is already one */
		if (ksess->consumer_fds_sent != 0) {
			ret = LTTNG_ERR_KERN_CONSUMER_FAIL;
			goto error;
		}

		sock = lttcomm_connect_unix_sock(sock_path);
		if (sock < 0) {
			ret = LTTNG_ERR_CONNECT_FAIL;
			goto error;
		}
		cdata->cmd_sock = sock;

		socket = consumer_allocate_socket(&cdata->cmd_sock);
		if (socket == NULL) {
			ret = close(sock);
			if (ret < 0) {
				PERROR("close register consumer");
			}
			cdata->cmd_sock = -1;
			ret = LTTNG_ERR_FATAL;
			goto error;
		}

		socket->lock = zmalloc(sizeof(pthread_mutex_t));
		if (socket->lock == NULL) {
			PERROR("zmalloc pthread mutex");
			ret = LTTNG_ERR_FATAL;
			goto error;
		}
		pthread_mutex_init(socket->lock, NULL);
		socket->registered = 1;

		rcu_read_lock();
		consumer_add_socket(socket, ksess->consumer);
		rcu_read_unlock();

		pthread_mutex_lock(&cdata->pid_mutex);
		cdata->pid = -1;
		pthread_mutex_unlock(&cdata->pid_mutex);

		break;
	}
	default:
		/* TODO: Userspace tracing */
		ret = LTTNG_ERR_UND;
		goto error;
	}

	return LTTNG_OK;

error:
	if (socket) {
		consumer_destroy_socket(socket);
	}
	return ret;
}

/*
 * Command LTTNG_LIST_DOMAINS processed by the client thread.
 */
ssize_t cmd_list_domains(struct ltt_session *session,
		struct lttng_domain **domains)
{
	int ret, index = 0;
	ssize_t nb_dom = 0;
	struct agent *agt;
	struct lttng_ht_iter iter;

	if (session->kernel_session != NULL) {
		DBG3("Listing domains found kernel domain");
		nb_dom++;
	}

	if (session->ust_session != NULL) {
		DBG3("Listing domains found UST global domain");
		nb_dom++;

		rcu_read_lock();
		cds_lfht_for_each_entry(session->ust_session->agents->ht, &iter.iter,
				agt, node.node) {
			if (agt->being_used) {
				nb_dom++;
			}
		}
		rcu_read_unlock();
	}

	if (!nb_dom) {
		goto end;
	}

	*domains = zmalloc(nb_dom * sizeof(struct lttng_domain));
	if (*domains == NULL) {
		ret = LTTNG_ERR_FATAL;
		goto error;
	}

	if (session->kernel_session != NULL) {
		(*domains)[index].type = LTTNG_DOMAIN_KERNEL;

		/* Kernel session buffer type is always GLOBAL */
		(*domains)[index].buf_type = LTTNG_BUFFER_GLOBAL;

		index++;
	}

	if (session->ust_session != NULL) {
		(*domains)[index].type = LTTNG_DOMAIN_UST;
		(*domains)[index].buf_type = session->ust_session->buffer_type;
		index++;

		rcu_read_lock();
		cds_lfht_for_each_entry(session->ust_session->agents->ht, &iter.iter,
				agt, node.node) {
			if (agt->being_used) {
				(*domains)[index].type = agt->domain;
				(*domains)[index].buf_type = session->ust_session->buffer_type;
				index++;
			}
		}
		rcu_read_unlock();
	}
end:
	return nb_dom;

error:
	/* Return negative value to differentiate return code */
	return -ret;
}


/*
 * Command LTTNG_LIST_CHANNELS processed by the client thread.
 */
ssize_t cmd_list_channels(enum lttng_domain_type domain,
		struct ltt_session *session, struct lttng_channel **channels)
{
	ssize_t nb_chan = 0, payload_size = 0, ret;

	switch (domain) {
	case LTTNG_DOMAIN_KERNEL:
		if (session->kernel_session != NULL) {
			nb_chan = session->kernel_session->channel_count;
		}
		DBG3("Number of kernel channels %zd", nb_chan);
		if (nb_chan <= 0) {
			ret = -LTTNG_ERR_KERN_CHAN_NOT_FOUND;
			goto end;
		}
		break;
	case LTTNG_DOMAIN_UST:
		if (session->ust_session != NULL) {
			rcu_read_lock();
			nb_chan = lttng_ht_get_count(
				session->ust_session->domain_global.channels);
			rcu_read_unlock();
		}
		DBG3("Number of UST global channels %zd", nb_chan);
		if (nb_chan < 0) {
			ret = -LTTNG_ERR_UST_CHAN_NOT_FOUND;
			goto end;
		}
		break;
	default:
		ret = -LTTNG_ERR_UND;
		goto end;
	}

	if (nb_chan > 0) {
		const size_t channel_size = sizeof(struct lttng_channel) +
			sizeof(struct lttng_channel_extended);
		struct lttng_channel_extended *channel_exts;

		payload_size = nb_chan * channel_size;
		*channels = zmalloc(payload_size);
		if (*channels == NULL) {
			ret = -LTTNG_ERR_FATAL;
			goto end;
		}

		channel_exts = ((void *) *channels) +
				(nb_chan * sizeof(struct lttng_channel));
		ret = list_lttng_channels(domain, session, *channels, channel_exts);
		if (ret != LTTNG_OK) {
			free(*channels);
			*channels = NULL;
			goto end;
		}
	} else {
		*channels = NULL;
	}

	ret = payload_size;
end:
	return ret;
}

/*
 * Command LTTNG_LIST_EVENTS processed by the client thread.
 */
ssize_t cmd_list_events(enum lttng_domain_type domain,
		struct ltt_session *session, char *channel_name,
		struct lttng_event **events, size_t *total_size)
{
	int ret = 0;
	ssize_t nb_event = 0;

	switch (domain) {
	case LTTNG_DOMAIN_KERNEL:
		if (session->kernel_session != NULL) {
			nb_event = list_lttng_kernel_events(channel_name,
					session->kernel_session, events,
					total_size);
		}
		break;
	case LTTNG_DOMAIN_UST:
	{
		if (session->ust_session != NULL) {
			nb_event = list_lttng_ust_global_events(channel_name,
					&session->ust_session->domain_global, events,
					total_size);
		}
		break;
	}
	case LTTNG_DOMAIN_LOG4J:
	case LTTNG_DOMAIN_JUL:
	case LTTNG_DOMAIN_PYTHON:
		if (session->ust_session) {
			struct lttng_ht_iter iter;
			struct agent *agt;

			rcu_read_lock();
			cds_lfht_for_each_entry(session->ust_session->agents->ht,
					&iter.iter, agt, node.node) {
				if (agt->domain == domain) {
					nb_event = list_lttng_agent_events(
							agt, events,
							total_size);
					break;
				}
			}
			rcu_read_unlock();
		}
		break;
	default:
		ret = LTTNG_ERR_UND;
		goto error;
	}

	return nb_event;

error:
	/* Return negative value to differentiate return code */
	return -ret;
}

/*
 * Using the session list, filled a lttng_session array to send back to the
 * client for session listing.
 *
 * The session list lock MUST be acquired before calling this function. Use
 * session_lock_list() and session_unlock_list().
 */
void cmd_list_lttng_sessions(struct lttng_session *sessions, uid_t uid,
		gid_t gid)
{
	int ret;
	unsigned int i = 0;
	struct ltt_session *session;
	struct ltt_session_list *list = session_get_list();

	DBG("Getting all available session for UID %d GID %d",
			uid, gid);
	/*
	 * Iterate over session list and append data after the control struct in
	 * the buffer.
	 */
	cds_list_for_each_entry(session, &list->head, list) {
		/*
		 * Only list the sessions the user can control.
		 */
		if (!session_access_ok(session, uid, gid)) {
			continue;
		}

		struct ltt_kernel_session *ksess = session->kernel_session;
		struct ltt_ust_session *usess = session->ust_session;

		if (session->consumer->type == CONSUMER_DST_NET ||
				(ksess && ksess->consumer->type == CONSUMER_DST_NET) ||
				(usess && usess->consumer->type == CONSUMER_DST_NET)) {
			ret = build_network_session_path(sessions[i].path,
					sizeof(sessions[i].path), session);
		} else {
			ret = snprintf(sessions[i].path, sizeof(sessions[i].path), "%s",
					session->consumer->dst.session_root_path);
		}
		if (ret < 0) {
			PERROR("snprintf session path");
			continue;
		}

		strncpy(sessions[i].name, session->name, NAME_MAX);
		sessions[i].name[NAME_MAX - 1] = '\0';
		sessions[i].enabled = session->active;
		sessions[i].snapshot_mode = session->snapshot_mode;
		sessions[i].live_timer_interval = session->live_timer;
		i++;
	}
}

/*
 * Command LTTNG_DATA_PENDING returning 0 if the data is NOT pending meaning
 * ready for trace analysis (or any kind of reader) or else 1 for pending data.
 */
int cmd_data_pending(struct ltt_session *session)
{
	int ret;
	struct ltt_kernel_session *ksess = session->kernel_session;
	struct ltt_ust_session *usess = session->ust_session;

	assert(session);

	DBG("Data pending for session %s", session->name);

	/* Session MUST be stopped to ask for data availability. */
	if (session->active) {
		ret = LTTNG_ERR_SESSION_STARTED;
		goto error;
	} else {
		/*
		 * If stopped, just make sure we've started before else the above call
		 * will always send that there is data pending.
		 *
		 * The consumer assumes that when the data pending command is received,
		 * the trace has been started before or else no output data is written
		 * by the streams which is a condition for data pending. So, this is
		 * *VERY* important that we don't ask the consumer before a start
		 * trace.
		 */
		if (!session->has_been_started) {
			ret = 0;
			goto error;
		}
	}

	/*
	 * A rotation is still pending, we have to wait.
	 */
	if (session->rotate_pending) {
		DBG("Rotate still pending for session %s", session->name);
		ret = 1;
		goto error;
	}

	if (ksess && ksess->consumer) {
		ret = consumer_is_data_pending(ksess->id, ksess->consumer);
		if (ret == 1) {
			/* Data is still being extracted for the kernel. */
			goto error;
		}
	}

	if (usess && usess->consumer) {
		ret = consumer_is_data_pending(usess->id, usess->consumer);
		if (ret == 1) {
			/* Data is still being extracted for the kernel. */
			goto error;
		}
	}

	/* Data is ready to be read by a viewer */
	ret = 0;

error:
	return ret;
}

/*
 * Command LTTNG_SNAPSHOT_ADD_OUTPUT from the lttng ctl library.
 *
 * Return LTTNG_OK on success or else a LTTNG_ERR code.
 */
int cmd_snapshot_add_output(struct ltt_session *session,
		struct lttng_snapshot_output *output, uint32_t *id)
{
	int ret;
	struct snapshot_output *new_output;

	assert(session);
	assert(output);

	DBG("Cmd snapshot add output for session %s", session->name);

	/*
	 * Can't create an output if the session is not set in no-output mode.
	 */
	if (session->output_traces) {
		ret = LTTNG_ERR_NOT_SNAPSHOT_SESSION;
		goto error;
	}

	/* Only one output is allowed until we have the "tee" feature. */
	if (session->snapshot.nb_output == 1) {
		ret = LTTNG_ERR_SNAPSHOT_OUTPUT_EXIST;
		goto error;
	}

	new_output = snapshot_output_alloc();
	if (!new_output) {
		ret = LTTNG_ERR_NOMEM;
		goto error;
	}

	ret = snapshot_output_init(output->max_size, output->name,
			output->ctrl_url, output->data_url, session->consumer, new_output,
			&session->snapshot);
	if (ret < 0) {
		if (ret == -ENOMEM) {
			ret = LTTNG_ERR_NOMEM;
		} else {
			ret = LTTNG_ERR_INVALID;
		}
		goto free_error;
	}

	rcu_read_lock();
	snapshot_add_output(&session->snapshot, new_output);
	if (id) {
		*id = new_output->id;
	}
	rcu_read_unlock();

	return LTTNG_OK;

free_error:
	snapshot_output_destroy(new_output);
error:
	return ret;
}

/*
 * Command LTTNG_SNAPSHOT_DEL_OUTPUT from lib lttng ctl.
 *
 * Return LTTNG_OK on success or else a LTTNG_ERR code.
 */
int cmd_snapshot_del_output(struct ltt_session *session,
		struct lttng_snapshot_output *output)
{
	int ret;
	struct snapshot_output *sout = NULL;

	assert(session);
	assert(output);

	rcu_read_lock();

	/*
	 * Permission denied to create an output if the session is not
	 * set in no output mode.
	 */
	if (session->output_traces) {
		ret = LTTNG_ERR_NOT_SNAPSHOT_SESSION;
		goto error;
	}

	if (output->id) {
		DBG("Cmd snapshot del output id %" PRIu32 " for session %s", output->id,
				session->name);
		sout = snapshot_find_output_by_id(output->id, &session->snapshot);
	} else if (*output->name != '\0') {
		DBG("Cmd snapshot del output name %s for session %s", output->name,
				session->name);
		sout = snapshot_find_output_by_name(output->name, &session->snapshot);
	}
	if (!sout) {
		ret = LTTNG_ERR_INVALID;
		goto error;
	}

	snapshot_delete_output(&session->snapshot, sout);
	snapshot_output_destroy(sout);
	ret = LTTNG_OK;

error:
	rcu_read_unlock();
	return ret;
}

/*
 * Command LTTNG_SNAPSHOT_LIST_OUTPUT from lib lttng ctl.
 *
 * If no output is available, outputs is untouched and 0 is returned.
 *
 * Return the size of the newly allocated outputs or a negative LTTNG_ERR code.
 */
ssize_t cmd_snapshot_list_outputs(struct ltt_session *session,
		struct lttng_snapshot_output **outputs)
{
	int ret, idx = 0;
	struct lttng_snapshot_output *list = NULL;
	struct lttng_ht_iter iter;
	struct snapshot_output *output;

	assert(session);
	assert(outputs);

	DBG("Cmd snapshot list outputs for session %s", session->name);

	/*
	 * Permission denied to create an output if the session is not
	 * set in no output mode.
	 */
	if (session->output_traces) {
		ret = -LTTNG_ERR_NOT_SNAPSHOT_SESSION;
		goto end;
	}

	if (session->snapshot.nb_output == 0) {
		ret = 0;
		goto end;
	}

	list = zmalloc(session->snapshot.nb_output * sizeof(*list));
	if (!list) {
		ret = -LTTNG_ERR_NOMEM;
		goto end;
	}

	/* Copy list from session to the new list object. */
	rcu_read_lock();
	cds_lfht_for_each_entry(session->snapshot.output_ht->ht, &iter.iter,
			output, node.node) {
		assert(output->consumer);
		list[idx].id = output->id;
		list[idx].max_size = output->max_size;
		if (lttng_strncpy(list[idx].name, output->name,
				sizeof(list[idx].name))) {
			ret = -LTTNG_ERR_INVALID;
			goto error;
		}
		if (output->consumer->type == CONSUMER_DST_LOCAL) {
			if (lttng_strncpy(list[idx].ctrl_url,
					output->consumer->dst.session_root_path,
					sizeof(list[idx].ctrl_url))) {
				ret = -LTTNG_ERR_INVALID;
				goto error;
			}
		} else {
			/* Control URI. */
			ret = uri_to_str_url(&output->consumer->dst.net.control,
					list[idx].ctrl_url, sizeof(list[idx].ctrl_url));
			if (ret < 0) {
				ret = -LTTNG_ERR_NOMEM;
				goto error;
			}

			/* Data URI. */
			ret = uri_to_str_url(&output->consumer->dst.net.data,
					list[idx].data_url, sizeof(list[idx].data_url));
			if (ret < 0) {
				ret = -LTTNG_ERR_NOMEM;
				goto error;
			}
		}
		idx++;
	}

	*outputs = list;
	list = NULL;
	ret = session->snapshot.nb_output;
error:
	rcu_read_unlock();
	free(list);
end:
	return ret;
}

/*
 * Check if we can regenerate the metadata for this session.
 * Only kernel, UST per-uid and non-live sessions are supported.
 *
 * Return 0 if the metadata can be generated, a LTTNG_ERR code otherwise.
 */
static
int check_regenerate_metadata_support(struct ltt_session *session)
{
	int ret;

	assert(session);

	if (session->live_timer != 0) {
		ret = LTTNG_ERR_LIVE_SESSION;
		goto end;
	}
	if (!session->active) {
		ret = LTTNG_ERR_SESSION_NOT_STARTED;
		goto end;
	}
	if (session->ust_session) {
		switch (session->ust_session->buffer_type) {
		case LTTNG_BUFFER_PER_UID:
			break;
		case LTTNG_BUFFER_PER_PID:
			ret = LTTNG_ERR_PER_PID_SESSION;
			goto end;
		default:
			assert(0);
			ret = LTTNG_ERR_UNK;
			goto end;
		}
	}
	if (session->consumer->type == CONSUMER_DST_NET &&
			session->consumer->relay_minor_version < 8) {
		ret = LTTNG_ERR_RELAYD_VERSION_FAIL;
		goto end;
	}
	ret = 0;

end:
	return ret;
}

static
int clear_metadata_file(int fd)
{
	int ret;
	off_t lseek_ret;

	lseek_ret = lseek(fd, 0, SEEK_SET);
	if (lseek_ret < 0) {
		PERROR("lseek");
		ret = -1;
		goto end;
	}

	ret = ftruncate(fd, 0);
	if (ret < 0) {
		PERROR("ftruncate");
		goto end;
	}

end:
	return ret;
}

static
int ust_regenerate_metadata(struct ltt_ust_session *usess)
{
	int ret = 0;
	struct buffer_reg_uid *uid_reg = NULL;
	struct buffer_reg_session *session_reg = NULL;

	rcu_read_lock();
	cds_list_for_each_entry(uid_reg, &usess->buffer_reg_uid_list, lnode) {
		struct ust_registry_session *registry;
		struct ust_registry_channel *chan;
		struct lttng_ht_iter iter_chan;

		session_reg = uid_reg->registry;
		registry = session_reg->reg.ust;

		pthread_mutex_lock(&registry->lock);
		registry->metadata_len_sent = 0;
		memset(registry->metadata, 0, registry->metadata_alloc_len);
		registry->metadata_len = 0;
		registry->metadata_version++;
		if (registry->metadata_fd > 0) {
			/* Clear the metadata file's content. */
			ret = clear_metadata_file(registry->metadata_fd);
			if (ret) {
				pthread_mutex_unlock(&registry->lock);
				goto end;
			}
		}

		ret = ust_metadata_session_statedump(registry, NULL,
				registry->major, registry->minor);
		if (ret) {
			pthread_mutex_unlock(&registry->lock);
			ERR("Failed to generate session metadata (err = %d)",
					ret);
			goto end;
		}
		cds_lfht_for_each_entry(registry->channels->ht, &iter_chan.iter,
				chan, node.node) {
			struct ust_registry_event *event;
			struct lttng_ht_iter iter_event;

			ret = ust_metadata_channel_statedump(registry, chan);
			if (ret) {
				pthread_mutex_unlock(&registry->lock);
				ERR("Failed to generate channel metadata "
						"(err = %d)", ret);
				goto end;
			}
			cds_lfht_for_each_entry(chan->ht->ht, &iter_event.iter,
					event, node.node) {
				ret = ust_metadata_event_statedump(registry,
						chan, event);
				if (ret) {
					pthread_mutex_unlock(&registry->lock);
					ERR("Failed to generate event metadata "
							"(err = %d)", ret);
					goto end;
				}
			}
		}
		pthread_mutex_unlock(&registry->lock);
	}

end:
	rcu_read_unlock();
	return ret;
}

/*
 * Command LTTNG_REGENERATE_METADATA from the lttng-ctl library.
 *
 * Ask the consumer to truncate the existing metadata file(s) and
 * then regenerate the metadata. Live and per-pid sessions are not
 * supported and return an error.
 *
 * Return 0 on success or else a LTTNG_ERR code.
 */
int cmd_regenerate_metadata(struct ltt_session *session)
{
	int ret;

	assert(session);

	ret = check_regenerate_metadata_support(session);
	if (ret) {
		goto end;
	}

	if (session->kernel_session) {
		ret = kernctl_session_regenerate_metadata(
				session->kernel_session->fd);
		if (ret < 0) {
			ERR("Failed to regenerate the kernel metadata");
			goto end;
		}
	}

	if (session->ust_session) {
		ret = ust_regenerate_metadata(session->ust_session);
		if (ret < 0) {
			ERR("Failed to regenerate the UST metadata");
			goto end;
		}
	}
	DBG("Cmd metadata regenerate for session %s", session->name);
	ret = LTTNG_OK;

end:
	return ret;
}

/*
 * Command LTTNG_REGENERATE_STATEDUMP from the lttng-ctl library.
 *
 * Ask the tracer to regenerate a new statedump.
 *
 * Return 0 on success or else a LTTNG_ERR code.
 */
int cmd_regenerate_statedump(struct ltt_session *session)
{
	int ret;

	assert(session);

	if (!session->active) {
		ret = LTTNG_ERR_SESSION_NOT_STARTED;
		goto end;
	}

	if (session->kernel_session) {
		ret = kernctl_session_regenerate_statedump(
				session->kernel_session->fd);
		/*
		 * Currently, the statedump in kernel can only fail if out
		 * of memory.
		 */
		if (ret < 0) {
			if (ret == -ENOMEM) {
				ret = LTTNG_ERR_REGEN_STATEDUMP_NOMEM;
			} else {
				ret = LTTNG_ERR_REGEN_STATEDUMP_FAIL;
			}
			ERR("Failed to regenerate the kernel statedump");
			goto end;
		}
	}

	if (session->ust_session) {
		ret = ust_app_regenerate_statedump_all(session->ust_session);
		/*
		 * Currently, the statedump in UST always returns 0.
		 */
		if (ret < 0) {
			ret = LTTNG_ERR_REGEN_STATEDUMP_FAIL;
			ERR("Failed to regenerate the UST statedump");
			goto end;
		}
	}
	DBG("Cmd regenerate statedump for session %s", session->name);
	ret = LTTNG_OK;

end:
	return ret;
}

int cmd_register_trigger(struct command_ctx *cmd_ctx, int sock,
		struct notification_thread_handle *notification_thread)
{
	int ret;
	size_t trigger_len;
	ssize_t sock_recv_len;
	struct lttng_trigger *trigger = NULL;
	struct lttng_buffer_view view;
	struct lttng_dynamic_buffer trigger_buffer;

	lttng_dynamic_buffer_init(&trigger_buffer);
	trigger_len = (size_t) cmd_ctx->lsm->u.trigger.length;
	ret = lttng_dynamic_buffer_set_size(&trigger_buffer, trigger_len);
	if (ret) {
		ret = LTTNG_ERR_NOMEM;
		goto end;
	}

	sock_recv_len = lttcomm_recv_unix_sock(sock, trigger_buffer.data,
			trigger_len);
	if (sock_recv_len < 0 || sock_recv_len != trigger_len) {
		ERR("Failed to receive \"register trigger\" command payload");
		/* TODO: should this be a new error enum ? */
		ret = LTTNG_ERR_INVALID_TRIGGER;
		goto end;
	}

	view = lttng_buffer_view_from_dynamic_buffer(&trigger_buffer, 0, -1);
	if (lttng_trigger_create_from_buffer(&view, &trigger) !=
			trigger_len) {
		ERR("Invalid trigger payload received in \"register trigger\" command");
		ret = LTTNG_ERR_INVALID_TRIGGER;
		goto end;
	}

	ret = notification_thread_command_register_trigger(notification_thread,
			trigger);
	/* Ownership of trigger was transferred. */
	trigger = NULL;
end:
	lttng_trigger_destroy(trigger);
	lttng_dynamic_buffer_reset(&trigger_buffer);
	return ret;
}

int cmd_unregister_trigger(struct command_ctx *cmd_ctx, int sock,
		struct notification_thread_handle *notification_thread)
{
	int ret;
	size_t trigger_len;
	ssize_t sock_recv_len;
	struct lttng_trigger *trigger = NULL;
	struct lttng_buffer_view view;
	struct lttng_dynamic_buffer trigger_buffer;

	lttng_dynamic_buffer_init(&trigger_buffer);
	trigger_len = (size_t) cmd_ctx->lsm->u.trigger.length;
	ret = lttng_dynamic_buffer_set_size(&trigger_buffer, trigger_len);
	if (ret) {
		ret = LTTNG_ERR_NOMEM;
		goto end;
	}

	sock_recv_len = lttcomm_recv_unix_sock(sock, trigger_buffer.data,
			trigger_len);
	if (sock_recv_len < 0 || sock_recv_len != trigger_len) {
		ERR("Failed to receive \"unregister trigger\" command payload");
		/* TODO: should this be a new error enum ? */
		ret = LTTNG_ERR_INVALID_TRIGGER;
		goto end;
	}

	view = lttng_buffer_view_from_dynamic_buffer(&trigger_buffer, 0, -1);
	if (lttng_trigger_create_from_buffer(&view, &trigger) !=
			trigger_len) {
		ERR("Invalid trigger payload received in \"unregister trigger\" command");
		ret = LTTNG_ERR_INVALID_TRIGGER;
		goto end;
	}

	ret = notification_thread_command_unregister_trigger(notification_thread,
			trigger);
end:
	lttng_trigger_destroy(trigger);
	lttng_dynamic_buffer_reset(&trigger_buffer);
	return ret;
}

/*
 * Send relayd sockets from snapshot output to consumer. Ignore request if the
 * snapshot output is *not* set with a remote destination.
 *
 * Return 0 on success or a LTTNG_ERR code.
 */
static int set_relayd_for_snapshot(struct consumer_output *consumer,
		struct snapshot_output *snap_output, struct ltt_session *session)
{
	int ret = LTTNG_OK;
	struct lttng_ht_iter iter;
	struct consumer_socket *socket;

	assert(consumer);
	assert(snap_output);
	assert(session);

	DBG2("Set relayd object from snapshot output");

	/* Ignore if snapshot consumer output is not network. */
	if (snap_output->consumer->type != CONSUMER_DST_NET) {
		goto error;
	}

	/*
	 * For each consumer socket, create and send the relayd object of the
	 * snapshot output.
	 */
	rcu_read_lock();
	cds_lfht_for_each_entry(snap_output->consumer->socks->ht, &iter.iter,
			socket, node.node) {
		pthread_mutex_lock(socket->lock);
		ret = send_consumer_relayd_sockets(0, session->id,
				snap_output->consumer, socket,
				session->name, session->hostname,
				session->live_timer);
		pthread_mutex_unlock(socket->lock);
		if (ret != LTTNG_OK) {
			rcu_read_unlock();
			goto error;
		}
	}
	rcu_read_unlock();

error:
	return ret;
}

/*
 * Record a kernel snapshot.
 *
 * Return LTTNG_OK on success or a LTTNG_ERR code.
 */
static int record_kernel_snapshot(struct ltt_kernel_session *ksess,
		struct snapshot_output *output, struct ltt_session *session,
		int wait, uint64_t nb_packets_per_stream)
{
	int ret;

	assert(ksess);
	assert(output);
	assert(session);


	/*
	 * Copy kernel session sockets so we can communicate with the right
	 * consumer for the snapshot record command.
	 */
	ret = consumer_copy_sockets(output->consumer, ksess->consumer);
	if (ret < 0) {
		ret = LTTNG_ERR_NOMEM;
		goto error;
	}

	ret = set_relayd_for_snapshot(ksess->consumer, output, session);
	if (ret != LTTNG_OK) {
		goto error_snapshot;
	}

	ret = kernel_snapshot_record(ksess, output, wait, nb_packets_per_stream);
	if (ret != LTTNG_OK) {
		goto error_snapshot;
	}

	ret = LTTNG_OK;
	goto end;

error_snapshot:
	/* Clean up copied sockets so this output can use some other later on. */
	consumer_destroy_output_sockets(output->consumer);
error:
end:
	return ret;
}

/*
 * Record a UST snapshot.
 *
 * Return 0 on success or a LTTNG_ERR error code.
 */
static int record_ust_snapshot(struct ltt_ust_session *usess,
		struct snapshot_output *output, struct ltt_session *session,
		int wait, uint64_t nb_packets_per_stream)
{
	int ret;

	assert(usess);
	assert(output);
	assert(session);

	/*
	 * Copy UST session sockets so we can communicate with the right
	 * consumer for the snapshot record command.
	 */
	ret = consumer_copy_sockets(output->consumer, usess->consumer);
	if (ret < 0) {
		ret = LTTNG_ERR_NOMEM;
		goto error;
	}

	ret = set_relayd_for_snapshot(usess->consumer, output, session);
	if (ret != LTTNG_OK) {
		goto error_snapshot;
	}

	ret = ust_app_snapshot_record(usess, output, wait, nb_packets_per_stream);
	if (ret < 0) {
		switch (-ret) {
		case EINVAL:
			ret = LTTNG_ERR_INVALID;
			break;
		default:
			ret = LTTNG_ERR_SNAPSHOT_FAIL;
			break;
		}
		goto error_snapshot;
	}

	ret = LTTNG_OK;

error_snapshot:
	/* Clean up copied sockets so this output can use some other later on. */
	consumer_destroy_output_sockets(output->consumer);
error:
	return ret;
}

static
uint64_t get_session_size_one_more_packet_per_stream(struct ltt_session *session,
	uint64_t cur_nr_packets)
{
	uint64_t tot_size = 0;

	if (session->kernel_session) {
		struct ltt_kernel_channel *chan;
		struct ltt_kernel_session *ksess = session->kernel_session;

		cds_list_for_each_entry(chan, &ksess->channel_list.head, list) {
			if (cur_nr_packets >= chan->channel->attr.num_subbuf) {
				/*
				 * Don't take channel into account if we
				 * already grab all its packets.
				 */
				continue;
			}
			tot_size += chan->channel->attr.subbuf_size
				* chan->stream_count;
		}
	}

	if (session->ust_session) {
		struct ltt_ust_session *usess = session->ust_session;

		tot_size += ust_app_get_size_one_more_packet_per_stream(usess,
				cur_nr_packets);
	}

	return tot_size;
}

/*
 * Calculate the number of packets we can grab from each stream that
 * fits within the overall snapshot max size.
 *
 * Returns -1 on error, 0 means infinite number of packets, else > 0 is
 * the number of packets per stream.
 *
 * TODO: this approach is not perfect: we consider the worse case
 * (packet filling the sub-buffers) as an upper bound, but we could do
 * better if we do this calculation while we actually grab the packet
 * content: we would know how much padding we don't actually store into
 * the file.
 *
 * This algorithm is currently bounded by the number of packets per
 * stream.
 *
 * Since we call this algorithm before actually grabbing the data, it's
 * an approximation: for instance, applications could appear/disappear
 * in between this call and actually grabbing data.
 */
static
int64_t get_session_nb_packets_per_stream(struct ltt_session *session, uint64_t max_size)
{
	int64_t size_left;
	uint64_t cur_nb_packets = 0;

	if (!max_size) {
		return 0;	/* Infinite */
	}

	size_left = max_size;
	for (;;) {
		uint64_t one_more_packet_tot_size;

		one_more_packet_tot_size = get_session_size_one_more_packet_per_stream(session,
					cur_nb_packets);
		if (!one_more_packet_tot_size) {
			/* We are already grabbing all packets. */
			break;
		}
		size_left -= one_more_packet_tot_size;
		if (size_left < 0) {
			break;
		}
		cur_nb_packets++;
	}
	if (!cur_nb_packets) {
		/* Not enough room to grab one packet of each stream, error. */
		return -1;
	}
	return cur_nb_packets;
}

/*
 * Command LTTNG_SNAPSHOT_RECORD from lib lttng ctl.
 *
 * The wait parameter is ignored so this call always wait for the snapshot to
 * complete before returning.
 *
 * Return LTTNG_OK on success or else a LTTNG_ERR code.
 */
int cmd_snapshot_record(struct ltt_session *session,
		struct lttng_snapshot_output *output, int wait)
{
	int ret = LTTNG_OK;
	unsigned int use_tmp_output = 0;
	struct snapshot_output tmp_output;
	unsigned int snapshot_success = 0;
	char datetime[16];

	assert(session);
	assert(output);

	DBG("Cmd snapshot record for session %s", session->name);

	/* Get the datetime for the snapshot output directory. */
	ret = utils_get_current_time_str("%Y%m%d-%H%M%S", datetime,
			sizeof(datetime));
	if (!ret) {
		ret = LTTNG_ERR_INVALID;
		goto error;
	}

	/*
	 * Permission denied to create an output if the session is not
	 * set in no output mode.
	 */
	if (session->output_traces) {
		ret = LTTNG_ERR_NOT_SNAPSHOT_SESSION;
		goto error;
	}

	/* The session needs to be started at least once. */
	if (!session->has_been_started) {
		ret = LTTNG_ERR_START_SESSION_ONCE;
		goto error;
	}

	/* Use temporary output for the session. */
	if (*output->ctrl_url != '\0') {
		ret = snapshot_output_init(output->max_size, output->name,
				output->ctrl_url, output->data_url, session->consumer,
				&tmp_output, NULL);
		if (ret < 0) {
			if (ret == -ENOMEM) {
				ret = LTTNG_ERR_NOMEM;
			} else {
				ret = LTTNG_ERR_INVALID;
			}
			goto error;
		}
		/* Use the global session count for the temporary snapshot. */
		tmp_output.nb_snapshot = session->snapshot.nb_snapshot;

		/* Use the global datetime */
		memcpy(tmp_output.datetime, datetime, sizeof(datetime));
		use_tmp_output = 1;
	}

	if (use_tmp_output) {
		int64_t nb_packets_per_stream;

		nb_packets_per_stream = get_session_nb_packets_per_stream(session,
				tmp_output.max_size);
		if (nb_packets_per_stream < 0) {
			ret = LTTNG_ERR_MAX_SIZE_INVALID;
			goto error;
		}

		if (session->kernel_session) {
			ret = record_kernel_snapshot(session->kernel_session,
					&tmp_output, session,
					wait, nb_packets_per_stream);
			if (ret != LTTNG_OK) {
				goto error;
			}
		}

		if (session->ust_session) {
			ret = record_ust_snapshot(session->ust_session,
					&tmp_output, session,
					wait, nb_packets_per_stream);
			if (ret != LTTNG_OK) {
				goto error;
			}
		}

		snapshot_success = 1;
	} else {
		struct snapshot_output *sout;
		struct lttng_ht_iter iter;

		rcu_read_lock();
		cds_lfht_for_each_entry(session->snapshot.output_ht->ht,
				&iter.iter, sout, node.node) {
			int64_t nb_packets_per_stream;

			/*
			 * Make a local copy of the output and assign the possible
			 * temporary value given by the caller.
			 */
			memset(&tmp_output, 0, sizeof(tmp_output));
			memcpy(&tmp_output, sout, sizeof(tmp_output));

			if (output->max_size != (uint64_t) -1ULL) {
				tmp_output.max_size = output->max_size;
			}

			nb_packets_per_stream = get_session_nb_packets_per_stream(session,
					tmp_output.max_size);
			if (nb_packets_per_stream < 0) {
				ret = LTTNG_ERR_MAX_SIZE_INVALID;
				rcu_read_unlock();
				goto error;
			}

			/* Use temporary name. */
			if (*output->name != '\0') {
				if (lttng_strncpy(tmp_output.name, output->name,
						sizeof(tmp_output.name))) {
					ret = LTTNG_ERR_INVALID;
					rcu_read_unlock();
					goto error;
				}
			}

			tmp_output.nb_snapshot = session->snapshot.nb_snapshot;
			memcpy(tmp_output.datetime, datetime, sizeof(datetime));

			if (session->kernel_session) {
				ret = record_kernel_snapshot(session->kernel_session,
						&tmp_output, session,
						wait, nb_packets_per_stream);
				if (ret != LTTNG_OK) {
					rcu_read_unlock();
					goto error;
				}
			}

			if (session->ust_session) {
				ret = record_ust_snapshot(session->ust_session,
						&tmp_output, session,
						wait, nb_packets_per_stream);
				if (ret != LTTNG_OK) {
					rcu_read_unlock();
					goto error;
				}
			}
			snapshot_success = 1;
		}
		rcu_read_unlock();
	}

	if (snapshot_success) {
		session->snapshot.nb_snapshot++;
	} else {
		ret = LTTNG_ERR_SNAPSHOT_FAIL;
	}

error:
	return ret;
}

/*
 * Command LTTNG_SET_SESSION_SHM_PATH processed by the client thread.
 */
int cmd_set_session_shm_path(struct ltt_session *session,
		const char *shm_path)
{
	/* Safety net */
	assert(session);

	/*
	 * Can only set shm path before session is started.
	 */
	if (session->has_been_started) {
		return LTTNG_ERR_SESSION_STARTED;
	}

	strncpy(session->shm_path, shm_path,
		sizeof(session->shm_path));
	session->shm_path[sizeof(session->shm_path) - 1] = '\0';

	return 0;
}

/*
 * Command LTTNG_ROTATE_SESSION from the lttng-ctl library.
 *
 * Ask the consumer to rotate the session output directory.
 * The session lock must be held.
 *
 * Return LTTNG_OK on success or else a LTTNG_ERR code.
 */
int cmd_rotate_session(struct ltt_session *session,
		struct lttng_rotate_session_return *rotate_return)
{
	int ret;
	size_t strf_ret;
	struct tm *timeinfo;
	char datetime[21];
	time_t now;
	bool ust_active = false;

	assert(session);

	if (!session->has_been_started) {
		ret = -LTTNG_ERR_START_SESSION_ONCE;
		goto end;
	}

	if (session->live_timer || session->snapshot_mode ||
			!session->output_traces) {
		ret = -LTTNG_ERR_ROTATION_NOT_AVAILABLE;
		goto end;
	}

	/*
	 * Unsupported feature in lttng-relayd before 2.11.
	 */
	if (session->consumer->type == CONSUMER_DST_NET &&
			(session->consumer->relay_major_version == 2 &&
			session->consumer->relay_minor_version < 11)) {
		ret = -LTTNG_ERR_ROTATION_NOT_AVAILABLE_RELAY;
		goto end;
	}

	if (session->rotate_pending || session->rotate_pending_relay) {
		ret = -LTTNG_ERR_ROTATION_PENDING;
		DBG("Rotate already in progress");
		goto end;
	}

	/*
	 * After a stop, we only allow one rotation to occur, the other ones are
	 * useless until a new start.
	 */
	if (session->rotated_after_last_stop) {
		DBG("Session \"%s\" was already rotated after stop, refusing rotation",
				session->name);
		ret = -LTTNG_ERR_ROTATION_MULTIPLE_AFTER_STOP;
		goto end;
	}

	/* Special case for the first rotation. */
	if (session->current_archive_id == 0) {
		const char *base_path = NULL;

		/* Either one of the two sessions is enough to get the root path. */
		if (session->kernel_session) {
			base_path = session_get_base_path(session);
		} else if (session->ust_session) {
			base_path = session_get_base_path(session);
		} else {
			assert(0);
		}
		assert(base_path);
		ret = lttng_strncpy(session->rotation_chunk.current_rotate_path,
				base_path,
				sizeof(session->rotation_chunk.current_rotate_path));
		if (ret) {
			ERR("Failed to copy session base path to current rotation chunk path");
			ret = -LTTNG_ERR_UNK;
			goto end;
		}
	} else {
		/*
		 * The currently active tracing path is now the folder we
		 * want to rotate.
		 */
		ret = lttng_strncpy(session->rotation_chunk.current_rotate_path,
				session->rotation_chunk.active_tracing_path,
				sizeof(session->rotation_chunk.current_rotate_path));
		if (ret) {
			ERR("Failed to copy the active tracing path to the current rotate path");
			ret = -LTTNG_ERR_UNK;
			goto end;
		}
	}
	DBG("Current rotate path %s", session->rotation_chunk.current_rotate_path);

	session->current_archive_id++;
	session->rotate_pending = true;
	session->rotation_state = LTTNG_ROTATION_STATE_ONGOING;
	ret = notification_thread_command_session_rotation_ongoing(
			notification_thread_handle,
			session->name, session->uid, session->gid,
			session->current_archive_id);
	if (ret != LTTNG_OK) {
		ERR("Failed to notify notification thread that a session rotation is ongoing for session %s",
				session->name);
	}

	/*
	 * Create the path name for the next chunk.
	 */
	now = time(NULL);
	if (now == (time_t) -1) {
		ret = -LTTNG_ERR_ROTATION_NOT_AVAILABLE;
		goto end;
	}
	session->last_chunk_start_ts = session->current_chunk_start_ts;
	session->current_chunk_start_ts = now;

	timeinfo = localtime(&now);
	if (!timeinfo) {
		PERROR("Failed to sample local time in rotate session command");
		ret = -LTTNG_ERR_UNK;
		goto end;
	}
	strf_ret = strftime(datetime, sizeof(datetime), "%Y%m%dT%H%M%S%z",
			timeinfo);
	if (!strf_ret) {
		ERR("Failed to format local time timestamp in rotate session command");
		ret = -LTTNG_ERR_UNK;
		goto end;
	}
	if (session->kernel_session) {
		/*
		 * The active path for the next rotation/destroy.
		 * Ex: ~/lttng-traces/auto-20170922-111748/20170922-111754-42
		 */
		ret = snprintf(session->rotation_chunk.active_tracing_path,
				sizeof(session->rotation_chunk.active_tracing_path),
				"%s/%s-%" PRIu64,
				session_get_base_path(session),
				datetime, session->current_archive_id + 1);
		if (ret < 0 || ret == sizeof(session->rotation_chunk.active_tracing_path)) {
			ERR("Failed to format active kernel tracing path in rotate session command");
			ret = -LTTNG_ERR_UNK;
			goto end;
		}
		/*
		 * The sub-directory for the consumer
		 * Ex: /20170922-111754-42/kernel
		 */
		ret = snprintf(session->kernel_session->consumer->chunk_path,
				sizeof(session->kernel_session->consumer->chunk_path),
				"/%s-%" PRIu64, datetime,
				session->current_archive_id + 1);
		if (ret < 0 || ret == sizeof(session->kernel_session->consumer->chunk_path)) {
			ERR("Failed to format the kernel consumer's sub-directory in rotate session command");
			ret = -LTTNG_ERR_UNK;
			goto end;
		}
		/*
		 * Create the new chunk folder, before the rotation begins so we don't
		 * race with the consumer/tracer activity.
		 */
		ret = domain_mkdir(session->kernel_session->consumer, session,
				session->kernel_session->uid,
				session->kernel_session->gid);
		if (ret) {
			ERR("Failed to create kernel session tracing path at %s",
					session->kernel_session->consumer->chunk_path);
			ret = -LTTNG_ERR_CREATE_DIR_FAIL;
			goto end;
		}
		ret = kernel_rotate_session(session);
		if (ret != LTTNG_OK) {
			ret = -ret;
			goto end;
		}
	}
	if (session->ust_session) {
		ret = snprintf(session->rotation_chunk.active_tracing_path,
				PATH_MAX, "%s/%s-%" PRIu64,
				session_get_base_path(session),
				datetime, session->current_archive_id + 1);
		if (ret < 0) {
			ERR("Failed to format active UST tracing path in rotate session command");
			ret = -LTTNG_ERR_UNK;
			goto end;
		}
		ret = snprintf(session->ust_session->consumer->chunk_path,
				PATH_MAX, "/%s-%" PRIu64, datetime,
				session->current_archive_id + 1);
		if (ret < 0) {
			ERR("Failed to format the UST consumer's sub-directory in rotate session command");
			ret = -LTTNG_ERR_UNK;
			goto end;
		}
		/*
		 * Create the new chunk folder, before the rotation begins so we don't
		 * race with the consumer/tracer activity.
		 */
		ret = domain_mkdir(session->ust_session->consumer, session,
				session->ust_session->uid,
				session->ust_session->gid);
		if (ret) {
			ret = -LTTNG_ERR_CREATE_DIR_FAIL;
			goto end;
		}
		ret = ust_app_rotate_session(session, &ust_active);
		if (ret != LTTNG_OK) {
			goto end;
		}
		/*
		 * Handle the case where we did not start a rotation on any channel.
		 * The consumer will never wake up the rotation thread to perform the
		 * rename, so we have to do it here while we hold the session and
		 * session_list locks.
		 */
		if (!session->kernel_session && !ust_active) {
			struct lttng_trace_archive_location *location;

			session->rotate_pending = false;
			session->rotation_state = LTTNG_ROTATION_STATE_COMPLETED;
			ret = rename_complete_chunk(session, now);
			if (ret < 0) {
				ERR("Failed to rename completed rotation chunk");
				goto end;
			}

			/* Ownership of location is transferred. */
			location = session_get_trace_archive_location(session);
			ret = notification_thread_command_session_rotation_completed(
					notification_thread_handle,
					session->name,
					session->uid,
					session->gid,
					session->current_archive_id,
					location);
			if (ret != LTTNG_OK) {
				ERR("Failed to notify notification thread that rotation is complete for session %s",
						session->name);
			}
		}
	}

	if (!session->active) {
		session->rotated_after_last_stop = true;
	}

	if (rotate_return) {
		rotate_return->rotation_id = session->current_archive_id;
	}

	DBG("Cmd rotate session %s, current_archive_id %" PRIu64 " sent",
			session->name, session->current_archive_id);
	ret = LTTNG_OK;

end:
	return ret;
}

/*
 * Command LTTNG_ROTATION_GET_INFO from the lttng-ctl library.
 *
 * Check if the session has finished its rotation.
 *
 * Return 0 on success or else a LTTNG_ERR code.
 */
int cmd_rotate_get_info(struct ltt_session *session,
		struct lttng_rotation_get_info_return *info_return,
		uint64_t rotation_id)
{
	int ret;

	assert(session);

	DBG("Cmd rotate_get_info session %s, rotation id %" PRIu64, session->name,
			session->current_archive_id);

	if (session->current_archive_id != rotation_id) {
		info_return->status = (int32_t) LTTNG_ROTATION_STATE_EXPIRED;
		ret = LTTNG_OK;
		goto end;
	}

	switch (session->rotation_state) {
	case LTTNG_ROTATION_STATE_ONGOING:
		DBG("Reporting that rotation id %" PRIu64 " of session %s is still pending",
				rotation_id, session->name);
		break;
	case LTTNG_ROTATION_STATE_COMPLETED:
	{
		char *current_tracing_path_reply;
		size_t current_tracing_path_reply_len;

		switch (session_get_consumer_destination_type(session)) {
		case CONSUMER_DST_LOCAL:
			current_tracing_path_reply =
					info_return->location.local.absolute_path;
			current_tracing_path_reply_len =
					sizeof(info_return->location.local.absolute_path);
			info_return->location_type =
					(int8_t) LTTNG_TRACE_ARCHIVE_LOCATION_TYPE_LOCAL;
			break;
		case CONSUMER_DST_NET:
			current_tracing_path_reply =
					info_return->location.relay.relative_path;
			current_tracing_path_reply_len =
					sizeof(info_return->location.relay.relative_path);
			/* Currently the only supported relay protocol. */
			info_return->location.relay.protocol =
					(int8_t) LTTNG_TRACE_ARCHIVE_LOCATION_RELAY_PROTOCOL_TYPE_TCP;

			ret = lttng_strncpy(info_return->location.relay.host,
					session_get_net_consumer_hostname(session),
					sizeof(info_return->location.relay.host));
			if (ret) {
				ERR("Failed to host name to rotate_get_info reply");
				info_return->status = LTTNG_ROTATION_STATUS_ERROR;
				ret = -LTTNG_ERR_UNK;
				goto end;
			}

			session_get_net_consumer_ports(session,
					&info_return->location.relay.ports.control,
					&info_return->location.relay.ports.data);
			info_return->location_type =
					(int8_t) LTTNG_TRACE_ARCHIVE_LOCATION_TYPE_RELAY;
			break;
		default:
			abort();
		}
		ret = lttng_strncpy(current_tracing_path_reply,
				session->rotation_chunk.current_rotate_path,
				current_tracing_path_reply_len);
		if (ret) {
			ERR("Failed to copy current tracing path to rotate_get_info reply");
			info_return->status = LTTNG_ROTATION_STATUS_ERROR;
			ret = -LTTNG_ERR_UNK;
			goto end;
		}

		break;
	}
	case LTTNG_ROTATION_STATE_ERROR:
		DBG("Reporting that an error occurred during rotation %" PRIu64 " of session %s",
				rotation_id, session->name);
		break;
	default:
		abort();
	}

	info_return->status = (int32_t) session->rotation_state;
	ret = LTTNG_OK;
end:
	return ret;
}

/*
 * Command LTTNG_ROTATION_SET_SCHEDULE from the lttng-ctl library.
 *
 * Configure the automatic rotation parameters.
 * 'activate' to true means activate the rotation schedule type with 'new_value'.
 * 'activate' to false means deactivate the rotation schedule and validate that
 * 'new_value' has the same value as the currently active value.
 *
 * Return 0 on success or else a positive LTTNG_ERR code.
 */
int cmd_rotation_set_schedule(struct ltt_session *session,
		bool activate, enum lttng_rotation_schedule_type schedule_type,
		uint64_t new_value,
		struct notification_thread_handle *notification_thread_handle)
{
	int ret;
	uint64_t *parameter_value;

	assert(session);

	DBG("Cmd rotate set schedule session %s", session->name);

	if (session->live_timer || session->snapshot_mode ||
			!session->output_traces) {
		DBG("Failing ROTATION_SET_SCHEDULE command as the rotation feature is not available for this session");
		ret = LTTNG_ERR_ROTATION_NOT_AVAILABLE;
		goto end;
	}

	switch (schedule_type) {
	case LTTNG_ROTATION_SCHEDULE_TYPE_SIZE_THRESHOLD:
		parameter_value = &session->rotate_size;
		break;
	case LTTNG_ROTATION_SCHEDULE_TYPE_PERIODIC:
		parameter_value = &session->rotate_timer_period;
		if (new_value >= UINT_MAX) {
			DBG("Failing ROTATION_SET_SCHEDULE command as the value requested for a periodic rotation schedule is invalid: %" PRIu64 " > %u (UINT_MAX)",
					new_value, UINT_MAX);
			ret = LTTNG_ERR_INVALID;
			goto end;
		}
		break;
	default:
		WARN("Failing ROTATION_SET_SCHEDULE command on unknown schedule type");
		ret = LTTNG_ERR_INVALID;
		goto end;
	}

	/* Improper use of the API. */
	if (new_value == -1ULL) {
		WARN("Failing ROTATION_SET_SCHEDULE command as the value requested is -1");
		ret = LTTNG_ERR_INVALID;
		goto end;
	}

	/*
	 * As indicated in struct ltt_session's comments, a value of == 0 means
	 * this schedule rotation type is not in use.
	 *
	 * Reject the command if we were asked to activate a schedule that was
	 * already active.
	 */
	if (activate && *parameter_value != 0) {
		DBG("Failing ROTATION_SET_SCHEDULE (activate) command as the schedule is already active");
		ret = LTTNG_ERR_ROTATION_SCHEDULE_SET;
		goto end;
	}

	/*
	 * Reject the command if we were asked to deactivate a schedule that was
	 * not active.
	 */
	if (!activate && *parameter_value == 0) {
		DBG("Failing ROTATION_SET_SCHEDULE (deactivate) command as the schedule is already inactive");
		ret = LTTNG_ERR_ROTATION_SCHEDULE_NOT_SET;
		goto end;
	}

	/*
	 * Reject the command if we were asked to deactivate a schedule that
	 * doesn't exist.
	 */
	if (!activate && *parameter_value != new_value) {
		DBG("Failing ROTATION_SET_SCHEDULE (deactivate) command as an inexistant schedule was provided");
		ret = LTTNG_ERR_ROTATION_SCHEDULE_NOT_SET;
		goto end;
	}

	*parameter_value = activate ? new_value : 0;

	switch (schedule_type) {
	case LTTNG_ROTATION_SCHEDULE_TYPE_PERIODIC:
		if (activate && session->active) {
			/*
			 * Only start the timer if the session is active,
			 * otherwise it will be started when the session starts.
			 */
			ret = sessiond_rotate_timer_start(session, new_value);
			if (ret) {
				ERR("Failed to enable session rotation timer in ROTATION_SET_SCHEDULE command");
				ret = LTTNG_ERR_UNK;
				goto end;
			}
		} else {
			ret = sessiond_rotate_timer_stop(session);
			if (ret) {
				ERR("Failed to disable session rotation timer in ROTATION_SET_SCHEDULE command");
				ret = LTTNG_ERR_UNK;
				goto end;
			}
		}
		break;
	case LTTNG_ROTATION_SCHEDULE_TYPE_SIZE_THRESHOLD:
		if (activate) {
			ret = subscribe_session_consumed_size_rotation(session,
					new_value, notification_thread_handle);
			if (ret) {
				ERR("Failed to enable consumed-size notification in ROTATION_SET_SCHEDULE command");
				ret = LTTNG_ERR_UNK;
				goto end;
			}
		} else {
			ret = unsubscribe_session_consumed_size_rotation(session,
					notification_thread_handle);
			if (ret) {
				ERR("Failed to disable consumed-size notification in ROTATION_SET_SCHEDULE command");
				ret = LTTNG_ERR_UNK;
				goto end;
			}

		}
		break;
	default:
		/* Would have been caught before. */
		abort();
	}

	ret = LTTNG_OK;

	goto end;

end:
	return ret;
}

/*
 * Command ROTATE_GET_CURRENT_PATH from the lttng-ctl library.
 *
 * Configure the automatic rotation parameters.
 * Set to -1ULL to disable them.
 *
 * Return LTTNG_OK on success or else a LTTNG_ERR code.
 */
int cmd_session_get_current_output(struct ltt_session *session,
		struct lttng_session_get_current_output_return *output_return)
{
	int ret;
	const char *path;

	if (!session->snapshot_mode) {
		if (session->current_archive_id == 0) {
			if (session->kernel_session) {
				path = session_get_base_path(session);
			} else if (session->ust_session) {
				path = session_get_base_path(session);
			} else {
				abort();
			}
			assert(path);
		} else {
			path = session->rotation_chunk.active_tracing_path;
		}
	} else {
		/*
		 * A snapshot session does not have a "current" trace archive
		 * location.
		 */
		path = "";
	}

	DBG("Cmd get current output for session %s, returning %s",
			session->name, path);

	ret = lttng_strncpy(output_return->path,
			path,
			sizeof(output_return->path));
	if (ret) {
		ERR("Failed to copy trace output path to session get current output command reply");
		ret = -LTTNG_ERR_UNK;
		goto end;
	}

	ret = LTTNG_OK;
end:
	return ret;
}

/* Wait for a given path to be removed before continuing. */
static enum lttng_error_code wait_on_path(void *path_data)
{
	const char *shm_path = path_data;

	DBG("Waiting for the shm path at %s to be removed before completing session destruction",
			shm_path);
	while (true) {
		int ret;
		struct stat st;

		ret = stat(shm_path, &st);
		if (ret) {
			if (errno != ENOENT) {
				PERROR("stat() returned an error while checking for the existence of the shm path");
			} else {
				DBG("shm path no longer exists, completing the destruction of session");
			}
			break;
		} else {
			if (!S_ISDIR(st.st_mode)) {
				ERR("The type of shm path %s returned by stat() is not a directory; aborting the wait for shm path removal",
						shm_path);
				break;
			}
		}
		usleep(SESSION_DESTROY_SHM_PATH_CHECK_DELAY_US);
	}
	return LTTNG_OK;
}

/*
 * Returns a pointer to a handler to run on completion of a command.
 * Returns NULL if no handler has to be run for the last command executed.
 */
const struct cmd_completion_handler *cmd_pop_completion_handler(void)
{
	struct cmd_completion_handler *handler = current_completion_handler;

	current_completion_handler = NULL;
	return handler;
}

/*
 * Init command subsystem.
 */
void cmd_init(void)
{
	/*
	 * Set network sequence index to 1 for streams to match a relayd
	 * socket on the consumer side.
	 */
	pthread_mutex_lock(&relayd_net_seq_idx_lock);
	relayd_net_seq_idx = 1;
	pthread_mutex_unlock(&relayd_net_seq_idx_lock);

	DBG("Command subsystem initialized");
}
