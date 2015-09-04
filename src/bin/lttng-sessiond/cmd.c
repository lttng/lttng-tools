/*
 * Copyright (C) 2012 - David Goulet <dgoulet@efficios.com>
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

#define _GNU_SOURCE
#define _LGPL_SOURCE
#include <assert.h>
#include <string.h>
#include <inttypes.h>
#include <urcu/list.h>
#include <urcu/uatomic.h>

#include <common/defaults.h>
#include <common/common.h>
#include <common/sessiond-comm/sessiond-comm.h>
#include <common/relayd/relayd.h>
#include <common/utils.h>

#include "channel.h"
#include "consumer.h"
#include "event.h"
#include "health-sessiond.h"
#include "kernel.h"
#include "kernel-consumer.h"
#include "lttng-sessiond.h"
#include "utils.h"
#include "syscall.h"
#include "agent.h"

#include "cmd.h"

/*
 * Used to keep a unique index for each relayd socket created where this value
 * is associated with streams on the consumer so it can match the right relayd
 * to send to. It must be accessed with the relayd_net_seq_idx_lock
 * held.
 */
static pthread_mutex_t relayd_net_seq_idx_lock = PTHREAD_MUTEX_INITIALIZER;
static uint64_t relayd_net_seq_idx;

static int validate_event_name(const char *);
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
 * Fill lttng_channel array of all channels.
 */
static void list_lttng_channels(enum lttng_domain_type domain,
		struct ltt_session *session, struct lttng_channel *channels)
{
	int i = 0;
	struct ltt_kernel_channel *kchan;

	DBG("Listing channels for session %s", session->name);

	switch (domain) {
	case LTTNG_DOMAIN_KERNEL:
		/* Kernel channels */
		if (session->kernel_session != NULL) {
			cds_list_for_each_entry(kchan,
					&session->kernel_session->channel_list.head, list) {
				/* Copy lttng_channel struct to array */
				memcpy(&channels[i], kchan->channel, sizeof(struct lttng_channel));
				channels[i].enabled = kchan->enabled;
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
			strncpy(channels[i].name, uchan->name, LTTNG_SYMBOL_NAME_LEN);
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
			switch (uchan->attr.output) {
			case LTTNG_UST_MMAP:
			default:
				channels[i].attr.output = LTTNG_EVENT_MMAP;
				break;
			}
			i++;
		}
		rcu_read_unlock();
		break;
	}
	default:
		break;
	}
}

/*
 * Create a list of agent domain events.
 *
 * Return number of events in list on success or else a negative value.
 */
static int list_lttng_agent_events(struct agent *agt,
		struct lttng_event **events)
{
	int i = 0, ret = 0;
	unsigned int nb_event = 0;
	struct agent_event *event;
	struct lttng_event *tmp_events;
	struct lttng_ht_iter iter;

	assert(agt);
	assert(events);

	DBG3("Listing agent events");

	rcu_read_lock();
	nb_event = lttng_ht_get_count(agt->events);
	rcu_read_unlock();
	if (nb_event == 0) {
		ret = nb_event;
		goto error;
	}

	tmp_events = zmalloc(nb_event * sizeof(*tmp_events));
	if (!tmp_events) {
		PERROR("zmalloc agent events session");
		ret = -LTTNG_ERR_FATAL;
		goto error;
	}

	rcu_read_lock();
	cds_lfht_for_each_entry(agt->events->ht, &iter.iter, event, node.node) {
		strncpy(tmp_events[i].name, event->name, sizeof(tmp_events[i].name));
		tmp_events[i].name[sizeof(tmp_events[i].name) - 1] = '\0';
		tmp_events[i].enabled = event->enabled;
		tmp_events[i].loglevel = event->loglevel_value;
		tmp_events[i].loglevel_type = event->loglevel_type;
		i++;
	}
	rcu_read_unlock();

	*events = tmp_events;
	ret = nb_event;

error:
	assert(nb_event == i);
	return ret;
}

/*
 * Create a list of ust global domain events.
 */
static int list_lttng_ust_global_events(char *channel_name,
		struct ltt_ust_domain_global *ust_global, struct lttng_event **events)
{
	int i = 0, ret = 0;
	unsigned int nb_event = 0;
	struct lttng_ht_iter iter;
	struct lttng_ht_node_str *node;
	struct ltt_ust_channel *uchan;
	struct ltt_ust_event *uevent;
	struct lttng_event *tmp;

	DBG("Listing UST global events for channel %s", channel_name);

	rcu_read_lock();

	lttng_ht_lookup(ust_global->channels, (void *)channel_name, &iter);
	node = lttng_ht_iter_get_node_str(&iter);
	if (node == NULL) {
		ret = LTTNG_ERR_UST_CHAN_NOT_FOUND;
		goto error;
	}

	uchan = caa_container_of(&node->node, struct ltt_ust_channel, node.node);

	nb_event = lttng_ht_get_count(uchan->events);
	if (nb_event == 0) {
		ret = nb_event;
		goto error;
	}

	DBG3("Listing UST global %d events", nb_event);

	tmp = zmalloc(nb_event * sizeof(struct lttng_event));
	if (tmp == NULL) {
		ret = LTTNG_ERR_FATAL;
		goto error;
	}

	cds_lfht_for_each_entry(uchan->events->ht, &iter.iter, uevent, node.node) {
		if (uevent->internal) {
			/* This event should remain hidden from clients */
			nb_event--;
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
	}

	ret = nb_event;
	*events = tmp;

error:
	rcu_read_unlock();
	return ret;
}

/*
 * Fill lttng_event array of all kernel events in the channel.
 */
static int list_lttng_kernel_events(char *channel_name,
		struct ltt_kernel_session *kernel_session, struct lttng_event **events)
{
	int i = 0, ret;
	unsigned int nb_event;
	struct ltt_kernel_event *event;
	struct ltt_kernel_channel *kchan;

	kchan = trace_kernel_get_channel_by_name(channel_name, kernel_session);
	if (kchan == NULL) {
		ret = LTTNG_ERR_KERN_CHAN_NOT_FOUND;
		goto error;
	}

	nb_event = kchan->event_count;

	DBG("Listing events for channel %s", kchan->channel->name);

	if (nb_event == 0) {
		*events = NULL;
		goto syscall;
	}

	*events = zmalloc(nb_event * sizeof(struct lttng_event));
	if (*events == NULL) {
		ret = LTTNG_ERR_FATAL;
		goto error;
	}

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
			assert(0);
			break;
		}
		i++;
	}

syscall:
	if (syscall_table) {
		ssize_t new_size;

		new_size = syscall_list_channel(kchan, events, nb_event);
		if (new_size < 0) {
			free(events);
			ret = -new_size;
			goto error;
		}
		nb_event = new_size;
	}

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
		memset(consumer->dst.trace_path, 0,
				sizeof(consumer->dst.trace_path));
		strncpy(consumer->dst.trace_path, uri->dst.path,
				sizeof(consumer->dst.trace_path));
		/* Append default trace dir */
		strncat(consumer->dst.trace_path, default_trace_dir,
				sizeof(consumer->dst.trace_path) -
				strlen(consumer->dst.trace_path) - 1);
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
		struct lttcomm_relayd_sock **relayd_sock)
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
		if (ret < 0) {
			ret = LTTNG_ERR_RELAYD_VERSION_FAIL;
			goto close_sock;
		}
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
 */
static int send_consumer_relayd_socket(enum lttng_domain_type domain,
		unsigned int session_id, struct lttng_uri *relayd_uri,
		struct consumer_output *consumer,
		struct consumer_socket *consumer_sock,
		char *session_name, char *hostname, int session_live_timer)
{
	int ret;
	struct lttcomm_relayd_sock *rsock = NULL;

	/* Connect to relayd and make version check if uri is the control. */
	ret = create_connect_relayd(relayd_uri, &rsock);
	if (ret != LTTNG_OK) {
		goto error;
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
	(void) relayd_close(rsock);
	free(rsock);

error:
	if (ret != LTTNG_OK) {
		/*
		 * The consumer output for this session should not be used anymore
		 * since the relayd connection failed thus making any tracing or/and
		 * streaming not usable.
		 */
		consumer->enabled = 0;
	}
	return ret;
}

/*
 * Send both relayd sockets to a specific consumer and domain.  This is a
 * helper function to facilitate sending the information to the consumer for a
 * session.
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
		ret = send_consumer_relayd_socket(domain, session_id,
				&consumer->dst.net.control, consumer, sock,
				session_name, hostname, session_live_timer);
		if (ret != LTTNG_OK) {
			goto error;
		}
	}

	/* Sending data relayd socket. */
	if (!sock->data_sock_sent) {
		ret = send_consumer_relayd_socket(domain, session_id,
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
	kernel_wait_quiescent(kernel_tracer_fd);

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

	len = strnlen(attr->name, sizeof(attr->name));

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

	/*
	 * The ringbuffer (both in user space and kernel) behave badly in overwrite
	 * mode and with less than 2 subbuf so block it right away and send back an
	 * invalid attribute error.
	 */
	if (attr->attr.overwrite && attr->attr.num_subbuf < 2) {
		ret = LTTNG_ERR_INVALID;
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
	if (validate_event_name(event_name)) {
		ret = LTTNG_ERR_INVALID_EVENT_NAME;
		goto error;
	}

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
			ret = event_kernel_disable_event_all(kchan);
			if (ret != LTTNG_OK) {
				goto error_unlock;
			}
			break;
		case LTTNG_EVENT_TRACEPOINT:	/* fall-through */
		case LTTNG_EVENT_SYSCALL:
			if (!strcmp(event_name, "*")) {
				ret = event_kernel_disable_event_type(kchan,
					event->type);
			} else {
				ret = event_kernel_disable_event(kchan,
					event_name);
			}
			if (ret != LTTNG_OK) {
				goto error_unlock;
			}
			break;
		case LTTNG_EVENT_PROBE:
		case LTTNG_EVENT_FUNCTION:
		case LTTNG_EVENT_FUNCTION_ENTRY:
			ret = event_kernel_disable_event(kchan, event_name);
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
		 * session, explicitely require that -c chan_name needs
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
			ret = event_ust_disable_tracepoint(usess, uchan, event_name);
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
		/* The wild card * means that everything should be disabled. */
		if (strncmp(event->name, "*", 1) == 0 && strlen(event->name) == 1) {
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
			free(attr);
			chan_ust_created = 1;
		}

		ret = context_ust_add(usess, domain, ctx, channel_name);
		if (ret != LTTNG_OK) {
			goto error;
		}
		break;
	}
	default:
		ret = LTTNG_ERR_UND;
		goto error;
	}

	return LTTNG_OK;

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
	return ret;
}

static int validate_event_name(const char *name)
{
	int ret = 0;
	const char *c = name;
	const char *event_name_end = c + LTTNG_SYMBOL_NAME_LEN;
	bool null_terminated = false;

	/*
	 * Make sure that unescaped wildcards are only used as the last
	 * character of the event name.
	 */
	while (c < event_name_end) {
		switch (*c) {
		case '\0':
		        null_terminated = true;
			goto end;
		case '\\':
			c++;
			break;
		case '*':
			if ((c + 1) < event_name_end && *(c + 1)) {
				/* Wildcard is not the last character */
				ret = LTTNG_ERR_INVALID_EVENT_NAME;
				goto end;
			}
		default:
			break;
		}
		c++;
	}
end:
	if (!ret && !null_terminated) {
		ret = LTTNG_ERR_INVALID_EVENT_NAME;
	}
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
	int ret, channel_created = 0;
	struct lttng_channel *attr;

	assert(session);
	assert(event);
	assert(channel_name);

	/* If we have a filter, we must have its filter expression */
	assert(!(!!filter_expression ^ !!filter));

	DBG("Enable event command for event \'%s\'", event->name);

	ret = validate_event_name(event->name);
	if (ret) {
		goto error;
	}

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
			strncpy(attr->name, channel_name, sizeof(attr->name));

			ret = cmd_enable_channel(session, domain, attr, wpipe);
			if (ret != LTTNG_OK) {
				free(attr);
				goto error;
			}
			free(attr);

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
			if (ret != LTTNG_OK) {
				free(filter_expression_a);
				free(filter_a);
				goto error;
			}
			break;
		}
		case LTTNG_EVENT_PROBE:
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
			strncpy(attr->name, channel_name, sizeof(attr->name));

			ret = cmd_enable_channel(session, domain, attr, wpipe);
			if (ret != LTTNG_OK) {
				free(attr);
				goto error;
			}
			free(attr);

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
						event->name ?
						event->name : "NULL");
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
		if (ret != LTTNG_OK) {
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

		if (ret != LTTNG_OK && ret != LTTNG_ERR_UST_EVENT_ENABLED) {
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

error:
	free(filter_expression);
	free(filter);
	free(exclusion);
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

	/* Kernel tracing */
	if (ksession != NULL) {
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

	ret = LTTNG_OK;

error:
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

	assert(session);

	/* Short cut */
	ksession = session->kernel_session;
	usess = session->ust_session;

	/* Session is not active. Skip everythong and inform the client. */
	if (!session->active) {
		ret = LTTNG_ERR_TRACE_ALREADY_STOPPED;
		goto error;
	}

	/* Kernel tracer */
	if (ksession && ksession->active) {
		DBG("Stop kernel tracing");

		/* Flush metadata if exist */
		if (ksession->metadata_stream_fd >= 0) {
			ret = kernel_metadata_flush_buffer(ksession->metadata_stream_fd);
			if (ret < 0) {
				ERR("Kernel metadata flush failed");
			}
		}

		/* Flush all buffers before stopping */
		cds_list_for_each_entry(kchan, &ksession->channel_list.head, list) {
			ret = kernel_flush_buffer(kchan);
			if (ret < 0) {
				ERR("Kernel flush buffer error");
			}
		}

		ret = kernel_stop_session(ksession);
		if (ret < 0) {
			ret = LTTNG_ERR_KERN_STOP_FAIL;
			goto error;
		}

		kernel_wait_quiescent(kernel_tracer_fd);

		ksession->active = 0;
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
	ret = LTTNG_OK;

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
	ret = cmd_create_session_uri(name, NULL, 0, creds, -1);
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
int cmd_destroy_session(struct ltt_session *session, int wpipe)
{
	int ret;
	struct ltt_ust_session *usess;
	struct ltt_kernel_session *ksess;

	/* Safety net */
	assert(session);

	usess = session->ust_session;
	ksess = session->kernel_session;

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

	ret = session_destroy(session);

	return ret;
}

/*
 * Command LTTNG_CALIBRATE processed by the client thread.
 */
int cmd_calibrate(enum lttng_domain_type domain,
		struct lttng_calibrate *calibrate)
{
	int ret;

	switch (domain) {
	case LTTNG_DOMAIN_KERNEL:
	{
		struct lttng_kernel_calibrate kcalibrate;

		switch (calibrate->type) {
		case LTTNG_CALIBRATE_FUNCTION:
		default:
			/* Default and only possible calibrate option. */
			kcalibrate.type = LTTNG_KERNEL_CALIBRATE_KRETPROBE;
			break;
		}

		ret = kernel_calibrate(kernel_tracer_fd, &kcalibrate);
		if (ret < 0) {
			ret = LTTNG_ERR_KERN_ENABLE_FAIL;
			goto error;
		}
		break;
	}
	case LTTNG_DOMAIN_UST:
	{
		struct lttng_ust_calibrate ucalibrate;

		switch (calibrate->type) {
		case LTTNG_CALIBRATE_FUNCTION:
		default:
			/* Default and only possible calibrate option. */
			ucalibrate.type = LTTNG_UST_CALIBRATE_TRACEPOINT;
			break;
		}

		ret = ust_app_calibrate_glb(&ucalibrate);
		if (ret < 0) {
			ret = LTTNG_ERR_UST_CALIBRATE_FAIL;
			goto error;
		}
		break;
	}
	default:
		ret = LTTNG_ERR_UND;
		goto error;
	}

	ret = LTTNG_OK;

error:
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
	int ret;
	ssize_t nb_chan = 0;

	switch (domain) {
	case LTTNG_DOMAIN_KERNEL:
		if (session->kernel_session != NULL) {
			nb_chan = session->kernel_session->channel_count;
		}
		DBG3("Number of kernel channels %zd", nb_chan);
		if (nb_chan <= 0) {
			ret = LTTNG_ERR_KERN_CHAN_NOT_FOUND;
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
			ret = LTTNG_ERR_UST_CHAN_NOT_FOUND;
			goto error;
		}
		break;
	default:
		ret = LTTNG_ERR_UND;
		goto error;
	}

	if (nb_chan > 0) {
		*channels = zmalloc(nb_chan * sizeof(struct lttng_channel));
		if (*channels == NULL) {
			ret = LTTNG_ERR_FATAL;
			goto error;
		}

		list_lttng_channels(domain, session, *channels);
	}

	return nb_chan;

error:
	/* Return negative value to differentiate return code */
	return -ret;
}

/*
 * Command LTTNG_LIST_EVENTS processed by the client thread.
 */
ssize_t cmd_list_events(enum lttng_domain_type domain,
		struct ltt_session *session, char *channel_name,
		struct lttng_event **events)
{
	int ret = 0;
	ssize_t nb_event = 0;

	switch (domain) {
	case LTTNG_DOMAIN_KERNEL:
		if (session->kernel_session != NULL) {
			nb_event = list_lttng_kernel_events(channel_name,
					session->kernel_session, events);
		}
		break;
	case LTTNG_DOMAIN_UST:
	{
		if (session->ust_session != NULL) {
			nb_event = list_lttng_ust_global_events(channel_name,
					&session->ust_session->domain_global, events);
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
				nb_event = list_lttng_agent_events(agt, events);
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
					session->consumer->dst.trace_path);
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
	 * Permission denied to create an output if the session is not
	 * set in no output mode.
	 */
	if (session->output_traces) {
		ret = LTTNG_ERR_EPERM;
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
		ret = LTTNG_ERR_EPERM;
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
		ret = -LTTNG_ERR_EPERM;
		goto error;
	}

	if (session->snapshot.nb_output == 0) {
		ret = 0;
		goto error;
	}

	list = zmalloc(session->snapshot.nb_output * sizeof(*list));
	if (!list) {
		ret = -LTTNG_ERR_NOMEM;
		goto error;
	}

	/* Copy list from session to the new list object. */
	rcu_read_lock();
	cds_lfht_for_each_entry(session->snapshot.output_ht->ht, &iter.iter,
			output, node.node) {
		assert(output->consumer);
		list[idx].id = output->id;
		list[idx].max_size = output->max_size;
		strncpy(list[idx].name, output->name, sizeof(list[idx].name));
		if (output->consumer->type == CONSUMER_DST_LOCAL) {
			strncpy(list[idx].ctrl_url, output->consumer->dst.trace_path,
					sizeof(list[idx].ctrl_url));
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
	free(list);
	rcu_read_unlock();
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
		ret = send_consumer_relayd_sockets(0, session->id,
				snap_output->consumer, socket,
				session->name, session->hostname,
				session->live_timer);
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

	/* Get the datetime for the snapshot output directory. */
	ret = utils_get_current_time_str("%Y%m%d-%H%M%S", output->datetime,
			sizeof(output->datetime));
	if (!ret) {
		ret = LTTNG_ERR_INVALID;
		goto error;
	}

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

	/* Get the datetime for the snapshot output directory. */
	ret = utils_get_current_time_str("%Y%m%d-%H%M%S", output->datetime,
			sizeof(output->datetime));
	if (!ret) {
		ret = LTTNG_ERR_INVALID;
		goto error;
	}

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
		case ENODATA:
			ret = LTTNG_ERR_SNAPSHOT_NODATA;
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

	assert(session);
	assert(output);

	DBG("Cmd snapshot record for session %s", session->name);

	/*
	 * Permission denied to create an output if the session is not
	 * set in no output mode.
	 */
	if (session->output_traces) {
		ret = LTTNG_ERR_EPERM;
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
		use_tmp_output = 1;
	}

	if (session->kernel_session) {
		struct ltt_kernel_session *ksess = session->kernel_session;

		if (use_tmp_output) {
			int64_t nb_packets_per_stream;

			nb_packets_per_stream = get_session_nb_packets_per_stream(session,
					tmp_output.max_size);
			if (nb_packets_per_stream < 0) {
				ret = LTTNG_ERR_MAX_SIZE_INVALID;
				goto error;
			}
			ret = record_kernel_snapshot(ksess, &tmp_output, session,
					wait, nb_packets_per_stream);
			if (ret != LTTNG_OK) {
				goto error;
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
					goto error;
				}

				/* Use temporary name. */
				if (*output->name != '\0') {
					strncpy(tmp_output.name, output->name,
							sizeof(tmp_output.name));
				}

				tmp_output.nb_snapshot = session->snapshot.nb_snapshot;

				ret = record_kernel_snapshot(ksess, &tmp_output,
						session, wait, nb_packets_per_stream);
				if (ret != LTTNG_OK) {
					rcu_read_unlock();
					goto error;
				}
				snapshot_success = 1;
			}
			rcu_read_unlock();
		}
	}

	if (session->ust_session) {
		struct ltt_ust_session *usess = session->ust_session;

		if (use_tmp_output) {
			int64_t nb_packets_per_stream;

			nb_packets_per_stream = get_session_nb_packets_per_stream(session,
					tmp_output.max_size);
			if (nb_packets_per_stream < 0) {
				ret = LTTNG_ERR_MAX_SIZE_INVALID;
				goto error;
			}
			ret = record_ust_snapshot(usess, &tmp_output, session,
					wait, nb_packets_per_stream);
			if (ret != LTTNG_OK) {
				goto error;
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
					strncpy(tmp_output.name, output->name,
							sizeof(tmp_output.name));
				}

				tmp_output.nb_snapshot = session->snapshot.nb_snapshot;

				ret = record_ust_snapshot(usess, &tmp_output, session,
						wait, nb_packets_per_stream);
				if (ret != LTTNG_OK) {
					rcu_read_unlock();
					goto error;
				}
				snapshot_success = 1;
			}
			rcu_read_unlock();
		}
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
