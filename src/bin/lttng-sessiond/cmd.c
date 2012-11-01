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
#include <assert.h>
#include <urcu/list.h>
#include <urcu/uatomic.h>

#include <common/defaults.h>
#include <common/common.h>
#include <common/sessiond-comm/sessiond-comm.h>
#include <common/relayd/relayd.h>

#include "channel.h"
#include "consumer.h"
#include "event.h"
#include "kernel.h"
#include "kernel-consumer.h"
#include "lttng-sessiond.h"
#include "utils.h"

#include "cmd.h"

/*
 * Used to keep a unique index for each relayd socket created where this value
 * is associated with streams on the consumer so it can match the right relayd
 * to send to.
 *
 * This value should be incremented atomically for safety purposes and future
 * possible concurrent access.
 */
static unsigned int relayd_net_seq_idx;

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

	if (strlen(tmp_uurl) > 0) {
		ret = snprintf(dst, size, "[K]: %s [data: %d] -- [U]: %s [data: %d]",
				tmp_urls, kdata_port, tmp_uurl, udata_port);
	} else {
		ret = snprintf(dst, size, "%s [data: %d]", tmp_urls, kdata_port);
	}

error:
	return ret;
}

/*
 * Fill lttng_channel array of all channels.
 */
static void list_lttng_channels(int domain, struct ltt_session *session,
		struct lttng_channel *channels)
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
			switch (uchan->attr.output) {
			case LTTNG_UST_MMAP:
			default:
				channels[i].attr.output = LTTNG_EVENT_MMAP;
				break;
			}
			i++;
		}
		break;
	}
	default:
		break;
	}
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

	nb_event += lttng_ht_get_count(uchan->events);

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
		goto end;
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

		switch (event->event->instrumentation) {
		case LTTNG_KERNEL_TRACEPOINT:
			(*events)[i].type = LTTNG_EVENT_TRACEPOINT;
			break;
		case LTTNG_KERNEL_KPROBE:
		case LTTNG_KERNEL_KRETPROBE:
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
		struct lttng_uri *uri, int domain, const char *session_name)
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

		/* Set URI into consumer output object */
		ret = consumer_set_network_uri(consumer, uri);
		if (ret < 0) {
			ret = LTTNG_ERR_FATAL;
			goto error;
		} else if (ret == 1) {
			/*
			 * URI was the same in the consumer so we do not append the subdir
			 * again so to not duplicate output dir.
			 */
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

	if (session->consumer_fds_sent == 0 && session->consumer != NULL) {
		cds_lfht_for_each_entry(session->consumer->socks->ht, &iter.iter,
				socket, node.node) {
			/* Code flow error */
			assert(socket->fd >= 0);

			pthread_mutex_lock(socket->lock);
			ret = kernel_consumer_send_session(socket->fd, session);
			pthread_mutex_unlock(socket->lock);
			if (ret < 0) {
				ret = LTTNG_ERR_KERN_CONSUMER_FAIL;
				goto error;
			}
		}
	}

error:
	return ret;
}

/*
 * Create a socket to the relayd using the URI.
 *
 * On success, the relayd_sock pointer is set to the created socket.
 * Else, it's stays untouched and a lttcomm error code is returned.
 */
static int create_connect_relayd(struct consumer_output *output,
		const char *session_name, struct lttng_uri *uri,
		struct lttcomm_sock **relayd_sock)
{
	int ret;
	struct lttcomm_sock *sock;

	/* Create socket object from URI */
	sock = lttcomm_alloc_sock_from_uri(uri);
	if (sock == NULL) {
		ret = LTTNG_ERR_FATAL;
		goto error;
	}

	ret = lttcomm_create_sock(sock);
	if (ret < 0) {
		ret = LTTNG_ERR_FATAL;
		goto error;
	}

	/* Connect to relayd so we can proceed with a session creation. */
	ret = relayd_connect(sock);
	if (ret < 0) {
		ERR("Unable to reach lttng-relayd");
		ret = LTTNG_ERR_RELAYD_CONNECT_FAIL;
		goto free_sock;
	}

	/* Create socket for control stream. */
	if (uri->stype == LTTNG_STREAM_CONTROL) {
		DBG3("Creating relayd stream socket from URI");

		/* Check relayd version */
		ret = relayd_version_check(sock, RELAYD_VERSION_COMM_MAJOR,
				RELAYD_VERSION_COMM_MINOR);
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

	*relayd_sock = sock;

	return LTTNG_OK;

close_sock:
	if (sock) {
		(void) relayd_close(sock);
	}
free_sock:
	if (sock) {
		lttcomm_destroy_sock(sock);
	}
error:
	return ret;
}

/*
 * Connect to the relayd using URI and send the socket to the right consumer.
 */
static int send_consumer_relayd_socket(int domain, struct ltt_session *session,
		struct lttng_uri *relayd_uri, struct consumer_output *consumer,
		int consumer_fd)
{
	int ret;
	struct lttcomm_sock *sock = NULL;

	/* Set the network sequence index if not set. */
	if (consumer->net_seq_index == -1) {
		/*
		 * Increment net_seq_idx because we are about to transfer the
		 * new relayd socket to the consumer.
		 */
		uatomic_inc(&relayd_net_seq_idx);
		/* Assign unique key so the consumer can match streams */
		uatomic_set(&consumer->net_seq_index,
				uatomic_read(&relayd_net_seq_idx));
	}

	/* Connect to relayd and make version check if uri is the control. */
	ret = create_connect_relayd(consumer, session->name, relayd_uri, &sock);
	if (ret != LTTNG_OK) {
		goto close_sock;
	}

	/* If the control socket is connected, network session is ready */
	if (relayd_uri->stype == LTTNG_STREAM_CONTROL) {
		session->net_handle = 1;
	}

	/* Send relayd socket to consumer. */
	ret = consumer_send_relayd_socket(consumer_fd, sock,
			consumer, relayd_uri->stype);
	if (ret < 0) {
		ret = LTTNG_ERR_ENABLE_CONSUMER_FAIL;
		goto close_sock;
	}

	/* Flag that the corresponding socket was sent. */
	if (relayd_uri->stype == LTTNG_STREAM_CONTROL) {
		consumer->dst.net.control_sock_sent = 1;
	} else if (relayd_uri->stype == LTTNG_STREAM_DATA) {
		consumer->dst.net.data_sock_sent = 1;
	}

	ret = LTTNG_OK;

	/*
	 * Close socket which was dup on the consumer side. The session daemon does
	 * NOT keep track of the relayd socket(s) once transfer to the consumer.
	 */

close_sock:
	if (sock) {
		(void) relayd_close(sock);
		lttcomm_destroy_sock(sock);
	}

	return ret;
}

/*
 * Send both relayd sockets to a specific consumer and domain.  This is a
 * helper function to facilitate sending the information to the consumer for a
 * session.
 */
static int send_consumer_relayd_sockets(int domain,
		struct ltt_session *session, struct consumer_output *consumer, int fd)
{
	int ret = LTTNG_OK;

	assert(session);
	assert(consumer);

	/* Sending control relayd socket. */
	if (!consumer->dst.net.control_sock_sent) {
		ret = send_consumer_relayd_socket(domain, session,
				&consumer->dst.net.control, consumer, fd);
		if (ret != LTTNG_OK) {
			goto error;
		}
	}

	/* Sending data relayd socket. */
	if (!consumer->dst.net.data_sock_sent) {
		ret = send_consumer_relayd_socket(domain, session,
				&consumer->dst.net.data, consumer, fd);
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
static int setup_relayd(struct ltt_session *session)
{
	int ret = LTTNG_OK;
	struct ltt_ust_session *usess;
	struct ltt_kernel_session *ksess;
	struct consumer_socket *socket;
	struct lttng_ht_iter iter;

	assert(session);

	usess = session->ust_session;
	ksess = session->kernel_session;

	DBG2("Setting relayd for session %s", session->name);

	if (usess && usess->consumer && usess->consumer->type == CONSUMER_DST_NET
			&& usess->consumer->enabled) {
		/* For each consumer socket, send relayd sockets */
		cds_lfht_for_each_entry(usess->consumer->socks->ht, &iter.iter,
				socket, node.node) {
			/* Code flow error */
			assert(socket->fd >= 0);

			pthread_mutex_lock(socket->lock);
			ret = send_consumer_relayd_sockets(LTTNG_DOMAIN_UST, session,
					usess->consumer, socket->fd);
			pthread_mutex_unlock(socket->lock);
			if (ret != LTTNG_OK) {
				goto error;
			}
		}
	}

	if (ksess && ksess->consumer && ksess->consumer->type == CONSUMER_DST_NET
			&& ksess->consumer->enabled) {
		cds_lfht_for_each_entry(ksess->consumer->socks->ht, &iter.iter,
				socket, node.node) {
			/* Code flow error */
			assert(socket->fd >= 0);

			pthread_mutex_lock(socket->lock);
			ret = send_consumer_relayd_sockets(LTTNG_DOMAIN_KERNEL, session,
					ksess->consumer, socket->fd);
			pthread_mutex_unlock(socket->lock);
			if (ret != LTTNG_OK) {
				goto error;
			}
		}
	}

error:
	return ret;
}

/*
 * Command LTTNG_DISABLE_CHANNEL processed by the client thread.
 */
int cmd_disable_channel(struct ltt_session *session, int domain,
		char *channel_name)
{
	int ret;
	struct ltt_ust_session *usess;

	usess = session->ust_session;

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

		ret = channel_ust_disable(usess, domain, uchan);
		if (ret != LTTNG_OK) {
			goto error;
		}
		break;
	}
#if 0
	case LTTNG_DOMAIN_UST_PID_FOLLOW_CHILDREN:
	case LTTNG_DOMAIN_UST_EXEC_NAME:
	case LTTNG_DOMAIN_UST_PID:
#endif
	default:
		ret = LTTNG_ERR_UNKNOWN_DOMAIN;
		goto error;
	}

	ret = LTTNG_OK;

error:
	return ret;
}

/*
 * Command LTTNG_ENABLE_CHANNEL processed by the client thread.
 *
 * The wpipe arguments is used as a notifier for the kernel thread.
 */
int cmd_enable_channel(struct ltt_session *session,
		int domain, struct lttng_channel *attr, int wpipe)
{
	int ret;
	struct ltt_ust_session *usess = session->ust_session;
	struct lttng_ht *chan_ht;

	assert(session);
	assert(attr);

	DBG("Enabling channel %s for session %s", attr->name, session->name);

	switch (domain) {
	case LTTNG_DOMAIN_KERNEL:
	{
		struct ltt_kernel_channel *kchan;

		/* Mandatory for a kernel channel. */
		assert(wpipe > 0);

		kchan = trace_kernel_get_channel_by_name(attr->name,
				session->kernel_session);
		if (kchan == NULL) {
			ret = channel_kernel_create(session->kernel_session, attr, wpipe);
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
	{
		struct ltt_ust_channel *uchan;

		chan_ht = usess->domain_global.channels;

		uchan = trace_ust_find_channel_by_name(chan_ht, attr->name);
		if (uchan == NULL) {
			ret = channel_ust_create(usess, domain, attr);
		} else {
			ret = channel_ust_enable(usess, domain, uchan);
		}
		break;
	}
#if 0
	case LTTNG_DOMAIN_UST_PID_FOLLOW_CHILDREN:
	case LTTNG_DOMAIN_UST_EXEC_NAME:
	case LTTNG_DOMAIN_UST_PID:
#endif
	default:
		ret = LTTNG_ERR_UNKNOWN_DOMAIN;
		goto error;
	}

error:
	return ret;
}


/*
 * Command LTTNG_DISABLE_EVENT processed by the client thread.
 */
int cmd_disable_event(struct ltt_session *session, int domain,
		char *channel_name, char *event_name)
{
	int ret;

	switch (domain) {
	case LTTNG_DOMAIN_KERNEL:
	{
		struct ltt_kernel_channel *kchan;
		struct ltt_kernel_session *ksess;

		ksess = session->kernel_session;

		kchan = trace_kernel_get_channel_by_name(channel_name, ksess);
		if (kchan == NULL) {
			ret = LTTNG_ERR_KERN_CHAN_NOT_FOUND;
			goto error;
		}

		ret = event_kernel_disable_tracepoint(ksess, kchan, event_name);
		if (ret != LTTNG_OK) {
			goto error;
		}

		kernel_wait_quiescent(kernel_tracer_fd);
		break;
	}
	case LTTNG_DOMAIN_UST:
	{
		struct ltt_ust_channel *uchan;
		struct ltt_ust_session *usess;

		usess = session->ust_session;

		uchan = trace_ust_find_channel_by_name(usess->domain_global.channels,
				channel_name);
		if (uchan == NULL) {
			ret = LTTNG_ERR_UST_CHAN_NOT_FOUND;
			goto error;
		}

		ret = event_ust_disable_tracepoint(usess, domain, uchan, event_name);
		if (ret != LTTNG_OK) {
			goto error;
		}

		DBG3("Disable UST event %s in channel %s completed", event_name,
				channel_name);
		break;
	}
#if 0
	case LTTNG_DOMAIN_UST_EXEC_NAME:
	case LTTNG_DOMAIN_UST_PID:
	case LTTNG_DOMAIN_UST_PID_FOLLOW_CHILDREN:
#endif
	default:
		ret = LTTNG_ERR_UND;
		goto error;
	}

	ret = LTTNG_OK;

error:
	return ret;
}

/*
 * Command LTTNG_DISABLE_ALL_EVENT processed by the client thread.
 */
int cmd_disable_event_all(struct ltt_session *session, int domain,
		char *channel_name)
{
	int ret;

	switch (domain) {
	case LTTNG_DOMAIN_KERNEL:
	{
		struct ltt_kernel_session *ksess;
		struct ltt_kernel_channel *kchan;

		ksess = session->kernel_session;

		kchan = trace_kernel_get_channel_by_name(channel_name, ksess);
		if (kchan == NULL) {
			ret = LTTNG_ERR_KERN_CHAN_NOT_FOUND;
			goto error;
		}

		ret = event_kernel_disable_all(ksess, kchan);
		if (ret != LTTNG_OK) {
			goto error;
		}

		kernel_wait_quiescent(kernel_tracer_fd);
		break;
	}
	case LTTNG_DOMAIN_UST:
	{
		struct ltt_ust_session *usess;
		struct ltt_ust_channel *uchan;

		usess = session->ust_session;

		uchan = trace_ust_find_channel_by_name(usess->domain_global.channels,
				channel_name);
		if (uchan == NULL) {
			ret = LTTNG_ERR_UST_CHAN_NOT_FOUND;
			goto error;
		}

		ret = event_ust_disable_all_tracepoints(usess, domain, uchan);
		if (ret != 0) {
			goto error;
		}

		DBG3("Disable all UST events in channel %s completed", channel_name);

		break;
	}
#if 0
	case LTTNG_DOMAIN_UST_EXEC_NAME:
	case LTTNG_DOMAIN_UST_PID:
	case LTTNG_DOMAIN_UST_PID_FOLLOW_CHILDREN:
#endif
	default:
		ret = LTTNG_ERR_UND;
		goto error;
	}

	ret = LTTNG_OK;

error:
	return ret;
}

/*
 * Command LTTNG_ADD_CONTEXT processed by the client thread.
 */
int cmd_add_context(struct ltt_session *session, int domain,
		char *channel_name, char *event_name, struct lttng_event_context *ctx)
{
	int ret;

	switch (domain) {
	case LTTNG_DOMAIN_KERNEL:
		/* Add kernel context to kernel tracer */
		ret = context_kernel_add(session->kernel_session, ctx,
				event_name, channel_name);
		if (ret != LTTNG_OK) {
			goto error;
		}
		break;
	case LTTNG_DOMAIN_UST:
	{
		struct ltt_ust_session *usess = session->ust_session;

		assert(usess);

		ret = context_ust_add(usess, domain, ctx, event_name, channel_name);
		if (ret != LTTNG_OK) {
			goto error;
		}
		break;
	}
#if 0
	case LTTNG_DOMAIN_UST_EXEC_NAME:
	case LTTNG_DOMAIN_UST_PID:
	case LTTNG_DOMAIN_UST_PID_FOLLOW_CHILDREN:
#endif
	default:
		ret = LTTNG_ERR_UND;
		goto error;
	}

	ret = LTTNG_OK;

error:
	return ret;
}

/*
 * Command LTTNG_SET_FILTER processed by the client thread.
 */
int cmd_set_filter(struct ltt_session *session, int domain,
		char *channel_name, char *event_name,
		struct lttng_filter_bytecode *bytecode)
{
	int ret;

	switch (domain) {
	case LTTNG_DOMAIN_KERNEL:
		ret = LTTNG_ERR_FATAL;
		break;
	case LTTNG_DOMAIN_UST:
	{
		struct ltt_ust_session *usess = session->ust_session;

		ret = filter_ust_set(usess, domain, bytecode, event_name, channel_name);
		if (ret != LTTNG_OK) {
			goto error;
		}
		break;
	}
#if 0
	case LTTNG_DOMAIN_UST_EXEC_NAME:
	case LTTNG_DOMAIN_UST_PID:
	case LTTNG_DOMAIN_UST_PID_FOLLOW_CHILDREN:
#endif
	default:
		ret = LTTNG_ERR_UND;
		goto error;
	}

	ret = LTTNG_OK;

error:
	return ret;

}


/*
 * Command LTTNG_ENABLE_EVENT processed by the client thread.
 */
int cmd_enable_event(struct ltt_session *session, int domain,
		char *channel_name, struct lttng_event *event, int wpipe)
{
	int ret;
	struct lttng_channel *attr;

	assert(session);
	assert(event);
	assert(channel_name);

	switch (domain) {
	case LTTNG_DOMAIN_KERNEL:
	{
		struct ltt_kernel_channel *kchan;

		kchan = trace_kernel_get_channel_by_name(channel_name,
				session->kernel_session);
		if (kchan == NULL) {
			attr = channel_new_default_attr(domain);
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
		}

		/* Get the newly created kernel channel pointer */
		kchan = trace_kernel_get_channel_by_name(channel_name,
				session->kernel_session);
		if (kchan == NULL) {
			/* This sould not happen... */
			ret = LTTNG_ERR_FATAL;
			goto error;
		}

		ret = event_kernel_enable_tracepoint(session->kernel_session, kchan,
				event);
		if (ret != LTTNG_OK) {
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

		/* Get channel from global UST domain */
		uchan = trace_ust_find_channel_by_name(usess->domain_global.channels,
				channel_name);
		if (uchan == NULL) {
			/* Create default channel */
			attr = channel_new_default_attr(domain);
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

		/* At this point, the session and channel exist on the tracer */
		ret = event_ust_enable_tracepoint(usess, domain, uchan, event);
		if (ret != LTTNG_OK) {
			goto error;
		}
		break;
	}
#if 0
	case LTTNG_DOMAIN_UST_EXEC_NAME:
	case LTTNG_DOMAIN_UST_PID:
	case LTTNG_DOMAIN_UST_PID_FOLLOW_CHILDREN:
#endif
	default:
		ret = LTTNG_ERR_UND;
		goto error;
	}

	ret = LTTNG_OK;

error:
	return ret;
}

/*
 * Command LTTNG_ENABLE_ALL_EVENT processed by the client thread.
 */
int cmd_enable_event_all(struct ltt_session *session, int domain,
		char *channel_name, int event_type, int wpipe)
{
	int ret;
	struct lttng_channel *attr;

	assert(session);
	assert(channel_name);

	switch (domain) {
	case LTTNG_DOMAIN_KERNEL:
	{
		struct ltt_kernel_channel *kchan;

		assert(session->kernel_session);

		kchan = trace_kernel_get_channel_by_name(channel_name,
				session->kernel_session);
		if (kchan == NULL) {
			/* Create default channel */
			attr = channel_new_default_attr(domain);
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

			/* Get the newly created kernel channel pointer */
			kchan = trace_kernel_get_channel_by_name(channel_name,
					session->kernel_session);
			assert(kchan);
		}

		switch (event_type) {
		case LTTNG_EVENT_SYSCALL:
			ret = event_kernel_enable_all_syscalls(session->kernel_session,
					kchan, kernel_tracer_fd);
			break;
		case LTTNG_EVENT_TRACEPOINT:
			/*
			 * This call enables all LTTNG_KERNEL_TRACEPOINTS and
			 * events already registered to the channel.
			 */
			ret = event_kernel_enable_all_tracepoints(session->kernel_session,
					kchan, kernel_tracer_fd);
			break;
		case LTTNG_EVENT_ALL:
			/* Enable syscalls and tracepoints */
			ret = event_kernel_enable_all(session->kernel_session,
					kchan, kernel_tracer_fd);
			break;
		default:
			ret = LTTNG_ERR_KERN_ENABLE_FAIL;
			goto error;
		}

		/* Manage return value */
		if (ret != LTTNG_OK) {
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

		/* Get channel from global UST domain */
		uchan = trace_ust_find_channel_by_name(usess->domain_global.channels,
				channel_name);
		if (uchan == NULL) {
			/* Create default channel */
			attr = channel_new_default_attr(domain);
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

		/* At this point, the session and channel exist on the tracer */

		switch (event_type) {
		case LTTNG_EVENT_ALL:
		case LTTNG_EVENT_TRACEPOINT:
			ret = event_ust_enable_all_tracepoints(usess, domain, uchan);
			if (ret != LTTNG_OK) {
				goto error;
			}
			break;
		default:
			ret = LTTNG_ERR_UST_ENABLE_FAIL;
			goto error;
		}

		/* Manage return value */
		if (ret != LTTNG_OK) {
			goto error;
		}

		break;
	}
#if 0
	case LTTNG_DOMAIN_UST_EXEC_NAME:
	case LTTNG_DOMAIN_UST_PID:
	case LTTNG_DOMAIN_UST_PID_FOLLOW_CHILDREN:
#endif
	default:
		ret = LTTNG_ERR_UND;
		goto error;
	}

	ret = LTTNG_OK;

error:
	return ret;
}


/*
 * Command LTTNG_LIST_TRACEPOINTS processed by the client thread.
 */
ssize_t cmd_list_tracepoints(int domain, struct lttng_event **events)
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
ssize_t cmd_list_tracepoint_fields(int domain,
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

/*
 * Command LTTNG_START_TRACE processed by the client thread.
 */
int cmd_start_trace(struct ltt_session *session)
{
	int ret;
	struct ltt_kernel_session *ksession;
	struct ltt_ust_session *usess;
	struct ltt_kernel_channel *kchan;

	assert(session);

	/* Ease our life a bit ;) */
	ksession = session->kernel_session;
	usess = session->ust_session;

	if (session->enabled) {
		/* Already started. */
		ret = LTTNG_ERR_TRACE_ALREADY_STARTED;
		goto error;
	}

	session->enabled = 1;

	ret = setup_relayd(session);
	if (ret != LTTNG_OK) {
		ERR("Error setting up relayd for session %s", session->name);
		goto error;
	}

	/* Kernel tracing */
	if (ksession != NULL) {
		/* Open kernel metadata */
		if (ksession->metadata == NULL) {
			ret = kernel_open_metadata(ksession);
			if (ret < 0) {
				ret = LTTNG_ERR_KERN_META_FAIL;
				goto error;
			}
		}

		/* Open kernel metadata stream */
		if (ksession->metadata_stream_fd < 0) {
			ret = kernel_open_metadata_stream(ksession);
			if (ret < 0) {
				ERR("Kernel create metadata stream failed");
				ret = LTTNG_ERR_KERN_STREAM_FAIL;
				goto error;
			}
		}

		/* For each channel */
		cds_list_for_each_entry(kchan, &ksession->channel_list.head, list) {
			if (kchan->stream_count == 0) {
				ret = kernel_open_channel_stream(kchan);
				if (ret < 0) {
					ret = LTTNG_ERR_KERN_STREAM_FAIL;
					goto error;
				}
				/* Update the stream global counter */
				ksession->stream_count_global += ret;
			}
		}

		/* Setup kernel consumer socket and send fds to it */
		ret = init_kernel_tracing(ksession);
		if (ret < 0) {
			ret = LTTNG_ERR_KERN_START_FAIL;
			goto error;
		}

		/* This start the kernel tracing */
		ret = kernel_start_session(ksession);
		if (ret < 0) {
			ret = LTTNG_ERR_KERN_START_FAIL;
			goto error;
		}

		/* Quiescent wait after starting trace */
		kernel_wait_quiescent(kernel_tracer_fd);
	}

	/* Flag session that trace should start automatically */
	if (usess) {
		usess->start_trace = 1;

		ret = ust_app_start_trace_all(usess);
		if (ret < 0) {
			ret = LTTNG_ERR_UST_START_FAIL;
			goto error;
		}
	}

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

	if (!session->enabled) {
		ret = LTTNG_ERR_TRACE_ALREADY_STOPPED;
		goto error;
	}

	session->enabled = 0;

	/* Kernel tracer */
	if (ksession) {
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
	}

	if (usess) {
		usess->start_trace = 0;

		ret = ust_app_stop_trace_all(usess);
		if (ret < 0) {
			ret = LTTNG_ERR_UST_STOP_FAIL;
			goto error;
		}
	}

	ret = LTTNG_OK;

error:
	return ret;
}

/*
 * Command LTTNG_SET_CONSUMER_URI processed by the client thread.
 */
int cmd_set_consumer_uri(int domain, struct ltt_session *session,
		size_t nb_uri, struct lttng_uri *uris)
{
	int ret, i;
	struct ltt_kernel_session *ksess = session->kernel_session;
	struct ltt_ust_session *usess = session->ust_session;
	struct consumer_output *consumer = NULL;

	assert(session);
	assert(uris);
	assert(nb_uri > 0);

	/* Can't enable consumer after session started. */
	if (session->enabled) {
		ret = LTTNG_ERR_TRACE_ALREADY_STARTED;
		goto error;
	}

	/*
	 * This case switch makes sure the domain session has a temporary consumer
	 * so the URL can be set.
	 */
	switch (domain) {
	case 0:
		/* Code flow error. A session MUST always have a consumer object */
		assert(session->consumer);
		/*
		 * The URL will be added to the tracing session consumer instead of a
		 * specific domain consumer.
		 */
		consumer = session->consumer;
		break;
	case LTTNG_DOMAIN_KERNEL:
		/* Code flow error if we don't have a kernel session here. */
		assert(ksess);

		/* Create consumer output if none exists */
		consumer = ksess->tmp_consumer;
		if (consumer == NULL) {
			consumer = consumer_copy_output(ksess->consumer);
			if (consumer == NULL) {
				ret = LTTNG_ERR_FATAL;
				goto error;
			}
			/* Trash the consumer subdir, we are about to set a new one. */
			memset(consumer->subdir, 0, sizeof(consumer->subdir));
			ksess->tmp_consumer = consumer;
		}

		break;
	case LTTNG_DOMAIN_UST:
		/* Code flow error if we don't have a kernel session here. */
		assert(usess);

		/* Create consumer output if none exists */
		consumer = usess->tmp_consumer;
		if (consumer == NULL) {
			consumer = consumer_copy_output(usess->consumer);
			if (consumer == NULL) {
				ret = LTTNG_ERR_FATAL;
				goto error;
			}
			/* Trash the consumer subdir, we are about to set a new one. */
			memset(consumer->subdir, 0, sizeof(consumer->subdir));
			usess->tmp_consumer = consumer;
		}

		break;
	}

	for (i = 0; i < nb_uri; i++) {
		struct consumer_socket *socket;
		struct lttng_ht_iter iter;

		ret = add_uri_to_consumer(consumer, &uris[i], domain, session->name);
		if (ret < 0) {
			goto error;
		}

		/*
		 * Don't send relayd socket if URI is NOT remote or if the relayd
		 * socket for the session was already sent.
		 */
		if (uris[i].dtype == LTTNG_DST_PATH ||
				(uris[i].stype == LTTNG_STREAM_CONTROL &&
				consumer->dst.net.control_sock_sent) ||
				(uris[i].stype == LTTNG_STREAM_DATA &&
				consumer->dst.net.data_sock_sent)) {
			continue;
		}

		/* Try to send relayd URI to the consumer if exist. */
		rcu_read_lock();
		cds_lfht_for_each_entry(consumer->socks->ht, &iter.iter,
				socket, node.node) {

			/* A socket in the HT should never have a negative fd */
			assert(socket->fd >= 0);

			pthread_mutex_lock(socket->lock);
			ret = send_consumer_relayd_socket(domain, session, &uris[i],
					consumer, socket->fd);
			pthread_mutex_unlock(socket->lock);
			if (ret != LTTNG_OK) {
				rcu_read_unlock();
				goto error;
			}
		}
		rcu_read_unlock();
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
		size_t nb_uri, lttng_sock_cred *creds)
{
	int ret;
	char *path = NULL;
	struct ltt_session *session;

	assert(name);

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
	ret = session_create(name, path, LTTNG_SOCK_GET_UID_CRED(creds),
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

	/* Create default consumer output for the session not yet created. */
	session->consumer = consumer_create_output(CONSUMER_DST_LOCAL);
	if (session->consumer == NULL) {
		ret = LTTNG_ERR_FATAL;
		goto consumer_error;
	}

	/*
	 * This means that the lttng_create_session call was called with the _path_
	 * argument set to NULL.
	 */
	if (uris == NULL) {
		/*
		 * At this point, we'll skip the consumer URI setup and create a
		 * session with a NULL path which will flag the session to NOT spawn a
		 * consumer.
		 */
		DBG("Create session %s with NO uri, skipping consumer setup", name);
		goto end;
	}

	session->start_consumer = 1;

	ret = cmd_set_consumer_uri(0, session, nb_uri, uris);
	if (ret != LTTNG_OK) {
		goto consumer_error;
	}

	session->consumer->enabled = 1;

end:
	return LTTNG_OK;

consumer_error:
	session_destroy(session);
session_error:
find_error:
	return ret;
}

/*
 * Command LTTNG_DESTROY_SESSION processed by the client thread.
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
int cmd_calibrate(int domain, struct lttng_calibrate *calibrate)
{
	int ret;

	switch (domain) {
	case LTTNG_DOMAIN_KERNEL:
	{
		struct lttng_kernel_calibrate kcalibrate;

		kcalibrate.type = calibrate->type;
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

		ucalibrate.type = calibrate->type;
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
int cmd_register_consumer(struct ltt_session *session, int domain,
		const char *sock_path, struct consumer_data *cdata)
{
	int ret, sock;
	struct consumer_socket *socket;

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

		socket = consumer_allocate_socket(sock);
		if (socket == NULL) {
			ret = LTTNG_ERR_FATAL;
			close(sock);
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

	ret = LTTNG_OK;

error:
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

	if (session->kernel_session != NULL) {
		DBG3("Listing domains found kernel domain");
		nb_dom++;
	}

	if (session->ust_session != NULL) {
		DBG3("Listing domains found UST global domain");
		nb_dom++;
	}

	*domains = zmalloc(nb_dom * sizeof(struct lttng_domain));
	if (*domains == NULL) {
		ret = LTTNG_ERR_FATAL;
		goto error;
	}

	if (session->kernel_session != NULL) {
		(*domains)[index].type = LTTNG_DOMAIN_KERNEL;
		index++;
	}

	if (session->ust_session != NULL) {
		(*domains)[index].type = LTTNG_DOMAIN_UST;
		index++;
	}

	return nb_dom;

error:
	/* Return negative value to differentiate return code */
	return -ret;
}


/*
 * Command LTTNG_LIST_CHANNELS processed by the client thread.
 */
ssize_t cmd_list_channels(int domain, struct ltt_session *session,
		struct lttng_channel **channels)
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
			nb_chan = lttng_ht_get_count(
					session->ust_session->domain_global.channels);
		}
		DBG3("Number of UST global channels %zd", nb_chan);
		if (nb_chan <= 0) {
			ret = LTTNG_ERR_UST_CHAN_NOT_FOUND;
		}
		break;
	default:
		*channels = NULL;
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
	} else {
		*channels = NULL;
		/* Ret value was set in the domain switch case */
		goto error;
	}

	return nb_chan;

error:
	/* Return negative value to differentiate return code */
	return -ret;
}

/*
 * Command LTTNG_LIST_EVENTS processed by the client thread.
 */
ssize_t cmd_list_events(int domain, struct ltt_session *session,
		char *channel_name, struct lttng_event **events)
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
					sizeof(session[i].path), session);
		} else {
			ret = snprintf(sessions[i].path, sizeof(session[i].path), "%s",
					session->consumer->dst.trace_path);
		}
		if (ret < 0) {
			PERROR("snprintf session path");
			continue;
		}

		strncpy(sessions[i].name, session->name, NAME_MAX);
		sessions[i].name[NAME_MAX - 1] = '\0';
		sessions[i].enabled = session->enabled;
		i++;
	}
}

/*
 * Command LTTNG_DISABLE_CONSUMER processed by the client thread.
 */
int cmd_disable_consumer(int domain, struct ltt_session *session)
{
	int ret;
	struct ltt_kernel_session *ksess = session->kernel_session;
	struct ltt_ust_session *usess = session->ust_session;
	struct consumer_output *consumer;

	assert(session);

	if (session->enabled) {
		/* Can't disable consumer on an already started session */
		ret = LTTNG_ERR_TRACE_ALREADY_STARTED;
		goto error;
	}

	if (!session->start_consumer) {
		ret = LTTNG_ERR_NO_CONSUMER;
		goto error;
	}

	switch (domain) {
	case 0:
		DBG("Disable tracing session %s consumer", session->name);
		consumer = session->consumer;
		break;
	case LTTNG_DOMAIN_KERNEL:
		/* Code flow error if we don't have a kernel session here. */
		assert(ksess);

		DBG("Disabling kernel consumer");
		consumer = ksess->consumer;

		break;
	case LTTNG_DOMAIN_UST:
		/* Code flow error if we don't have a UST session here. */
		assert(usess);

		DBG("Disabling UST consumer");
		consumer = usess->consumer;

		break;
	default:
		ret = LTTNG_ERR_UNKNOWN_DOMAIN;
		goto error;
	}

	if (consumer) {
		consumer->enabled = 0;
		/* Success at this point */
		ret = LTTNG_OK;
	} else {
		ret = LTTNG_ERR_NO_CONSUMER;
	}

error:
	return ret;
}

/*
 * Command LTTNG_ENABLE_CONSUMER processed by the client thread.
 */
int cmd_enable_consumer(int domain, struct ltt_session *session)
{
	int ret;
	struct ltt_kernel_session *ksess = session->kernel_session;
	struct ltt_ust_session *usess = session->ust_session;
	struct consumer_output *consumer = NULL;

	assert(session);

	/* Can't enable consumer after session started. */
	if (session->enabled) {
		ret = LTTNG_ERR_TRACE_ALREADY_STARTED;
		goto error;
	}

	switch (domain) {
	case 0:
		assert(session->consumer);
		consumer = session->consumer;
		break;
	case LTTNG_DOMAIN_KERNEL:
		/* Code flow error if we don't have a kernel session here. */
		assert(ksess);

		/*
		 * Check if we have already sent fds to the consumer. In that case,
		 * the enable-consumer command can't be used because a start trace
		 * had previously occured.
		 */
		if (ksess->consumer_fds_sent) {
			ret = LTTNG_ERR_ENABLE_CONSUMER_FAIL;
			goto error;
		}

		consumer = ksess->tmp_consumer;
		if (consumer == NULL) {
			ret = LTTNG_OK;
			/* No temp. consumer output exists. Using the current one. */
			DBG3("No temporary consumer. Using default");
			consumer = ksess->consumer;
			goto error;
		}

		switch (consumer->type) {
		case CONSUMER_DST_LOCAL:
			DBG2("Consumer output is local. Creating directory(ies)");

			/* Create directory(ies) */
			ret = run_as_mkdir_recursive(consumer->dst.trace_path,
					S_IRWXU | S_IRWXG, session->uid, session->gid);
			if (ret < 0) {
				if (ret != -EEXIST) {
					ERR("Trace directory creation error");
					ret = LTTNG_ERR_FATAL;
					goto error;
				}
			}
			break;
		case CONSUMER_DST_NET:
			DBG2("Consumer output is network. Validating URIs");
			/* Validate if we have both control and data path set. */
			if (!consumer->dst.net.control_isset) {
				ret = LTTNG_ERR_URL_CTRL_MISS;
				goto error;
			}

			if (!consumer->dst.net.data_isset) {
				ret = LTTNG_ERR_URL_DATA_MISS;
				goto error;
			}

			/* Check established network session state */
			if (session->net_handle == 0) {
				ret = LTTNG_ERR_ENABLE_CONSUMER_FAIL;
				ERR("Session network handle is not set on enable-consumer");
				goto error;
			}

			break;
		}

		/*
		 * @session-lock
		 * This is race free for now since the session lock is acquired before
		 * ending up in this function. No other threads can access this kernel
		 * session without this lock hence freeing the consumer output object
		 * is valid.
		 */
		rcu_read_lock();
		/* Destroy current consumer. We are about to replace it */
		consumer_destroy_output(ksess->consumer);
		rcu_read_unlock();
		ksess->consumer = consumer;
		ksess->tmp_consumer = NULL;

		break;
	case LTTNG_DOMAIN_UST:
		/* Code flow error if we don't have a UST session here. */
		assert(usess);

		/*
		 * Check if we have already sent fds to the consumer. In that case,
		 * the enable-consumer command can't be used because a start trace
		 * had previously occured.
		 */
		if (usess->start_trace) {
			ret = LTTNG_ERR_ENABLE_CONSUMER_FAIL;
			goto error;
		}

		consumer = usess->tmp_consumer;
		if (consumer == NULL) {
			ret = LTTNG_OK;
			/* No temp. consumer output exists. Using the current one. */
			DBG3("No temporary consumer. Using default");
			consumer = usess->consumer;
			goto error;
		}

		switch (consumer->type) {
		case CONSUMER_DST_LOCAL:
			DBG2("Consumer output is local. Creating directory(ies)");

			/* Create directory(ies) */
			ret = run_as_mkdir_recursive(consumer->dst.trace_path,
					S_IRWXU | S_IRWXG, session->uid, session->gid);
			if (ret < 0) {
				if (ret != -EEXIST) {
					ERR("Trace directory creation error");
					ret = LTTNG_ERR_FATAL;
					goto error;
				}
			}
			break;
		case CONSUMER_DST_NET:
			DBG2("Consumer output is network. Validating URIs");
			/* Validate if we have both control and data path set. */
			if (!consumer->dst.net.control_isset) {
				ret = LTTNG_ERR_URL_CTRL_MISS;
				goto error;
			}

			if (!consumer->dst.net.data_isset) {
				ret = LTTNG_ERR_URL_DATA_MISS;
				goto error;
			}

			/* Check established network session state */
			if (session->net_handle == 0) {
				ret = LTTNG_ERR_ENABLE_CONSUMER_FAIL;
				DBG2("Session network handle is not set on enable-consumer");
				goto error;
			}

			if (consumer->net_seq_index == -1) {
				ret = LTTNG_ERR_ENABLE_CONSUMER_FAIL;
				DBG2("Network index is not set on the consumer");
				goto error;
			}

			break;
		}

		/*
		 * @session-lock
		 * This is race free for now since the session lock is acquired before
		 * ending up in this function. No other threads can access this kernel
		 * session without this lock hence freeing the consumer output object
		 * is valid.
		 */
		rcu_read_lock();
		/* Destroy current consumer. We are about to replace it */
		consumer_destroy_output(usess->consumer);
		rcu_read_unlock();
		usess->consumer = consumer;
		usess->tmp_consumer = NULL;

		break;
	}

	session->start_consumer = 1;

	/* Enable it */
	if (consumer) {
		consumer->enabled = 1;
		/* Success at this point */
		ret = LTTNG_OK;
	} else {
		/* Should not really happend... */
		ret = LTTNG_ERR_NO_CONSUMER;
	}

error:
	return ret;
}

/*
 * Command LTTNG_DATA_PENDING returning 0 if the data is NOT pending meaning
 * ready for trace analysis (or anykind of reader) or else 1 for pending data.
 */
int cmd_data_pending(struct ltt_session *session)
{
	int ret;
	struct ltt_kernel_session *ksess = session->kernel_session;
	struct ltt_ust_session *usess = session->ust_session;

	assert(session);

	/* Session MUST be stopped to ask for data availability. */
	if (session->enabled) {
		ret = LTTNG_ERR_SESSION_STARTED;
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
 * Init command subsystem.
 */
void cmd_init(void)
{
	/*
	 * Set network sequence index to 1 for streams to match a relayd socket on
	 * the consumer side.
	 */
	uatomic_set(&relayd_net_seq_idx, 1);

	DBG("Command subsystem initialized");
}
