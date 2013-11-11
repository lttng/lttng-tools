/*
 * Copyright (C) 2013 - David Goulet <dgoulet@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define _GNU_SOURCE
#include <assert.h>
#include <urcu/uatomic.h>

#include <common/common.h>
#include <common/sessiond-comm/jul.h>

#include "jul.h"
#include "ust-app.h"
#include "utils.h"

/*
 * URCU delayed JUL event reclaim.
 */
static void destroy_event_jul_rcu(struct rcu_head *head)
{
	struct lttng_ht_node_str *node =
		caa_container_of(head, struct lttng_ht_node_str, head);
	struct jul_event *event =
		caa_container_of(node, struct jul_event, node);

	free(event);
}

/*
 * URCU delayed JUL app reclaim.
 */
static void destroy_app_jul_rcu(struct rcu_head *head)
{
	struct lttng_ht_node_ulong *node =
		caa_container_of(head, struct lttng_ht_node_ulong, head);
	struct jul_app *app =
		caa_container_of(node, struct jul_app, node);

	free(app);
}

/*
 * Communication with Java agent. Send the message header to the given
 * socket in big endian.
 *
 * Return 0 on success or else a negative errno message of sendmsg() op.
 */
static int send_header(struct lttcomm_sock *sock, uint64_t data_size,
		uint32_t cmd, uint32_t cmd_version)
{
	int ret;
	ssize_t size;
	struct lttcomm_jul_hdr msg;

	assert(sock);

	msg.data_size = htobe64(data_size);
	msg.cmd = htobe32(cmd);
	msg.cmd_version = htobe32(cmd_version);

	size = sock->ops->sendmsg(sock, &msg, sizeof(msg), 0);
	if (size < sizeof(msg)) {
		ret = -errno;
		goto error;
	}
	ret = 0;

error:
	return ret;
}

/*
 * Communication call with the Java agent. Send the payload to the given
 * socket. The header MUST be sent prior to this call.
 *
 * Return 0 on success or else a negative errno value of sendmsg() op.
 */
static int send_payload(struct lttcomm_sock *sock, void *data,
		size_t size)
{
	int ret;
	ssize_t len;

	assert(sock);
	assert(data);

	len = sock->ops->sendmsg(sock, data, size, 0);
	if (len < size) {
		ret = -errno;
		goto error;
	}
	ret = 0;

error:
	return ret;
}

/*
 * Communication call with the Java agent. Receive reply from the agent using
 * the given socket.
 *
 * Return 0 on success or else a negative errno value from recvmsg() op.
 */
static int recv_reply(struct lttcomm_sock *sock, void *buf, size_t size)
{
	int ret;
	ssize_t len;

	assert(sock);
	assert(buf);

	len = sock->ops->recvmsg(sock, buf, size, 0);
	if (len < size) {
		ret = -errno;
		goto error;
	}
	ret = 0;

error:
	return ret;
}


/*
 * Internal event listing for a given app. Populate events.
 *
 * Return number of element in the list or else a negative LTTNG_ERR* code.
 * On success, the caller is responsible for freeing the memory
 * allocated for "events".
 */
static ssize_t list_events(struct jul_app *app, struct lttng_event **events)
{
	int ret, i, len = 0, offset = 0;
	uint32_t nb_event;
	size_t data_size;
	struct lttng_event *tmp_events = NULL;
	struct lttcomm_jul_list_reply *reply = NULL;
	struct lttcomm_jul_list_reply_hdr reply_hdr;

	assert(app);
	assert(app->sock);
	assert(events);

	DBG2("JUL listing events for app pid: %d and socket %d", app->pid,
			app->sock->fd);

	ret = send_header(app->sock, 0, JUL_CMD_LIST, 0);
	if (ret < 0) {
		goto error_io;
	}

	/* Get list header so we know how much we'll receive. */
	ret = recv_reply(app->sock, &reply_hdr, sizeof(reply_hdr));
	if (ret < 0) {
		goto error_io;
	}

	switch (be32toh(reply_hdr.ret_code)) {
	case JUL_RET_CODE_SUCCESS:
		data_size = be32toh(reply_hdr.data_size) + sizeof(*reply);
		break;
	default:
		ERR("Java agent returned an unknown code: %" PRIu32,
				be32toh(reply_hdr.ret_code));
		ret = LTTNG_ERR_FATAL;
		goto error;
	}

	reply = zmalloc(data_size);
	if (!reply) {
		ret = LTTNG_ERR_NOMEM;
		goto error;
	}

	/* Get the list with the appropriate data size. */
	ret = recv_reply(app->sock, reply, data_size);
	if (ret < 0) {
		goto error_io;
	}

	nb_event = be32toh(reply->nb_event);
	tmp_events = zmalloc(sizeof(*tmp_events) * nb_event);
	if (!tmp_events) {
		ret = LTTNG_ERR_NOMEM;
		goto error;
	}

	for (i = 0; i < nb_event; i++) {
		offset += len;
		strncpy(tmp_events[i].name, reply->payload + offset,
				sizeof(tmp_events[i].name));
		tmp_events[i].pid = app->pid;
		tmp_events[i].enabled = -1;
		len = strlen(reply->payload + offset) + 1;
	}

	*events = tmp_events;

	free(reply);
	return nb_event;

error_io:
	ret = LTTNG_ERR_UST_LIST_FAIL;
error:
	free(reply);
	free(tmp_events);
	return -ret;

}

/*
 * Internal enable JUL event on a JUL application. This function
 * communicates with the Java agent to enable a given event (Logger name).
 *
 * Return LTTNG_OK on success or else a LTTNG_ERR* code.
 */
static int enable_event(struct jul_app *app, struct jul_event *event)
{
	int ret;
	uint64_t data_size;
	struct lttcomm_jul_enable msg;
	struct lttcomm_jul_generic_reply reply;

	assert(app);
	assert(app->sock);
	assert(event);

	DBG2("JUL enabling event %s for app pid: %d and socket %d", event->name,
			app->pid, app->sock->fd);

	data_size = sizeof(msg);

	ret = send_header(app->sock, data_size, JUL_CMD_ENABLE, 0);
	if (ret < 0) {
		goto error_io;
	}

	strncpy(msg.name, event->name, sizeof(msg.name));
	ret = send_payload(app->sock, &msg, sizeof(msg));
	if (ret < 0) {
		goto error_io;
	}

	ret = recv_reply(app->sock, &reply, sizeof(reply));
	if (ret < 0) {
		goto error_io;
	}

	switch (be32toh(reply.ret_code)) {
	case JUL_RET_CODE_SUCCESS:
		break;
	case JUL_RET_CODE_UNKNOWN_NAME:
		ret = LTTNG_ERR_UST_EVENT_NOT_FOUND;
		goto error;
	default:
		ERR("Java agent returned an unknown code: %" PRIu32,
				be32toh(reply.ret_code));
		ret = LTTNG_ERR_FATAL;
		goto error;
	}

	return LTTNG_OK;

error_io:
	ret = LTTNG_ERR_UST_ENABLE_FAIL;
error:
	return ret;
}

/*
 * Internal disable JUL event call on a JUL application. This function
 * communicates with the Java agent to disable a given event (Logger name).
 *
 * Return LTTNG_OK on success or else a LTTNG_ERR* code.
 */
static int disable_event(struct jul_app *app, struct jul_event *event)
{
	int ret;
	uint64_t data_size;
	struct lttcomm_jul_disable msg;
	struct lttcomm_jul_generic_reply reply;

	assert(app);
	assert(app->sock);
	assert(event);

	DBG2("JUL disabling event %s for app pid: %d and socket %d", event->name,
			app->pid, app->sock->fd);

	data_size = sizeof(msg);

	ret = send_header(app->sock, data_size, JUL_CMD_DISABLE, 0);
	if (ret < 0) {
		goto error_io;
	}

	strncpy(msg.name, event->name, sizeof(msg.name));
	ret = send_payload(app->sock, &msg, sizeof(msg));
	if (ret < 0) {
		goto error_io;
	}

	ret = recv_reply(app->sock, &reply, sizeof(reply));
	if (ret < 0) {
		goto error_io;
	}

	switch (be32toh(reply.ret_code)) {
		case JUL_RET_CODE_SUCCESS:
			break;
		case JUL_RET_CODE_UNKNOWN_NAME:
			ret = LTTNG_ERR_UST_EVENT_NOT_FOUND;
			goto error;
		default:
			ERR("Java agent returned an unknown code: %" PRIu32,
					be32toh(reply.ret_code));
			ret = LTTNG_ERR_FATAL;
			goto error;
	}

	return LTTNG_OK;

error_io:
	ret = LTTNG_ERR_UST_DISABLE_FAIL;
error:
	return ret;
}

/*
 * Enable JUL event on every JUL applications registered with the session
 * daemon.
 *
 * Return LTTNG_OK on success or else a LTTNG_ERR* code.
 */
int jul_enable_event(struct jul_event *event)
{
	int ret;
	struct jul_app *app;
	struct lttng_ht_iter iter;

	assert(event);

	rcu_read_lock();

	cds_lfht_for_each_entry(jul_apps_ht_by_sock->ht, &iter.iter, app,
			node.node) {
		/* Enable event on JUL application through TCP socket. */
		ret = enable_event(app, event);
		if (ret != LTTNG_OK) {
			goto error;
		}
	}

	event->enabled = 1;
	ret = LTTNG_OK;

error:
	rcu_read_unlock();
	return ret;
}

/*
 * Disable JUL event on every JUL applications registered with the session
 * daemon.
 *
 * Return LTTNG_OK on success or else a LTTNG_ERR* code.
 */
int jul_disable_event(struct jul_event *event)
{
	int ret;
	struct jul_app *app;
	struct lttng_ht_iter iter;

	assert(event);

	rcu_read_lock();

	cds_lfht_for_each_entry(jul_apps_ht_by_sock->ht, &iter.iter, app,
			node.node) {
		/* Enable event on JUL application through TCP socket. */
		ret = disable_event(app, event);
		if (ret != LTTNG_OK) {
			goto error;
		}
	}

	event->enabled = 0;
	ret = LTTNG_OK;

error:
	rcu_read_unlock();
	return ret;
}

/*
 * Ask every java agent for the list of possible event (logger name). Events is
 * allocated with the events of every JUL application.
 *
 * Return the number of events or else a negative value.
 */
int jul_list_events(struct lttng_event **events)
{
	int ret;
	size_t nbmem, count = 0;
	struct jul_app *app;
	struct lttng_event *tmp_events = NULL;
	struct lttng_ht_iter iter;

	assert(events);

	nbmem = UST_APP_EVENT_LIST_SIZE;
	tmp_events = zmalloc(nbmem * sizeof(*tmp_events));
	if (!tmp_events) {
		PERROR("zmalloc jul list events");
		ret = -ENOMEM;
		goto error;
	}

	rcu_read_lock();
	cds_lfht_for_each_entry(jul_apps_ht_by_sock->ht, &iter.iter, app,
			node.node) {
		ssize_t nb_ev;
		struct lttng_event *jul_events;

		nb_ev = list_events(app, &jul_events);
		if (nb_ev < 0) {
			ret = nb_ev;
			goto error_unlock;
		}

		if (count >= nbmem) {
			/* In case the realloc fails, we free the memory */
			void *ptr;

			DBG2("Reallocating JUL event list from %zu to %zu entries", nbmem,
					2 * nbmem);
			nbmem *= 2;
			ptr = realloc(tmp_events, nbmem * sizeof(*tmp_events));
			if (!ptr) {
				PERROR("realloc JUL events");
				ret = -ENOMEM;
				free(jul_events);
				goto error_unlock;
			}
			tmp_events = ptr;
		}
		memcpy(tmp_events + (count * sizeof(*tmp_events)), jul_events,
				nb_ev * sizeof(*tmp_events));
		free(jul_events);
		count += nb_ev;
	}
	rcu_read_unlock();

	ret = count;
	*events = tmp_events;
	return ret;

error_unlock:
	rcu_read_unlock();
error:
	free(tmp_events);
	return ret;
}

/*
 * Create a JUL app object using the given PID.
 *
 * Return newly allocated object or else NULL on error.
 */
struct jul_app *jul_create_app(pid_t pid, struct lttcomm_sock *sock)
{
	struct jul_app *app;

	assert(sock);

	app = zmalloc(sizeof(*app));
	if (!app) {
		PERROR("zmalloc JUL create");
		goto error;
	}

	app->pid = pid;
	app->sock = sock;
	/* Flag it invalid until assignation. */
	app->ust_app_sock = -1;
	lttng_ht_node_init_ulong(&app->node, (unsigned long) app->sock->fd);

error:
	return app;
}

/*
 * Lookup JUL app by socket in the global hash table.
 *
 * RCU read side lock MUST be acquired.
 *
 * Return object if found else NULL.
 */
struct jul_app *jul_find_app_by_sock(int sock)
{
	struct lttng_ht_node_ulong *node;
	struct lttng_ht_iter iter;
	struct jul_app *app;

	assert(sock >= 0);

	lttng_ht_lookup(jul_apps_ht_by_sock, (void *)((unsigned long) sock), &iter);
	node = lttng_ht_iter_get_node_ulong(&iter);
	if (node == NULL) {
		goto error;
	}
	app = caa_container_of(node, struct jul_app, node);

	DBG3("JUL app pid %d found by sock %d.", app->pid, sock);
	return app;

error:
	DBG3("JUL app NOT found by sock %d.", sock);
	return NULL;
}

/*
 * Add JUL application object to a given hash table.
 */
void jul_add_app(struct jul_app *app)
{
	assert(app);

	DBG3("JUL adding app sock: %d and pid: %d to ht", app->sock->fd, app->pid);

	rcu_read_lock();
	lttng_ht_add_unique_ulong(jul_apps_ht_by_sock, &app->node);
	rcu_read_unlock();
}

/*
 * Attach a given JUL application to an UST app object. This is done by copying
 * the socket fd value into the ust app obj. atomically.
 */
void jul_attach_app(struct jul_app *japp)
{
	struct ust_app *uapp;

	assert(japp);

	rcu_read_lock();
	uapp = ust_app_find_by_pid(japp->pid);
	if (!uapp) {
		goto end;
	}

	uatomic_set(&uapp->jul_app_sock, japp->sock->fd);

	DBG3("JUL app pid: %d, sock: %d attached to UST app.", japp->pid,
			japp->sock->fd);

end:
	rcu_read_unlock();
	return;
}

/*
 * Remove JUL app. reference from an UST app object and set it to NULL.
 */
void jul_detach_app(struct jul_app *japp)
{
	struct ust_app *uapp;

	assert(japp);

	rcu_read_lock();

	if (japp->ust_app_sock < 0) {
		goto end;
	}

	uapp = ust_app_find_by_sock(japp->ust_app_sock);
	if (!uapp) {
		goto end;
	}

	uapp->jul_app_sock = -1;

end:
	rcu_read_unlock();
	return;
}

/*
 * Delete JUL application from the global hash table.
 */
void jul_delete_app(struct jul_app *app)
{
	int ret;
	struct lttng_ht_iter iter;

	assert(app);

	DBG3("JUL deleting app pid: %d and sock: %d", app->pid, app->sock->fd);

	iter.iter.node = &app->node.node;
	rcu_read_lock();
	ret = lttng_ht_del(jul_apps_ht_by_sock, &iter);
	rcu_read_unlock();
	assert(!ret);
}

/*
 * Destroy a JUL application object by detaching it from its corresponding UST
 * app if one is connected by closing the socket. Finally, perform a
 * delayed memory reclaim.
 */
void jul_destroy_app(struct jul_app *app)
{
	assert(app);

	if (app->sock) {
		app->sock->ops->close(app->sock);
		lttcomm_destroy_sock(app->sock);
	}

	call_rcu(&app->node.head, destroy_app_jul_rcu);
}

/*
 * Initialize an already allocated JUL domain object.
 *
 * Return 0 on success or else a negative errno value.
 */
int jul_init_domain(struct jul_domain *dom)
{
	int ret;

	assert(dom);

	dom->events = lttng_ht_new(0, LTTNG_HT_TYPE_STRING);
	if (!dom->events) {
		ret = -ENOMEM;
		goto error;
	}

	return 0;

error:
	return ret;
}

/*
 * Create a newly allocated JUL event data structure. If name is valid, it's
 * copied into the created event.
 *
 * Return a new object else NULL on error.
 */
struct jul_event *jul_create_event(const char *name)
{
	struct jul_event *event;

	DBG3("JUL create new event with name %s", name);

	event = zmalloc(sizeof(*event));
	if (!event) {
		goto error;
	}

	if (name) {
		strncpy(event->name, name, sizeof(event->name));
		event->name[sizeof(event->name) - 1] = '\0';
		lttng_ht_node_init_str(&event->node, event->name);
	}

error:
	return event;
}

/*
 * Unique add of a JUL event to a given domain.
 */
void jul_add_event(struct jul_event *event, struct jul_domain *dom)
{
	assert(event);
	assert(dom);
	assert(dom->events);

	DBG3("JUL adding event %s to domain", event->name);

	rcu_read_lock();
	lttng_ht_add_unique_str(dom->events, &event->node);
	rcu_read_unlock();
	dom->being_used = 1;
}

/*
 * Find a JUL event in the given domain using name.
 *
 * RCU read side lock MUST be acquired.
 *
 * Return object if found else NULL.
 */
struct jul_event *jul_find_by_name(const char *name, struct jul_domain *dom)
{
	struct lttng_ht_node_str *node;
	struct lttng_ht_iter iter;

	assert(name);
	assert(dom);
	assert(dom->events);

	lttng_ht_lookup(dom->events, (void *)name, &iter);
	node = lttng_ht_iter_get_node_str(&iter);
	if (node == NULL) {
		goto error;
	}

	DBG3("JUL found by name %s in domain.", name);
	return caa_container_of(node, struct jul_event, node);

error:
	DBG3("JUL NOT found by name %s in domain.", name);
	return NULL;
}

/*
 * Delete JUL event from given domain. Events hash table MUST be initialized.
 */
void jul_delete_event(struct jul_event *event, struct jul_domain *dom)
{
	int ret;
	struct lttng_ht_iter iter;

	assert(event);
	assert(dom);
	assert(dom->events);

	DBG3("JUL deleting event %s from domain", event->name);

	iter.iter.node = &event->node.node;
	rcu_read_lock();
	ret = lttng_ht_del(dom->events, &iter);
	rcu_read_unlock();
	assert(!ret);
}

/*
 * Free given JUL event. This event must not be globally visible at this
 * point (only expected to be used on failure just after event
 * creation). After this call, the pointer is not usable anymore.
 */
void jul_destroy_event(struct jul_event *event)
{
	assert(event);

	free(event);
}

/*
 * Destroy a JUL domain completely. Note that the given pointer is NOT freed
 * thus a reference to static or stack data can be passed to this function.
 */
void jul_destroy_domain(struct jul_domain *dom)
{
	struct lttng_ht_node_str *node;
	struct lttng_ht_iter iter;

	assert(dom);

	DBG3("JUL destroy domain");

	/*
	 * Just ignore if no events hash table exists. This is possible if for
	 * instance a JUL domain object was allocated but not initialized.
	 */
	if (!dom->events) {
		return;
	}

	rcu_read_lock();
	cds_lfht_for_each_entry(dom->events->ht, &iter.iter, node, node) {
		int ret;

		ret = lttng_ht_del(dom->events, &iter);
		assert(!ret);
		call_rcu(&node->head, destroy_event_jul_rcu);
	}
	rcu_read_unlock();

	lttng_ht_destroy(dom->events);
}

/*
 * Initialize JUL subsystem.
 */
int jul_init(void)
{
	jul_apps_ht_by_sock = lttng_ht_new(0, LTTNG_HT_TYPE_ULONG);
	if (!jul_apps_ht_by_sock) {
		return -1;
	}

	return 0;
}

/*
 * Update a JUL application (given socket) using the given domain.
 *
 * Note that this function is most likely to be used with a tracing session
 * thus the caller should make sure to hold the appropriate lock(s).
 */
void jul_update(struct jul_domain *domain, int sock)
{
	int ret;
	struct jul_app *app;
	struct jul_event *event;
	struct lttng_ht_iter iter;

	assert(domain);
	assert(sock >= 0);

	DBG("JUL updating app socket %d", sock);

	rcu_read_lock();
	cds_lfht_for_each_entry(domain->events->ht, &iter.iter, event, node.node) {
		/* Skip event if disabled. */
		if (!event->enabled) {
			continue;
		}

		app = jul_find_app_by_sock(sock);
		/*
		 * We are in the registration path thus if the application is gone,
		 * there is a serious code flow error.
		 */
		assert(app);

		ret = enable_event(app, event);
		if (ret != LTTNG_OK) {
			DBG2("JUL update unable to enable event %s on app pid: %d sock %d",
					event->name, app->pid, app->sock->fd);
			/* Let's try the others here and don't assume the app is dead. */
			continue;
		}
	}
	rcu_read_unlock();
}
