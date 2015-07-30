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
#define _LGPL_SOURCE
#include <assert.h>
#include <urcu/uatomic.h>

#include <common/common.h>
#include <common/sessiond-comm/agent.h>

#include <common/compat/endian.h>

#include "agent.h"
#include "ust-app.h"
#include "utils.h"

/*
 * Match function for the events hash table lookup by name.
 */
static int ht_match_event_by_name(struct cds_lfht_node *node,
		const void *_key)
{
	struct agent_event *event;
	const struct agent_ht_key *key;

	assert(node);
	assert(_key);

	event = caa_container_of(node, struct agent_event, node.node);
	key = _key;

	/* Match 1 elements of the key: name. */

	/* Event name */
	if (strncmp(event->name, key->name, sizeof(event->name)) != 0) {
		goto no_match;
	}
	/* Match. */
	return 1;

no_match:
	return 0;
}

/*
 * Match function for the events hash table lookup by name and loglevel.
 */
static int ht_match_event(struct cds_lfht_node *node,
		const void *_key)
{
	struct agent_event *event;
	const struct agent_ht_key *key;

	assert(node);
	assert(_key);

	event = caa_container_of(node, struct agent_event, node.node);
	key = _key;

	/* Match 2 elements of the key: name and loglevel. */

	/* Event name */
	if (strncmp(event->name, key->name, sizeof(event->name)) != 0) {
		goto no_match;
	}

	if (event->loglevel != key->loglevel) {
		if (event->loglevel_type == LTTNG_EVENT_LOGLEVEL_ALL &&
				key->loglevel == 0 && event->loglevel == -1) {
			goto match;
		}
		goto no_match;
	}
match:
	return 1;

no_match:
	return 0;
}

/*
 * Add unique agent event based on the event name and loglevel.
 */
static void add_unique_agent_event(struct lttng_ht *ht,
		struct agent_event *event)
{
	struct cds_lfht_node *node_ptr;
	struct agent_ht_key key;

	assert(ht);
	assert(ht->ht);
	assert(event);

	key.name = event->name;
	key.loglevel = event->loglevel;

	node_ptr = cds_lfht_add_unique(ht->ht,
			ht->hash_fct(event->node.key, lttng_ht_seed),
			ht_match_event, &key, &event->node.node);
	assert(node_ptr == &event->node.node);
}

/*
 * URCU delayed agent event reclaim.
 */
static void destroy_event_agent_rcu(struct rcu_head *head)
{
	struct lttng_ht_node_str *node =
		caa_container_of(head, struct lttng_ht_node_str, head);
	struct agent_event *event =
		caa_container_of(node, struct agent_event, node);

	free(event);
}

/*
 * URCU delayed agent app reclaim.
 */
static void destroy_app_agent_rcu(struct rcu_head *head)
{
	struct lttng_ht_node_ulong *node =
		caa_container_of(head, struct lttng_ht_node_ulong, head);
	struct agent_app *app =
		caa_container_of(node, struct agent_app, node);

	free(app);
}

/*
 * Communication with the agent. Send the message header to the given socket in
 * big endian.
 *
 * Return 0 on success or else a negative errno message of sendmsg() op.
 */
static int send_header(struct lttcomm_sock *sock, uint64_t data_size,
		uint32_t cmd, uint32_t cmd_version)
{
	int ret;
	ssize_t size;
	struct lttcomm_agent_hdr msg;

	assert(sock);

	memset(&msg, 0, sizeof(msg));
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
 * Communication call with the agent. Send the payload to the given socket. The
 * header MUST be sent prior to this call.
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
 * Communication call with the agent. Receive reply from the agent using the
 * given socket.
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
static ssize_t list_events(struct agent_app *app, struct lttng_event **events)
{
	int ret, i, len = 0, offset = 0;
	uint32_t nb_event;
	size_t data_size;
	struct lttng_event *tmp_events = NULL;
	struct lttcomm_agent_list_reply *reply = NULL;
	struct lttcomm_agent_list_reply_hdr reply_hdr;

	assert(app);
	assert(app->sock);
	assert(events);

	DBG2("Agent listing events for app pid: %d and socket %d", app->pid,
			app->sock->fd);

	ret = send_header(app->sock, 0, AGENT_CMD_LIST, 0);
	if (ret < 0) {
		goto error_io;
	}

	/* Get list header so we know how much we'll receive. */
	ret = recv_reply(app->sock, &reply_hdr, sizeof(reply_hdr));
	if (ret < 0) {
		goto error_io;
	}

	switch (be32toh(reply_hdr.ret_code)) {
	case AGENT_RET_CODE_SUCCESS:
		data_size = be32toh(reply_hdr.data_size) + sizeof(*reply);
		break;
	default:
		ERR("Agent returned an unknown code: %" PRIu32,
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
 * Internal enable agent event on a agent application. This function
 * communicates with the agent to enable a given event.
 *
 * Return LTTNG_OK on success or else a LTTNG_ERR* code.
 */
static int enable_event(struct agent_app *app, struct agent_event *event)
{
	int ret;
	uint64_t data_size;
	struct lttcomm_agent_enable msg;
	struct lttcomm_agent_generic_reply reply;

	assert(app);
	assert(app->sock);
	assert(event);

	DBG2("Agent enabling event %s for app pid: %d and socket %d", event->name,
			app->pid, app->sock->fd);

	data_size = sizeof(msg);

	ret = send_header(app->sock, data_size, AGENT_CMD_ENABLE, 0);
	if (ret < 0) {
		goto error_io;
	}

	memset(&msg, 0, sizeof(msg));
	msg.loglevel = event->loglevel;
	msg.loglevel_type = event->loglevel_type;
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
	case AGENT_RET_CODE_SUCCESS:
		break;
	case AGENT_RET_CODE_UNKNOWN_NAME:
		ret = LTTNG_ERR_UST_EVENT_NOT_FOUND;
		goto error;
	default:
		ERR("Agent returned an unknown code: %" PRIu32,
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
 * Internal disable agent event call on a agent application. This function
 * communicates with the agent to disable a given event.
 *
 * Return LTTNG_OK on success or else a LTTNG_ERR* code.
 */
static int disable_event(struct agent_app *app, struct agent_event *event)
{
	int ret;
	uint64_t data_size;
	struct lttcomm_agent_disable msg;
	struct lttcomm_agent_generic_reply reply;

	assert(app);
	assert(app->sock);
	assert(event);

	DBG2("Agent disabling event %s for app pid: %d and socket %d", event->name,
			app->pid, app->sock->fd);

	data_size = sizeof(msg);

	ret = send_header(app->sock, data_size, AGENT_CMD_DISABLE, 0);
	if (ret < 0) {
		goto error_io;
	}

	memset(&msg, 0, sizeof(msg));
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
	case AGENT_RET_CODE_SUCCESS:
		break;
	case AGENT_RET_CODE_UNKNOWN_NAME:
		ret = LTTNG_ERR_UST_EVENT_NOT_FOUND;
		goto error;
	default:
		ERR("Agent returned an unknown code: %" PRIu32,
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
 * Send back the registration DONE command to a given agent application.
 *
 * Return 0 on success or else a negative value.
 */
int agent_send_registration_done(struct agent_app *app)
{
	assert(app);
	assert(app->sock);

	DBG("Agent sending registration done to app socket %d", app->sock->fd);

	return send_header(app->sock, 0, AGENT_CMD_REG_DONE, 0);
}

/*
 * Enable agent event on every agent applications registered with the session
 * daemon.
 *
 * Return LTTNG_OK on success or else a LTTNG_ERR* code.
 */
int agent_enable_event(struct agent_event *event,
		enum lttng_domain_type domain)
{
	int ret;
	struct agent_app *app;
	struct lttng_ht_iter iter;

	assert(event);

	rcu_read_lock();

	cds_lfht_for_each_entry(agent_apps_ht_by_sock->ht, &iter.iter, app,
			node.node) {
		if (app->domain != domain) {
			continue;
		}

		/* Enable event on agent application through TCP socket. */
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
 * Disable agent event on every agent applications registered with the session
 * daemon.
 *
 * Return LTTNG_OK on success or else a LTTNG_ERR* code.
 */
int agent_disable_event(struct agent_event *event,
		enum lttng_domain_type domain)
{
	int ret;
	struct agent_app *app;
	struct lttng_ht_iter iter;

	assert(event);

	rcu_read_lock();

	cds_lfht_for_each_entry(agent_apps_ht_by_sock->ht, &iter.iter, app,
			node.node) {
		if (app->domain != domain) {
			continue;
		}

		/* Enable event on agent application through TCP socket. */
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
 * Ask every agent for the list of possible event. Events is allocated with the
 * events of every agent application.
 *
 * Return the number of events or else a negative value.
 */
int agent_list_events(struct lttng_event **events,
		enum lttng_domain_type domain)
{
	int ret;
	size_t nbmem, count = 0;
	struct agent_app *app;
	struct lttng_event *tmp_events = NULL;
	struct lttng_ht_iter iter;

	assert(events);

	DBG2("Agent listing events for domain %d", domain);

	nbmem = UST_APP_EVENT_LIST_SIZE;
	tmp_events = zmalloc(nbmem * sizeof(*tmp_events));
	if (!tmp_events) {
		PERROR("zmalloc agent list events");
		ret = -ENOMEM;
		goto error;
	}

	rcu_read_lock();
	cds_lfht_for_each_entry(agent_apps_ht_by_sock->ht, &iter.iter, app,
			node.node) {
		ssize_t nb_ev;
		struct lttng_event *agent_events;

		/* Skip domain not asked by the list. */
		if (app->domain != domain) {
			continue;
		}

		nb_ev = list_events(app, &agent_events);
		if (nb_ev < 0) {
			ret = nb_ev;
			goto error_unlock;
		}

		if (count + nb_ev > nbmem) {
			/* In case the realloc fails, we free the memory */
			struct lttng_event *new_tmp_events;
			size_t new_nbmem;

			new_nbmem = max_t(size_t, count + nb_ev, nbmem << 1);
			DBG2("Reallocating agent event list from %zu to %zu entries",
					nbmem, new_nbmem);
			new_tmp_events = realloc(tmp_events,
				new_nbmem * sizeof(*new_tmp_events));
			if (!new_tmp_events) {
				PERROR("realloc agent events");
				ret = -ENOMEM;
				free(agent_events);
				goto error_unlock;
			}
			/* Zero the new memory */
			memset(new_tmp_events + nbmem, 0,
				(new_nbmem - nbmem) * sizeof(*new_tmp_events));
			nbmem = new_nbmem;
			tmp_events = new_tmp_events;
		}
		memcpy(tmp_events + count, agent_events,
			nb_ev * sizeof(*tmp_events));
		free(agent_events);
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
 * Create a agent app object using the given PID.
 *
 * Return newly allocated object or else NULL on error.
 */
struct agent_app *agent_create_app(pid_t pid, enum lttng_domain_type domain,
		struct lttcomm_sock *sock)
{
	struct agent_app *app;

	assert(sock);

	app = zmalloc(sizeof(*app));
	if (!app) {
		PERROR("zmalloc agent create");
		goto error;
	}

	app->pid = pid;
	app->domain = domain;
	app->sock = sock;
	lttng_ht_node_init_ulong(&app->node, (unsigned long) app->sock->fd);

error:
	return app;
}

/*
 * Lookup agent app by socket in the global hash table.
 *
 * RCU read side lock MUST be acquired.
 *
 * Return object if found else NULL.
 */
struct agent_app *agent_find_app_by_sock(int sock)
{
	struct lttng_ht_node_ulong *node;
	struct lttng_ht_iter iter;
	struct agent_app *app;

	assert(sock >= 0);

	lttng_ht_lookup(agent_apps_ht_by_sock, (void *)((unsigned long) sock), &iter);
	node = lttng_ht_iter_get_node_ulong(&iter);
	if (node == NULL) {
		goto error;
	}
	app = caa_container_of(node, struct agent_app, node);

	DBG3("Agent app pid %d found by sock %d.", app->pid, sock);
	return app;

error:
	DBG3("Agent app NOT found by sock %d.", sock);
	return NULL;
}

/*
 * Add agent application object to the global hash table.
 */
void agent_add_app(struct agent_app *app)
{
	assert(app);

	DBG3("Agent adding app sock: %d and pid: %d to ht", app->sock->fd, app->pid);

	rcu_read_lock();
	lttng_ht_add_unique_ulong(agent_apps_ht_by_sock, &app->node);
	rcu_read_unlock();
}

/*
 * Delete agent application from the global hash table.
 *
 * rcu_read_lock() must be held by the caller.
 */
void agent_delete_app(struct agent_app *app)
{
	int ret;
	struct lttng_ht_iter iter;

	assert(app);

	DBG3("Agent deleting app pid: %d and sock: %d", app->pid, app->sock->fd);

	iter.iter.node = &app->node.node;
	ret = lttng_ht_del(agent_apps_ht_by_sock, &iter);
	assert(!ret);
}

/*
 * Destroy a agent application object by detaching it from its corresponding
 * UST app if one is connected by closing the socket. Finally, perform a
 * delayed memory reclaim.
 */
void agent_destroy_app(struct agent_app *app)
{
	assert(app);

	if (app->sock) {
		app->sock->ops->close(app->sock);
		lttcomm_destroy_sock(app->sock);
	}

	call_rcu(&app->node.head, destroy_app_agent_rcu);
}

/*
 * Initialize an already allocated agent object.
 *
 * Return 0 on success or else a negative errno value.
 */
int agent_init(struct agent *agt)
{
	int ret;

	assert(agt);

	agt->events = lttng_ht_new(0, LTTNG_HT_TYPE_STRING);
	if (!agt->events) {
		ret = -ENOMEM;
		goto error;
	}
	lttng_ht_node_init_u64(&agt->node, agt->domain);

	return 0;

error:
	return ret;
}

/*
 * Add agent object to the given hash table.
 */
void agent_add(struct agent *agt, struct lttng_ht *ht)
{
	assert(agt);
	assert(ht);

	DBG3("Agent adding from domain %d", agt->domain);

	rcu_read_lock();
	lttng_ht_add_unique_u64(ht, &agt->node);
	rcu_read_unlock();
}

/*
 * Create an agent object for the given domain.
 *
 * Return the allocated agent or NULL on error.
 */
struct agent *agent_create(enum lttng_domain_type domain)
{
	int ret;
	struct agent *agt;

	agt = zmalloc(sizeof(*agt));
	if (!agt) {
		goto error;
	}
	agt->domain = domain;

	ret = agent_init(agt);
	if (ret < 0) {
		free(agt);
		agt = NULL;
		goto error;
	}

error:
	return agt;
}

/*
 * Create a newly allocated agent event data structure. If name is valid, it's
 * copied into the created event.
 *
 * Return a new object else NULL on error.
 */
struct agent_event *agent_create_event(const char *name,
		struct lttng_filter_bytecode *filter)
{
	struct agent_event *event;

	DBG3("Agent create new event with name %s", name);

	event = zmalloc(sizeof(*event));
	if (!event) {
		goto error;
	}

	if (name) {
		strncpy(event->name, name, sizeof(event->name));
		event->name[sizeof(event->name) - 1] = '\0';
		lttng_ht_node_init_str(&event->node, event->name);
	}

	if (filter) {
		event->filter = filter;
	}

error:
	return event;
}

/*
 * Unique add of a agent event to an agent object.
 */
void agent_add_event(struct agent_event *event, struct agent *agt)
{
	assert(event);
	assert(agt);
	assert(agt->events);

	DBG3("Agent adding event %s", event->name);

	rcu_read_lock();
	add_unique_agent_event(agt->events, event);
	rcu_read_unlock();
	agt->being_used = 1;
}

/*
 * Find a agent event in the given agent using name.
 *
 * RCU read side lock MUST be acquired.
 *
 * Return object if found else NULL.
 */
struct agent_event *agent_find_event_by_name(const char *name,
		struct agent *agt)
{
	struct lttng_ht_node_str *node;
	struct lttng_ht_iter iter;
	struct lttng_ht *ht;
	struct agent_ht_key key;

	assert(name);
	assert(agt);
	assert(agt->events);

	ht = agt->events;
	key.name = name;

	cds_lfht_lookup(ht->ht, ht->hash_fct((void *) name, lttng_ht_seed),
			ht_match_event_by_name, &key, &iter.iter);
	node = lttng_ht_iter_get_node_str(&iter);
	if (node == NULL) {
		goto error;
	}

	DBG3("Agent event found %s by name.", name);
	return caa_container_of(node, struct agent_event, node);

error:
	DBG3("Agent NOT found by name %s.", name);
	return NULL;
}

/*
 * Find a agent event in the given agent using name and loglevel.
 *
 * RCU read side lock MUST be acquired.
 *
 * Return object if found else NULL.
 */
struct agent_event *agent_find_event(const char *name, int loglevel,
		struct agent *agt)
{
	struct lttng_ht_node_str *node;
	struct lttng_ht_iter iter;
	struct lttng_ht *ht;
	struct agent_ht_key key;

	assert(name);
	assert(agt);
	assert(agt->events);

	ht = agt->events;
	key.name = name;
	key.loglevel = loglevel;

	cds_lfht_lookup(ht->ht, ht->hash_fct((void *) name, lttng_ht_seed),
			ht_match_event, &key, &iter.iter);
	node = lttng_ht_iter_get_node_str(&iter);
	if (node == NULL) {
		goto error;
	}

	DBG3("Agent event found %s.", name);
	return caa_container_of(node, struct agent_event, node);

error:
	DBG3("Agent event NOT found %s.", name);
	return NULL;
}

/*
 * Free given agent event. This event must not be globally visible at this
 * point (only expected to be used on failure just after event creation). After
 * this call, the pointer is not usable anymore.
 */
void agent_destroy_event(struct agent_event *event)
{
	assert(event);

	free(event->filter);
	free(event);
}

/*
 * Destroy an agent completely. Note that the given pointer is NOT freed
 * thus a reference to static or stack data can be passed to this function.
 */
void agent_destroy(struct agent *agt)
{
	struct lttng_ht_node_str *node;
	struct lttng_ht_iter iter;

	assert(agt);

	DBG3("Agent destroy");

	/*
	 * Just ignore if no events hash table exists. This is possible if for
	 * instance an agent object was allocated but not initialized.
	 */
	if (!agt->events) {
		return;
	}

	rcu_read_lock();
	cds_lfht_for_each_entry(agt->events->ht, &iter.iter, node, node) {
		int ret;
		struct agent_event *event;

		/*
		 * When destroying an event, we have to try to disable it on the agent
		 * side so the event stops generating data. The return value is not
		 * important since we have to continue anyway destroying the object.
		 */
		event = caa_container_of(node, struct agent_event, node);
		(void) agent_disable_event(event, agt->domain);

		ret = lttng_ht_del(agt->events, &iter);
		assert(!ret);
		call_rcu(&node->head, destroy_event_agent_rcu);
	}
	rcu_read_unlock();

	ht_cleanup_push(agt->events);
}

/*
 * Allocate agent_apps_ht_by_sock.
 */
int agent_app_ht_alloc(void)
{
	int ret = 0;

	agent_apps_ht_by_sock = lttng_ht_new(0, LTTNG_HT_TYPE_ULONG);
	if (!agent_apps_ht_by_sock) {
		ret = -1;
	}

	return ret;
}

/*
 * Destroy a agent application by socket.
 */
void agent_destroy_app_by_sock(int sock)
{
	struct agent_app *app;

	assert(sock >= 0);

	/*
	 * Not finding an application is a very important error that should NEVER
	 * happen. The hash table deletion is ONLY done through this call when the
	 * main sessiond thread is torn down.
	 */
	rcu_read_lock();
	app = agent_find_app_by_sock(sock);
	assert(app);

	/* RCU read side lock is assumed to be held by this function. */
	agent_delete_app(app);

	/* The application is freed in a RCU call but the socket is closed here. */
	agent_destroy_app(app);
	rcu_read_unlock();
}

/*
 * Clean-up the agent app hash table and destroy it.
 */
void agent_app_ht_clean(void)
{
	struct lttng_ht_node_ulong *node;
	struct lttng_ht_iter iter;

	if (!agent_apps_ht_by_sock) {
		return;
	}
	rcu_read_lock();
	cds_lfht_for_each_entry(agent_apps_ht_by_sock->ht, &iter.iter, node, node) {
		struct agent_app *app;

		app = caa_container_of(node, struct agent_app, node);
		agent_destroy_app_by_sock(app->sock->fd);
	}
	rcu_read_unlock();

	lttng_ht_destroy(agent_apps_ht_by_sock);
}

/*
 * Update a agent application (given socket) using the given agent.
 *
 * Note that this function is most likely to be used with a tracing session
 * thus the caller should make sure to hold the appropriate lock(s).
 */
void agent_update(struct agent *agt, int sock)
{
	int ret;
	struct agent_app *app;
	struct agent_event *event;
	struct lttng_ht_iter iter;

	assert(agt);
	assert(sock >= 0);

	DBG("Agent updating app socket %d", sock);

	rcu_read_lock();
	cds_lfht_for_each_entry(agt->events->ht, &iter.iter, event, node.node) {
		/* Skip event if disabled. */
		if (!event->enabled) {
			continue;
		}

		app = agent_find_app_by_sock(sock);
		/*
		 * We are in the registration path thus if the application is gone,
		 * there is a serious code flow error.
		 */
		assert(app);

		ret = enable_event(app, event);
		if (ret != LTTNG_OK) {
			DBG2("Agent update unable to enable event %s on app pid: %d sock %d",
					event->name, app->pid, app->sock->fd);
			/* Let's try the others here and don't assume the app is dead. */
			continue;
		}
	}
	rcu_read_unlock();
}
