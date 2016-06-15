/*
 * Copyright (C) 2013 - David Goulet <dgoulet@efficios.com>
 * Copyright (C) 2016 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
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

#define _LGPL_SOURCE
#include <assert.h>
#include <urcu/uatomic.h>
#include <urcu/rculist.h>

#include <common/common.h>
#include <common/sessiond-comm/agent.h>

#include <common/compat/endian.h>

#include "agent.h"
#include "ust-app.h"
#include "utils.h"
#include "common/error.h"

#define AGENT_RET_CODE_INDEX(code) (code - AGENT_RET_CODE_SUCCESS)

/*
 * Agent application context representation.
 */
struct agent_app_ctx {
	char *provider_name;
	char *ctx_name;

	/* agent_app_ctx are part of the agent app_ctx_list. */
	struct cds_list_head list_node;

	/* For call_rcu teardown. */
	struct rcu_head rcu_node;
};

/*
 * Human readable agent return code.
 */
static const char *error_string_array[] = {
	[ AGENT_RET_CODE_INDEX(AGENT_RET_CODE_SUCCESS) ] = "Success",
	[ AGENT_RET_CODE_INDEX(AGENT_RET_CODE_INVALID) ] = "Invalid command",
	[ AGENT_RET_CODE_INDEX(AGENT_RET_CODE_UNKNOWN_NAME) ] = "Unknown logger name",

	/* Last element */
	[ AGENT_RET_CODE_INDEX(AGENT_RET_CODE_NR) ] = "Unknown code",
};

static
void log_reply_code(uint32_t in_reply_ret_code)
{
	int level = PRINT_DBG3;
	/*
	 * reply_ret_code and in_reply_ret_code are kept separate to have a
	 * sanitized value (used to retrieve the human readable string) and the
	 * original value which is logged as-is.
	 */
	uint32_t reply_ret_code = in_reply_ret_code;

	if (reply_ret_code < AGENT_RET_CODE_SUCCESS ||
			reply_ret_code >= AGENT_RET_CODE_NR) {
		reply_ret_code = AGENT_RET_CODE_NR;
		level = PRINT_ERR;
	}

	LOG(level, "Agent replied with retcode: %s (%"PRIu32")",
			error_string_array[AGENT_RET_CODE_INDEX(
			reply_ret_code)],
			in_reply_ret_code);
}

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
	int ll_match;

	assert(node);
	assert(_key);

	event = caa_container_of(node, struct agent_event, node.node);
	key = _key;

	/* Match 2 elements of the key: name and loglevel. */

	/* Event name */
	if (strncmp(event->name, key->name, sizeof(event->name)) != 0) {
		goto no_match;
	}

	/* Event loglevel value and type. */
	ll_match = loglevels_match(event->loglevel_type,
		event->loglevel_value, key->loglevel_type,
		key->loglevel_value, LTTNG_EVENT_LOGLEVEL_ALL);

	if (!ll_match) {
		goto no_match;
	}

	/* Filter expression */
	if (!!event->filter_expression ^ !!key->filter_expression) {
		/* One has a filter expression, the other does not */
		goto no_match;
	}

	if (event->filter_expression) {
		if (strncmp(event->filter_expression, key->filter_expression,
				strlen(event->filter_expression)) != 0) {
			goto no_match;
		}
	}

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
	key.loglevel_value = event->loglevel_value;
	key.loglevel_type = event->loglevel_type;
	key.filter_expression = event->filter_expression;

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

	agent_destroy_event(event);
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
static int send_payload(struct lttcomm_sock *sock, const void *data,
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
	uint32_t reply_ret_code;
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

	reply_ret_code = be32toh(reply_hdr.ret_code);
	log_reply_code(reply_ret_code);
	switch (reply_ret_code) {
	case AGENT_RET_CODE_SUCCESS:
		data_size = be32toh(reply_hdr.data_size) + sizeof(*reply);
		break;
	default:
		ret = LTTNG_ERR_UNK;
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
		if (lttng_strncpy(tmp_events[i].name, reply->payload + offset,
				sizeof(tmp_events[i].name))) {
			ret = LTTNG_ERR_INVALID;
			goto error;
		}
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
	char *bytes_to_send;
	uint64_t data_size;
	size_t filter_expression_length;
	uint32_t reply_ret_code;
	struct lttcomm_agent_enable_event msg;
	struct lttcomm_agent_generic_reply reply;

	assert(app);
	assert(app->sock);
	assert(event);

	DBG2("Agent enabling event %s for app pid: %d and socket %d", event->name,
			app->pid, app->sock->fd);

	/*
	 * Calculate the payload's size, which is the fixed-size struct followed
	 * by the variable-length filter expression (+1 for the ending \0).
	 */
	if (!event->filter_expression) {
		filter_expression_length = 0;
	} else {
		filter_expression_length = strlen(event->filter_expression) + 1;
	}
	data_size = sizeof(msg) + filter_expression_length;

	memset(&msg, 0, sizeof(msg));
	msg.loglevel_value = htobe32(event->loglevel_value);
	msg.loglevel_type = htobe32(event->loglevel_type);
	if (lttng_strncpy(msg.name, event->name, sizeof(msg.name))) {
		ret = LTTNG_ERR_INVALID;
		goto error;
	}
	msg.filter_expression_length = htobe32(filter_expression_length);

	ret = send_header(app->sock, data_size, AGENT_CMD_ENABLE, 0);
	if (ret < 0) {
		goto error_io;
	}

	bytes_to_send = zmalloc(data_size);
	if (!bytes_to_send) {
		ret = LTTNG_ERR_NOMEM;
		goto error;
	}

	memcpy(bytes_to_send, &msg, sizeof(msg));
	if (filter_expression_length > 0) {
		memcpy(bytes_to_send + sizeof(msg), event->filter_expression,
				filter_expression_length);
	}

	ret = send_payload(app->sock, bytes_to_send, data_size);
	free(bytes_to_send);
	if (ret < 0) {
		goto error_io;
	}

	ret = recv_reply(app->sock, &reply, sizeof(reply));
	if (ret < 0) {
		goto error_io;
	}

	reply_ret_code = be32toh(reply.ret_code);
	log_reply_code(reply_ret_code);
	switch (reply_ret_code) {
	case AGENT_RET_CODE_SUCCESS:
		break;
	case AGENT_RET_CODE_UNKNOWN_NAME:
		ret = LTTNG_ERR_UST_EVENT_NOT_FOUND;
		goto error;
	default:
		ret = LTTNG_ERR_UNK;
		goto error;
	}

	return LTTNG_OK;

error_io:
	ret = LTTNG_ERR_UST_ENABLE_FAIL;
error:
	return ret;
}

/*
 * Send Pascal-style string. Size is sent as a 32-bit big endian integer.
 */
static
int send_pstring(struct lttcomm_sock *sock, const char *str, uint32_t len)
{
	int ret;
	uint32_t len_be;

	len_be = htobe32(len);
	ret = send_payload(sock, &len_be, sizeof(len_be));
	if (ret) {
		goto end;
	}

	ret = send_payload(sock, str, len);
	if (ret) {
		goto end;
	}
end:
	return ret;
}

/*
 * Internal enable application context on an agent application. This function
 * communicates with the agent to enable a given application context.
 *
 * Return LTTNG_OK on success or else a LTTNG_ERR* code.
 */
static int app_context_op(struct agent_app *app,
		struct agent_app_ctx *ctx, enum lttcomm_agent_command cmd)
{
	int ret;
	uint32_t reply_ret_code;
	struct lttcomm_agent_generic_reply reply;
	size_t app_ctx_provider_name_len, app_ctx_name_len, data_size;

	assert(app);
	assert(app->sock);
	assert(ctx);
	assert(cmd == AGENT_CMD_APP_CTX_ENABLE ||
			cmd == AGENT_CMD_APP_CTX_DISABLE);

	DBG2("Agent %s application %s:%s for app pid: %d and socket %d",
			cmd == AGENT_CMD_APP_CTX_ENABLE ? "enabling" : "disabling",
			ctx->provider_name, ctx->ctx_name,
			app->pid, app->sock->fd);

	/*
	 * Calculate the payload's size, which consists of the size (u32, BE)
	 * of the provider name, the NULL-terminated provider name string, the
	 * size (u32, BE) of the context name, followed by the NULL-terminated
	 * context name string.
	 */
	app_ctx_provider_name_len = strlen(ctx->provider_name) + 1;
	app_ctx_name_len = strlen(ctx->ctx_name) + 1;
	data_size = sizeof(uint32_t) + app_ctx_provider_name_len +
			sizeof(uint32_t) + app_ctx_name_len;

	ret = send_header(app->sock, data_size, cmd, 0);
	if (ret < 0) {
		goto error_io;
	}

	if (app_ctx_provider_name_len > UINT32_MAX ||
			app_ctx_name_len > UINT32_MAX) {
		ERR("Application context name > MAX_UINT32");
		ret = LTTNG_ERR_INVALID;
		goto error;
	}

	ret = send_pstring(app->sock, ctx->provider_name,
			(uint32_t) app_ctx_provider_name_len);
	if (ret < 0) {
		goto error_io;
	}

	ret = send_pstring(app->sock, ctx->ctx_name,
			(uint32_t) app_ctx_name_len);
	if (ret < 0) {
		goto error_io;
	}

	ret = recv_reply(app->sock, &reply, sizeof(reply));
	if (ret < 0) {
		goto error_io;
	}

	reply_ret_code = be32toh(reply.ret_code);
	log_reply_code(reply_ret_code);
	switch (reply_ret_code) {
	case AGENT_RET_CODE_SUCCESS:
		break;
	default:
		ret = LTTNG_ERR_UNK;
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
	uint32_t reply_ret_code;
	struct lttcomm_agent_disable_event msg;
	struct lttcomm_agent_generic_reply reply;

	assert(app);
	assert(app->sock);
	assert(event);

	DBG2("Agent disabling event %s for app pid: %d and socket %d", event->name,
			app->pid, app->sock->fd);

	data_size = sizeof(msg);
	memset(&msg, 0, sizeof(msg));
	if (lttng_strncpy(msg.name, event->name, sizeof(msg.name))) {
		ret = LTTNG_ERR_INVALID;
		goto error;
	}

	ret = send_header(app->sock, data_size, AGENT_CMD_DISABLE, 0);
	if (ret < 0) {
		goto error_io;
	}

	ret = send_payload(app->sock, &msg, sizeof(msg));
	if (ret < 0) {
		goto error_io;
	}

	ret = recv_reply(app->sock, &reply, sizeof(reply));
	if (ret < 0) {
		goto error_io;
	}

	reply_ret_code = be32toh(reply.ret_code);
	log_reply_code(reply_ret_code);
	switch (reply_ret_code) {
	case AGENT_RET_CODE_SUCCESS:
		break;
	case AGENT_RET_CODE_UNKNOWN_NAME:
		ret = LTTNG_ERR_UST_EVENT_NOT_FOUND;
		goto error;
	default:
		ret = LTTNG_ERR_UNK;
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

static
void destroy_app_ctx(struct agent_app_ctx *ctx)
{
	free(ctx->provider_name);
	free(ctx->ctx_name);
	free(ctx);
}

static
struct agent_app_ctx *create_app_ctx(struct lttng_event_context *ctx)
{
	struct agent_app_ctx *agent_ctx = NULL;

	if (!ctx) {
		goto end;
	}

	assert(ctx->ctx == LTTNG_EVENT_CONTEXT_APP_CONTEXT);
	agent_ctx = zmalloc(sizeof(*ctx));
	if (!agent_ctx) {
		goto end;
	}

	agent_ctx->provider_name = strdup(ctx->u.app_ctx.provider_name);
	agent_ctx->ctx_name = strdup(ctx->u.app_ctx.ctx_name);
	if (!agent_ctx->provider_name || !agent_ctx->ctx_name) {
		destroy_app_ctx(agent_ctx);
		agent_ctx = NULL;
	}
end:
	return agent_ctx;
}

/*
 * Enable agent context on every agent applications registered with the session
 * daemon.
 *
 * Return LTTNG_OK on success or else a LTTNG_ERR* code.
 */
int agent_enable_context(struct lttng_event_context *ctx,
		enum lttng_domain_type domain)
{
	int ret;
	struct agent_app *app;
	struct lttng_ht_iter iter;

	assert(ctx);
	if (ctx->ctx != LTTNG_EVENT_CONTEXT_APP_CONTEXT) {
		ret = LTTNG_ERR_INVALID;
		goto error;
	}

	rcu_read_lock();

	cds_lfht_for_each_entry(agent_apps_ht_by_sock->ht, &iter.iter, app,
			node.node) {
		struct agent_app_ctx *agent_ctx;

		if (app->domain != domain) {
			continue;
		}

		agent_ctx = create_app_ctx(ctx);
		if (!agent_ctx) {
			ret = LTTNG_ERR_NOMEM;
			goto error_unlock;
		}

		/* Enable event on agent application through TCP socket. */
		ret = app_context_op(app, agent_ctx, AGENT_CMD_APP_CTX_ENABLE);
		destroy_app_ctx(agent_ctx);
		if (ret != LTTNG_OK) {
			goto error_unlock;
		}
	}

	ret = LTTNG_OK;

error_unlock:
	rcu_read_unlock();
error:
	return ret;
}

/*
 * Disable agent event on every agent application registered with the session
 * daemon.
 *
 * Return LTTNG_OK on success or else a LTTNG_ERR* code.
 */
int agent_disable_event(struct agent_event *event,
		enum lttng_domain_type domain)
{
	int ret = LTTNG_OK;
	struct agent_app *app;
	struct lttng_ht_iter iter;

	assert(event);
	if (!event->enabled) {
		goto end;
	}

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

error:
	rcu_read_unlock();
end:
	return ret;
}

/*
 * Disable agent context on every agent application registered with the session
 * daemon.
 *
 * Return LTTNG_OK on success or else a LTTNG_ERR* code.
 */
int disable_context(struct agent_app_ctx *ctx, enum lttng_domain_type domain)
{
	int ret = LTTNG_OK;
	struct agent_app *app;
	struct lttng_ht_iter iter;

	assert(ctx);

	rcu_read_lock();
	DBG2("Disabling agent application context %s:%s",
			ctx->provider_name, ctx->ctx_name);
	cds_lfht_for_each_entry(agent_apps_ht_by_sock->ht, &iter.iter, app,
			node.node) {
		if (app->domain != domain) {
			continue;
		}

		ret = app_context_op(app, ctx, AGENT_CMD_APP_CTX_DISABLE);
		if (ret != LTTNG_OK) {
			goto end;
		}
	}
end:
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
	lttng_ht_add_unique_ulong(agent_apps_ht_by_sock, &app->node);
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
 * Destroy an agent application object by detaching it from its corresponding
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

	CDS_INIT_LIST_HEAD(&agt->app_ctx_list);
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

	lttng_ht_add_unique_u64(ht, &agt->node);
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

	agt = zmalloc(sizeof(struct agent));
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
 * Create a newly allocated agent event data structure.
 * Ownership of filter_expression is taken.
 *
 * Return a new object else NULL on error.
 */
struct agent_event *agent_create_event(const char *name,
		enum lttng_loglevel_type loglevel_type, int loglevel_value,
		struct lttng_filter_bytecode *filter, char *filter_expression)
{
	struct agent_event *event = NULL;

	DBG3("Agent create new event with name %s, loglevel type %d, \
			loglevel value %d and filter %s",
			name, loglevel_type, loglevel_value,
			filter_expression ? filter_expression : "NULL");

	if (!name) {
		ERR("Failed to create agent event; no name provided.");
		goto error;
	}

	event = zmalloc(sizeof(*event));
	if (!event) {
		goto error;
	}

	strncpy(event->name, name, sizeof(event->name));
	event->name[sizeof(event->name) - 1] = '\0';
	lttng_ht_node_init_str(&event->node, event->name);

	event->loglevel_value = loglevel_value;
	event->loglevel_type = loglevel_type;
	event->filter = filter;
	event->filter_expression = filter_expression;
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
	add_unique_agent_event(agt->events, event);
	agt->being_used = 1;
}

/*
 * Unique add of a agent context to an agent object.
 */
int agent_add_context(struct lttng_event_context *ctx, struct agent *agt)
{
	int ret = LTTNG_OK;
	struct agent_app_ctx *agent_ctx = NULL;

	assert(ctx);
	assert(agt);
	assert(agt->events);
	assert(ctx->ctx == LTTNG_EVENT_CONTEXT_APP_CONTEXT);

	agent_ctx = create_app_ctx(ctx);
	if (!agent_ctx) {
		ret = LTTNG_ERR_NOMEM;
		goto end;
	}

	DBG3("Agent adding context %s:%s", ctx->u.app_ctx.provider_name,
			ctx->u.app_ctx.ctx_name);
	cds_list_add_tail_rcu(&agent_ctx->list_node, &agt->app_ctx_list);
end:
	return ret;
}

/*
 * Find multiple agent events sharing the given name.
 *
 * RCU read side lock MUST be acquired. It must be held for the
 * duration of the iteration.
 *
 * Sets the given iterator.
 */
void agent_find_events_by_name(const char *name, struct agent *agt,
		struct lttng_ht_iter* iter)
{
	struct lttng_ht *ht;
	struct agent_ht_key key;

	assert(name);
	assert(agt);
	assert(agt->events);
	assert(iter);

	ht = agt->events;
	key.name = name;

	cds_lfht_lookup(ht->ht, ht->hash_fct((void *) name, lttng_ht_seed),
			ht_match_event_by_name, &key, &iter->iter);
}

/*
 * Get the next agent event duplicate by name. This should be called
 * after a call to agent_find_events_by_name() to iterate on events.
 *
 * The RCU read lock must be held during the iteration and for as long
 * as the object the iterator points to remains in use.
 */
void agent_event_next_duplicate(const char *name,
		struct agent *agt, struct lttng_ht_iter* iter)
{
	struct agent_ht_key key;

	key.name = name;

	cds_lfht_next_duplicate(agt->events->ht, ht_match_event_by_name,
		&key, &iter->iter);
}

/*
 * Find a agent event in the given agent using name, loglevel and filter.
 *
 * RCU read side lock MUST be acquired. It must be kept for as long as
 * the returned agent_event is used.
 *
 * Return object if found else NULL.
 */
struct agent_event *agent_find_event(const char *name,
		enum lttng_loglevel_type loglevel_type, int loglevel_value,
		char *filter_expression, struct agent *agt)
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
	key.loglevel_value = loglevel_value;
	key.loglevel_type = loglevel_type;
	key.filter_expression = filter_expression;

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
	free(event->filter_expression);
	free(event->exclusion);
	free(event);
}

static
void destroy_app_ctx_rcu(struct rcu_head *head)
{
	struct agent_app_ctx *ctx =
			caa_container_of(head, struct agent_app_ctx, rcu_node);

	destroy_app_ctx(ctx);
}

/*
 * Destroy an agent completely.
 */
void agent_destroy(struct agent *agt)
{
	struct lttng_ht_node_str *node;
	struct lttng_ht_iter iter;
	struct agent_app_ctx *ctx;

	assert(agt);

	DBG3("Agent destroy");

	rcu_read_lock();
	cds_lfht_for_each_entry(agt->events->ht, &iter.iter, node, node) {
		int ret;
		struct agent_event *event;

		/*
		 * When destroying an event, we have to try to disable it on the
		 * agent side so the event stops generating data. The return
		 * value is not important since we have to continue anyway
		 * destroying the object.
		 */
		event = caa_container_of(node, struct agent_event, node);
		(void) agent_disable_event(event, agt->domain);

		ret = lttng_ht_del(agt->events, &iter);
		assert(!ret);
		call_rcu(&node->head, destroy_event_agent_rcu);
	}

	cds_list_for_each_entry_rcu(ctx, &agt->app_ctx_list, list_node) {
		(void) disable_context(ctx, agt->domain);
		cds_list_del(&ctx->list_node);
		call_rcu(&ctx->rcu_node, destroy_app_ctx_rcu);
	}
	rcu_read_unlock();
	ht_cleanup_push(agt->events);
	free(agt);
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
	struct agent_app_ctx *ctx;

	assert(agt);
	assert(sock >= 0);

	DBG("Agent updating app socket %d", sock);

	rcu_read_lock();
	app = agent_find_app_by_sock(sock);
	/*
	 * We are in the registration path thus if the application is gone,
	 * there is a serious code flow error.
	 */
	assert(app);
	cds_lfht_for_each_entry(agt->events->ht, &iter.iter, event, node.node) {
		/* Skip event if disabled. */
		if (!event->enabled) {
			continue;
		}

		ret = enable_event(app, event);
		if (ret != LTTNG_OK) {
			DBG2("Agent update unable to enable event %s on app pid: %d sock %d",
					event->name, app->pid, app->sock->fd);
			/* Let's try the others here and don't assume the app is dead. */
			continue;
		}
	}

	cds_list_for_each_entry_rcu(ctx, &agt->app_ctx_list, list_node) {
		ret = app_context_op(app, ctx, AGENT_CMD_APP_CTX_ENABLE);
		if (ret != LTTNG_OK) {
			DBG2("Agent update unable to add application context %s:%s on app pid: %d sock %d",
					ctx->provider_name, ctx->ctx_name,
					app->pid, app->sock->fd);
			continue;
		}
	}

	rcu_read_unlock();
}
