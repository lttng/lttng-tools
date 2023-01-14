/*
 * Copyright (C) 2019 Simon Marchi <simon.marchi@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <common/error.hpp>
#include <common/macros.hpp>
#include <common/mi-lttng.hpp>

#include <lttng/action/action-internal.hpp>
#include <lttng/action/rate-policy-internal.hpp>
#include <lttng/action/rate-policy.h>
#include <lttng/action/start-session-internal.hpp>
#include <lttng/action/start-session.h>

#define IS_START_SESSION_ACTION(action) \
	(lttng_action_get_type(action) == LTTNG_ACTION_TYPE_START_SESSION)

namespace {
struct lttng_action_start_session {
	struct lttng_action parent;

	/* Owned by this. */
	char *session_name;
	struct lttng_rate_policy *policy;
};

struct lttng_action_start_session_comm {
	/* Includes the trailing \0. */
	uint32_t session_name_len;

	/*
	 * Variable data:
	 *
	 *  - session name (null terminated)
	 *  - policy
	 */
	char data[];
} LTTNG_PACKED;
} /* namespace */

static const struct lttng_rate_policy *
lttng_action_start_session_internal_get_rate_policy(const struct lttng_action *action);

static struct lttng_action_start_session *
action_start_session_from_action(struct lttng_action *action)
{
	LTTNG_ASSERT(action);

	return lttng::utils::container_of(action, &lttng_action_start_session::parent);
}

static const struct lttng_action_start_session *
action_start_session_from_action_const(const struct lttng_action *action)
{
	LTTNG_ASSERT(action);

	return lttng::utils::container_of(action, &lttng_action_start_session::parent);
}

static bool lttng_action_start_session_validate(struct lttng_action *action)
{
	bool valid;
	struct lttng_action_start_session *action_start_session;

	if (!action) {
		valid = false;
		goto end;
	}

	action_start_session = action_start_session_from_action(action);

	/* A non-empty session name is mandatory. */
	if (!action_start_session->session_name ||
	    strlen(action_start_session->session_name) == 0) {
		valid = false;
		goto end;
	}

	valid = true;
end:
	return valid;
}

static bool lttng_action_start_session_is_equal(const struct lttng_action *_a,
						const struct lttng_action *_b)
{
	bool is_equal = false;
	struct lttng_action_start_session *a, *b;

	a = lttng::utils::container_of(_a, &lttng_action_start_session::parent);
	b = lttng::utils::container_of(_b, &lttng_action_start_session::parent);

	/* Action is not valid if this is not true. */
	LTTNG_ASSERT(a->session_name);
	LTTNG_ASSERT(b->session_name);
	if (strcmp(a->session_name, b->session_name) != 0) {
		goto end;
	}

	is_equal = lttng_rate_policy_is_equal(a->policy, b->policy);
end:
	return is_equal;
}

static int lttng_action_start_session_serialize(struct lttng_action *action,
						struct lttng_payload *payload)
{
	struct lttng_action_start_session *action_start_session;
	struct lttng_action_start_session_comm comm;
	size_t session_name_len;
	int ret;

	LTTNG_ASSERT(action);
	LTTNG_ASSERT(payload);

	action_start_session = action_start_session_from_action(action);

	LTTNG_ASSERT(action_start_session->session_name);

	DBG("Serializing start session action: session-name: %s",
	    action_start_session->session_name);

	session_name_len = strlen(action_start_session->session_name) + 1;
	comm.session_name_len = session_name_len;

	ret = lttng_dynamic_buffer_append(&payload->buffer, &comm, sizeof(comm));
	if (ret) {
		ret = -1;
		goto end;
	}

	ret = lttng_dynamic_buffer_append(
		&payload->buffer, action_start_session->session_name, session_name_len);
	if (ret) {
		ret = -1;
		goto end;
	}

	ret = lttng_rate_policy_serialize(action_start_session->policy, payload);
	if (ret) {
		ret = -1;
		goto end;
	}

	ret = 0;
end:
	return ret;
}

static void lttng_action_start_session_destroy(struct lttng_action *action)
{
	struct lttng_action_start_session *action_start_session;

	if (!action) {
		goto end;
	}

	action_start_session = action_start_session_from_action(action);

	lttng_rate_policy_destroy(action_start_session->policy);
	free(action_start_session->session_name);
	free(action_start_session);

end:
	return;
}

ssize_t lttng_action_start_session_create_from_payload(struct lttng_payload_view *view,
						       struct lttng_action **p_action)
{
	ssize_t consumed_len, ret;
	const struct lttng_action_start_session_comm *comm;
	const char *session_name;
	struct lttng_action *action = nullptr;
	enum lttng_action_status status;
	struct lttng_rate_policy *policy = nullptr;

	comm = (typeof(comm)) view->buffer.data;
	session_name = (const char *) &comm->data;

	/* Session name */
	if (!lttng_buffer_view_contains_string(
		    &view->buffer, session_name, comm->session_name_len)) {
		consumed_len = -1;
		goto end;
	}
	consumed_len = sizeof(*comm) + comm->session_name_len;

	/* Rate policy. */
	{
		struct lttng_payload_view policy_view =
			lttng_payload_view_from_view(view, consumed_len, -1);
		ret = lttng_rate_policy_create_from_payload(&policy_view, &policy);
		if (ret < 0) {
			consumed_len = -1;
			goto end;
		}
		consumed_len += ret;
	}

	action = lttng_action_start_session_create();
	if (!action) {
		consumed_len = -1;
		goto end;
	}

	status = lttng_action_start_session_set_session_name(action, session_name);
	if (status != LTTNG_ACTION_STATUS_OK) {
		consumed_len = -1;
		goto end;
	}

	LTTNG_ASSERT(policy);
	status = lttng_action_start_session_set_rate_policy(action, policy);
	if (status != LTTNG_ACTION_STATUS_OK) {
		consumed_len = -1;
		goto end;
	}

	*p_action = action;
	action = nullptr;

end:
	lttng_rate_policy_destroy(policy);
	lttng_action_start_session_destroy(action);

	return consumed_len;
}

static enum lttng_error_code
lttng_action_start_session_mi_serialize(const struct lttng_action *action, struct mi_writer *writer)
{
	int ret;
	enum lttng_error_code ret_code;
	enum lttng_action_status status;
	const char *session_name = nullptr;
	const struct lttng_rate_policy *policy = nullptr;

	LTTNG_ASSERT(action);
	LTTNG_ASSERT(IS_START_SESSION_ACTION(action));

	status = lttng_action_start_session_get_session_name(action, &session_name);
	LTTNG_ASSERT(status == LTTNG_ACTION_STATUS_OK);
	LTTNG_ASSERT(session_name != nullptr);

	status = lttng_action_start_session_get_rate_policy(action, &policy);
	LTTNG_ASSERT(status == LTTNG_ACTION_STATUS_OK);
	LTTNG_ASSERT(policy != nullptr);

	/* Open action start session element. */
	ret = mi_lttng_writer_open_element(writer, mi_lttng_element_action_start_session);
	if (ret) {
		goto mi_error;
	}

	/* Session name. */
	ret = mi_lttng_writer_write_element_string(
		writer, mi_lttng_element_session_name, session_name);
	if (ret) {
		goto mi_error;
	}

	/* Rate policy. */
	ret_code = lttng_rate_policy_mi_serialize(policy, writer);
	if (ret_code != LTTNG_OK) {
		goto end;
	}

	/* Close action start session element. */
	ret = mi_lttng_writer_close_element(writer);
	if (ret) {
		goto mi_error;
	}

	ret_code = LTTNG_OK;
	goto end;

mi_error:
	ret_code = LTTNG_ERR_MI_IO_FAIL;
end:
	return ret_code;
}

struct lttng_action *lttng_action_start_session_create(void)
{
	struct lttng_action_start_session *action_start = nullptr;
	struct lttng_rate_policy *policy = nullptr;
	enum lttng_action_status status;

	/* Create a every N = 1 rate policy. */
	policy = lttng_rate_policy_every_n_create(1);
	if (!policy) {
		goto end;
	}

	action_start = zmalloc<lttng_action_start_session>();
	if (!action_start) {
		goto end;
	}

	lttng_action_init(&action_start->parent,
			  LTTNG_ACTION_TYPE_START_SESSION,
			  lttng_action_start_session_validate,
			  lttng_action_start_session_serialize,
			  lttng_action_start_session_is_equal,
			  lttng_action_start_session_destroy,
			  lttng_action_start_session_internal_get_rate_policy,
			  lttng_action_generic_add_error_query_results,
			  lttng_action_start_session_mi_serialize);

	status = lttng_action_start_session_set_rate_policy(&action_start->parent, policy);
	if (status != LTTNG_ACTION_STATUS_OK) {
		lttng_action_destroy(&action_start->parent);
		action_start = nullptr;
		goto end;
	}

end:
	lttng_rate_policy_destroy(policy);
	return &action_start->parent;
}

enum lttng_action_status lttng_action_start_session_set_session_name(struct lttng_action *action,
								     const char *session_name)
{
	struct lttng_action_start_session *action_start_session;
	enum lttng_action_status status;

	if (!action || !IS_START_SESSION_ACTION(action) || !session_name ||
	    strlen(session_name) == 0) {
		status = LTTNG_ACTION_STATUS_INVALID;
		goto end;
	}

	action_start_session = action_start_session_from_action(action);

	free(action_start_session->session_name);

	action_start_session->session_name = strdup(session_name);
	if (!action_start_session->session_name) {
		status = LTTNG_ACTION_STATUS_ERROR;
		goto end;
	}

	status = LTTNG_ACTION_STATUS_OK;
end:
	return status;
}

enum lttng_action_status
lttng_action_start_session_get_session_name(const struct lttng_action *action,
					    const char **session_name)
{
	const struct lttng_action_start_session *action_start_session;
	enum lttng_action_status status;

	if (!action || !IS_START_SESSION_ACTION(action) || !session_name) {
		status = LTTNG_ACTION_STATUS_INVALID;
		goto end;
	}

	action_start_session = action_start_session_from_action_const(action);

	*session_name = action_start_session->session_name;

	status = LTTNG_ACTION_STATUS_OK;
end:
	return status;
}

enum lttng_action_status
lttng_action_start_session_set_rate_policy(struct lttng_action *action,
					   const struct lttng_rate_policy *policy)
{
	enum lttng_action_status status;
	struct lttng_action_start_session *start_session_action;
	struct lttng_rate_policy *copy = nullptr;

	if (!action || !policy || !IS_START_SESSION_ACTION(action)) {
		status = LTTNG_ACTION_STATUS_INVALID;
		goto end;
	}

	copy = lttng_rate_policy_copy(policy);
	if (!copy) {
		status = LTTNG_ACTION_STATUS_ERROR;
		goto end;
	}

	start_session_action = action_start_session_from_action(action);

	/* Release the previous rate policy .*/
	lttng_rate_policy_destroy(start_session_action->policy);

	/* Assign the policy. */
	start_session_action->policy = copy;
	status = LTTNG_ACTION_STATUS_OK;
	copy = nullptr;

end:
	lttng_rate_policy_destroy(copy);
	return status;
}

enum lttng_action_status
lttng_action_start_session_get_rate_policy(const struct lttng_action *action,
					   const struct lttng_rate_policy **policy)
{
	enum lttng_action_status status;
	const struct lttng_action_start_session *start_session_action;

	if (!action || !policy || !IS_START_SESSION_ACTION(action)) {
		status = LTTNG_ACTION_STATUS_INVALID;
		goto end;
	}

	start_session_action = action_start_session_from_action_const(action);

	*policy = start_session_action->policy;
	status = LTTNG_ACTION_STATUS_OK;
end:
	return status;
}

static const struct lttng_rate_policy *
lttng_action_start_session_internal_get_rate_policy(const struct lttng_action *action)
{
	const struct lttng_action_start_session *_action;
	_action = action_start_session_from_action_const(action);

	return _action->policy;
}
