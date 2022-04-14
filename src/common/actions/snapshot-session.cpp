/*
 * Copyright (C) 2019 Simon Marchi <simon.marchi@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <common/error.hpp>
#include <common/macros.hpp>
#include <common/mi-lttng.hpp>
#include <common/payload-view.hpp>
#include <common/payload.hpp>
#include <common/snapshot.hpp>
#include <inttypes.h>
#include <lttng/action/action-internal.hpp>
#include <lttng/action/rate-policy-internal.hpp>
#include <lttng/action/rate-policy.h>
#include <lttng/action/snapshot-session-internal.hpp>
#include <lttng/action/snapshot-session.h>
#include <lttng/snapshot-internal.hpp>
#include <lttng/snapshot.h>

#define IS_SNAPSHOT_SESSION_ACTION(action) \
	(lttng_action_get_type(action) == LTTNG_ACTION_TYPE_SNAPSHOT_SESSION)

namespace {
struct lttng_action_snapshot_session {
	struct lttng_action parent;

	/* Owned by this. */
	char *session_name;

	/*
	 * When non-NULL, use this custom output when taking the snapshot,
	 * rather than the session's registered snapshot output.
	 *
	 * Owned by this.
	 */
	struct lttng_snapshot_output *output;
	struct lttng_rate_policy *policy;
};

struct lttng_action_snapshot_session_comm {
	/* All string lengths include the trailing \0. */
	uint32_t session_name_len;
	uint32_t snapshot_output_len;
	uint32_t rate_policy_len;

	/*
	 * Variable data (all strings are null-terminated):
	 *
	 *  - session name string
	 *  - snapshot output object
	 *  - policy object
	 */
	char data[];
} LTTNG_PACKED;
} /* namespace */

static const struct lttng_rate_policy *
lttng_action_snapshot_session_internal_get_rate_policy(
		const struct lttng_action *action);

static struct lttng_action_snapshot_session *
action_snapshot_session_from_action(struct lttng_action *action)
{
	LTTNG_ASSERT(action);

	return container_of(
			action, struct lttng_action_snapshot_session, parent);
}

static const struct lttng_action_snapshot_session *
action_snapshot_session_from_action_const(const struct lttng_action *action)
{
	LTTNG_ASSERT(action);

	return container_of(
			action, struct lttng_action_snapshot_session, parent);
}

static bool lttng_action_snapshot_session_validate(struct lttng_action *action)
{
	bool valid = false;
	struct lttng_action_snapshot_session *action_snapshot_session;

	if (!action) {
		goto end;
	}

	action_snapshot_session = action_snapshot_session_from_action(action);

	/* A non-empty session name is mandatory. */
	if (!action_snapshot_session->session_name ||
			strlen(action_snapshot_session->session_name) == 0) {
		goto end;
	}

	if (action_snapshot_session->output &&
			!lttng_snapshot_output_validate(action_snapshot_session->output)) {
		goto end;
	}

	valid = true;
end:
	return valid;
}

static bool lttng_action_snapshot_session_is_equal(
		const struct lttng_action *_a, const struct lttng_action *_b)
{
	bool is_equal = false;
	const struct lttng_action_snapshot_session *a, *b;

	a = action_snapshot_session_from_action_const(_a);
	b = action_snapshot_session_from_action_const(_b);

	/* Action is not valid if this is not true. */
	LTTNG_ASSERT(a->session_name);
	LTTNG_ASSERT(b->session_name);
	if (strcmp(a->session_name, b->session_name)) {
		goto end;
	}

	if (a->output && b->output &&
			!lttng_snapshot_output_is_equal(a->output, b->output)) {
		goto end;
	} else if (!!a->output != !!b->output) {
		goto end;
	}

	is_equal = lttng_rate_policy_is_equal(a->policy, b->policy);
end:
	return is_equal;
}

static size_t serialize_strlen(const char *str)
{
	return str ? strlen(str) + 1 : 0;
}

static int lttng_action_snapshot_session_serialize(
		struct lttng_action *action, struct lttng_payload *payload)
{
	struct lttng_action_snapshot_session *action_snapshot_session;
	struct lttng_action_snapshot_session_comm comm = {};
	int ret;
	size_t size_before_comm;

	LTTNG_ASSERT(action);
	LTTNG_ASSERT(payload);

	size_before_comm = payload->buffer.size;

	action_snapshot_session = action_snapshot_session_from_action(action);
	comm.session_name_len =
		serialize_strlen(action_snapshot_session->session_name);

	/* Add header. */
	ret = lttng_dynamic_buffer_append(
			&payload->buffer, &comm, sizeof(comm));
	if (ret) {
		goto end;
	}

	LTTNG_ASSERT(action_snapshot_session->session_name);
	DBG("Serializing snapshot session action: session-name: %s",
			action_snapshot_session->session_name);

	/* Add session name. */
	ret = lttng_dynamic_buffer_append(&payload->buffer,
			action_snapshot_session->session_name,
			comm.session_name_len);
	if (ret) {
		goto end;
	}

	/* Serialize the snapshot output object, if any. */
	if (action_snapshot_session->output) {
		const size_t size_before_output = payload->buffer.size;
		struct lttng_action_snapshot_session_comm *comm_in_payload;

		ret = lttng_snapshot_output_serialize(
				action_snapshot_session->output,
				payload);
		if (ret) {
			goto end;
		}

		comm_in_payload = (typeof(comm_in_payload))(
				payload->buffer.data + size_before_comm);
		/* Adjust action length in header. */
		comm_in_payload->snapshot_output_len =
				payload->buffer.size - size_before_output;
	}

	/* Serialize the rate policy. */
	{
		const size_t size_before_output = payload->buffer.size;
		struct lttng_action_snapshot_session_comm *comm_in_payload;

		ret = lttng_rate_policy_serialize(
				action_snapshot_session->policy, payload);
		if (ret) {
			ret = -1;
			goto end;
		}

		comm_in_payload = (typeof(comm_in_payload))(
				payload->buffer.data + size_before_comm);
		/* Adjust rate policy length in header. */
		comm_in_payload->rate_policy_len =
				payload->buffer.size - size_before_output;
	}

end:
	return ret;
}

static void lttng_action_snapshot_session_destroy(struct lttng_action *action)
{
	struct lttng_action_snapshot_session *action_snapshot_session;

	if (!action) {
		goto end;
	}

	action_snapshot_session = action_snapshot_session_from_action(action);

	free(action_snapshot_session->session_name);
	lttng_snapshot_output_destroy(action_snapshot_session->output);
	lttng_rate_policy_destroy(action_snapshot_session->policy);
	free(action_snapshot_session);

end:
	return;
}

ssize_t lttng_action_snapshot_session_create_from_payload(
		struct lttng_payload_view *view,
		struct lttng_action **p_action)
{
	ssize_t consumed_len;
	const char *variable_data;
	struct lttng_action *action;
	enum lttng_action_status status;
	struct lttng_snapshot_output *snapshot_output = NULL;
	struct lttng_rate_policy *policy = NULL;
	const struct lttng_action_snapshot_session_comm *comm;
	const struct lttng_payload_view snapshot_session_comm_view =
			lttng_payload_view_from_view(
				view, 0, sizeof(*comm));

	action = lttng_action_snapshot_session_create();
	if (!action) {
		goto error;
	}

	if (!lttng_payload_view_is_valid(&snapshot_session_comm_view)) {
		/* Payload not large enough to contain the header. */
		goto error;
	}

	comm = (typeof(comm)) snapshot_session_comm_view.buffer.data;
	variable_data = (const char *) &comm->data;

	consumed_len = sizeof(struct lttng_action_snapshot_session_comm);

	if (!lttng_buffer_view_contains_string(
			&view->buffer, variable_data, comm->session_name_len)) {
		goto error;
	}

	status = lttng_action_snapshot_session_set_session_name(
			action, variable_data);
	if (status != LTTNG_ACTION_STATUS_OK) {
		goto error;
	}

	variable_data += comm->session_name_len;
	consumed_len += comm->session_name_len;

	/* If there is a snapshot output object, deserialize it. */
	if (comm->snapshot_output_len > 0) {
		ssize_t snapshot_output_consumed_len;
		enum lttng_action_status action_status;
		struct lttng_payload_view snapshot_output_buffer_view =
			lttng_payload_view_from_view(view, consumed_len,
				comm->snapshot_output_len);

		if (!lttng_payload_view_is_valid(&snapshot_output_buffer_view)) {
			ERR("Failed to create buffer view for snapshot output.");
			goto error;
		}

		snapshot_output_consumed_len =
				lttng_snapshot_output_create_from_payload(
						&snapshot_output_buffer_view,
						&snapshot_output);
		if (snapshot_output_consumed_len != comm->snapshot_output_len) {
			ERR("Failed to deserialize snapshot output object: "
					"consumed-len: %zd, expected-len: %" PRIu32,
					snapshot_output_consumed_len,
					comm->snapshot_output_len);
			goto error;
		}

		action_status = lttng_action_snapshot_session_set_output(
			action, snapshot_output);
		if (action_status != LTTNG_ACTION_STATUS_OK) {
			goto error;
		}

		/* Ownership has been transferred to the action. */
		snapshot_output = NULL;
	}

	variable_data += comm->snapshot_output_len;
	consumed_len += comm->snapshot_output_len;

	/* Rate policy. */
	if (comm->rate_policy_len <= 0) {
		ERR("Rate policy should be present.");
		goto error;
	}
	{
		ssize_t rate_policy_consumed_len;
		struct lttng_payload_view policy_view =
				lttng_payload_view_from_view(view, consumed_len,
						comm->rate_policy_len);

		if (!lttng_payload_view_is_valid(&policy_view)) {
			ERR("Failed to create buffer view for rate policy.");
			goto error;
		}

		rate_policy_consumed_len =
				lttng_rate_policy_create_from_payload(
						&policy_view, &policy);
		if (rate_policy_consumed_len < 0) {
			goto error;
		}

		if (rate_policy_consumed_len != comm->rate_policy_len) {
			ERR("Failed to deserialize rate policy object: "
			    "consumed-len: %zd, expected-len: %" PRIu32,
					rate_policy_consumed_len,
					comm->rate_policy_len);
			goto error;
		}

		status = lttng_action_snapshot_session_set_rate_policy(
				action, policy);
		if (status != LTTNG_ACTION_STATUS_OK) {
			goto error;
		}
	}

	variable_data += comm->rate_policy_len;
	consumed_len += comm->rate_policy_len;

	*p_action = action;
	action = NULL;

	goto end;

error:
	consumed_len = -1;

end:
	lttng_rate_policy_destroy(policy);
	lttng_action_snapshot_session_destroy(action);
	lttng_snapshot_output_destroy(snapshot_output);

	return consumed_len;
}

static enum lttng_error_code lttng_action_snapshot_session_mi_serialize(
		const struct lttng_action *action, struct mi_writer *writer)
{
	int ret;
	enum lttng_error_code ret_code;
	enum lttng_action_status status;
	const char *session_name = NULL;
	const struct lttng_snapshot_output *output = NULL;
	const struct lttng_rate_policy *policy = NULL;

	LTTNG_ASSERT(action);
	LTTNG_ASSERT(IS_SNAPSHOT_SESSION_ACTION(action));

	status = lttng_action_snapshot_session_get_session_name(
			action, &session_name);
	LTTNG_ASSERT(status == LTTNG_ACTION_STATUS_OK);
	LTTNG_ASSERT(session_name != NULL);

	status = lttng_action_snapshot_session_get_rate_policy(action, &policy);
	LTTNG_ASSERT(status == LTTNG_ACTION_STATUS_OK);
	LTTNG_ASSERT(policy != NULL);

	/* Open action snapshot session element. */
	ret = mi_lttng_writer_open_element(
			writer, mi_lttng_element_action_snapshot_session);
	if (ret) {
		goto mi_error;
	}

	/* Session name. */
	ret = mi_lttng_writer_write_element_string(
			writer, mi_lttng_element_session_name, session_name);
	if (ret) {
		goto mi_error;
	}

	/* Output if any. */
	status = lttng_action_snapshot_session_get_output(action, &output);
	if (status == LTTNG_ACTION_STATUS_OK) {
		LTTNG_ASSERT(output != NULL);
		ret_code = lttng_snapshot_output_mi_serialize(output, writer);
		if (ret_code != LTTNG_OK) {
			goto end;
		}
	} else if (status != LTTNG_ACTION_STATUS_UNSET) {
		/* This should not happen at this point. */
		abort();
	}

	/* Rate policy. */
	ret_code = lttng_rate_policy_mi_serialize(policy, writer);
	if (ret_code != LTTNG_OK) {
		goto end;
	}

	/* Close action_snapshot_session element. */
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

struct lttng_action *lttng_action_snapshot_session_create(void)
{
	struct lttng_action_snapshot_session *action_snapshot = NULL;
	struct lttng_rate_policy *policy = NULL;
	enum lttng_action_status status;

	/* Create a every N = 1 rate policy. */
	policy = lttng_rate_policy_every_n_create(1);
	if (!policy) {
		goto end;
	}

	action_snapshot = zmalloc<lttng_action_snapshot_session>();
	if (!action_snapshot) {
		goto end;
	}

	lttng_action_init(&action_snapshot->parent,
			LTTNG_ACTION_TYPE_SNAPSHOT_SESSION,
			lttng_action_snapshot_session_validate,
			lttng_action_snapshot_session_serialize,
			lttng_action_snapshot_session_is_equal,
			lttng_action_snapshot_session_destroy,
			lttng_action_snapshot_session_internal_get_rate_policy,
			lttng_action_generic_add_error_query_results,
			lttng_action_snapshot_session_mi_serialize);

	status = lttng_action_snapshot_session_set_rate_policy(
			&action_snapshot->parent, policy);
	if (status != LTTNG_ACTION_STATUS_OK) {
		lttng_action_destroy(&action_snapshot->parent);
		action_snapshot = NULL;
		goto end;
	}

end:
	lttng_rate_policy_destroy(policy);
	return action_snapshot ? &action_snapshot->parent : nullptr;
}

enum lttng_action_status lttng_action_snapshot_session_set_session_name(
		struct lttng_action *action, const char *session_name)
{
	struct lttng_action_snapshot_session *action_snapshot_session;
	enum lttng_action_status status;

	if (!action || !IS_SNAPSHOT_SESSION_ACTION(action) || !session_name ||
			strlen(session_name) == 0) {
		status = LTTNG_ACTION_STATUS_INVALID;
		goto end;
	}

	action_snapshot_session = action_snapshot_session_from_action(action);

	free(action_snapshot_session->session_name);

	action_snapshot_session->session_name = strdup(session_name);
	if (!action_snapshot_session->session_name) {
		status = LTTNG_ACTION_STATUS_ERROR;
		goto end;
	}

	status = LTTNG_ACTION_STATUS_OK;
end:
	return status;
}

enum lttng_action_status lttng_action_snapshot_session_get_session_name(
		const struct lttng_action *action, const char **session_name)
{
	const struct lttng_action_snapshot_session *action_snapshot_session;
	enum lttng_action_status status;

	if (!action || !IS_SNAPSHOT_SESSION_ACTION(action) || !session_name) {
		status = LTTNG_ACTION_STATUS_INVALID;
		goto end;
	}

	action_snapshot_session = action_snapshot_session_from_action_const(action);

	if (action_snapshot_session->session_name) {
		*session_name = action_snapshot_session->session_name;
		status = LTTNG_ACTION_STATUS_OK;
	} else {
		status = LTTNG_ACTION_STATUS_UNSET;
	}

end:

	return status;
}

enum lttng_action_status lttng_action_snapshot_session_set_output(
		struct lttng_action *action,
		struct lttng_snapshot_output *output)
{
	struct lttng_action_snapshot_session *action_snapshot_session;
	enum lttng_action_status status;

	if (!action || !IS_SNAPSHOT_SESSION_ACTION(action) || !output) {
		status = LTTNG_ACTION_STATUS_INVALID;
		goto end;
	}

	action_snapshot_session = action_snapshot_session_from_action(action);

	lttng_snapshot_output_destroy(action_snapshot_session->output);
	action_snapshot_session->output = output;

	status = LTTNG_ACTION_STATUS_OK;

end:
	return status;
}

enum lttng_action_status lttng_action_snapshot_session_get_output(
		const struct lttng_action *action,
		const struct lttng_snapshot_output **output)
{
	const struct lttng_action_snapshot_session *action_snapshot_session;
	enum lttng_action_status status;

	if (!action || !IS_SNAPSHOT_SESSION_ACTION(action)|| !output) {
		status = LTTNG_ACTION_STATUS_INVALID;
		goto end;
	}

	action_snapshot_session = action_snapshot_session_from_action_const(action);

	if (action_snapshot_session->output) {
		*output = action_snapshot_session->output;
		status = LTTNG_ACTION_STATUS_OK;
	} else {
		status = LTTNG_ACTION_STATUS_UNSET;
	}

end:
	return status;
}

enum lttng_action_status lttng_action_snapshot_session_set_rate_policy(
		struct lttng_action *action,
		const struct lttng_rate_policy *policy)
{
	enum lttng_action_status status;
	struct lttng_action_snapshot_session *snapshot_session_action;
	struct lttng_rate_policy *copy = NULL;

	if (!action || !policy || !IS_SNAPSHOT_SESSION_ACTION(action)) {
		status = LTTNG_ACTION_STATUS_INVALID;
		goto end;
	}

	copy = lttng_rate_policy_copy(policy);
	if (!copy) {
		status = LTTNG_ACTION_STATUS_ERROR;
		goto end;
	}

	snapshot_session_action = action_snapshot_session_from_action(action);

	/* Free the previous rate policy .*/
	lttng_rate_policy_destroy(snapshot_session_action->policy);

	/* Assign the policy. */
	snapshot_session_action->policy = copy;
	status = LTTNG_ACTION_STATUS_OK;
	copy = NULL;

end:
	lttng_rate_policy_destroy(copy);
	return status;
}

enum lttng_action_status lttng_action_snapshot_session_get_rate_policy(
		const struct lttng_action *action,
		const struct lttng_rate_policy **policy)
{
	enum lttng_action_status status;
	const struct lttng_action_snapshot_session *snapshot_session_action;

	if (!action || !policy || !IS_SNAPSHOT_SESSION_ACTION(action)) {
		status = LTTNG_ACTION_STATUS_INVALID;
		goto end;
	}

	snapshot_session_action =
			action_snapshot_session_from_action_const(action);

	*policy = snapshot_session_action->policy;
	status = LTTNG_ACTION_STATUS_OK;
end:
	return status;
}

static const struct lttng_rate_policy *
lttng_action_snapshot_session_internal_get_rate_policy(
		const struct lttng_action *action)
{
	const struct lttng_action_snapshot_session *_action;
	_action = action_snapshot_session_from_action_const(action);

	return _action->policy;
}
