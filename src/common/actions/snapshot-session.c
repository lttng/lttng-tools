/*
 * Copyright (C) 2019 Simon Marchi <simon.marchi@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <assert.h>
#include <common/error.h>
#include <common/macros.h>
#include <common/snapshot.h>
#include <common/payload.h>
#include <common/payload-view.h>
#include <lttng/action/action-internal.h>
#include <lttng/action/snapshot-session-internal.h>
#include <lttng/action/snapshot-session.h>
#include <lttng/snapshot.h>
#include <lttng/snapshot-internal.h>
#include <inttypes.h>

#define IS_SNAPSHOT_SESSION_ACTION(action) \
	(lttng_action_get_type(action) == LTTNG_ACTION_TYPE_SNAPSHOT_SESSION)

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
};

struct lttng_action_snapshot_session_comm {
	/* All string lengths include the trailing \0. */
	uint32_t session_name_len;
	uint32_t snapshot_output_len;

	/*
	 * Variable data (all strings are null-terminated):
	 *
	 *  - session name string
	 *  - snapshot output object
	 *
	 */
	char data[];
} LTTNG_PACKED;

static struct lttng_action_snapshot_session *
action_snapshot_session_from_action(struct lttng_action *action)
{
	assert(action);

	return container_of(
			action, struct lttng_action_snapshot_session, parent);
}

static const struct lttng_action_snapshot_session *
action_snapshot_session_from_action_const(const struct lttng_action *action)
{
	assert(action);

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
	assert(a->session_name);
	assert(b->session_name);
	if (strcmp(a->session_name, b->session_name)) {
		goto end;
	}

	if (a->output && b->output &&
			!lttng_snapshot_output_is_equal(a->output, b->output)) {
		goto end;
	} else if (!!a->output != !!b->output) {
		goto end;
	}

	is_equal = true;
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

	assert(action);
	assert(payload);

	size_before_comm = payload->buffer.size;
	size_before_comm = size_before_comm + sizeof(comm);

	action_snapshot_session = action_snapshot_session_from_action(action);
	comm.session_name_len =
		serialize_strlen(action_snapshot_session->session_name);

	/* Add header. */
	ret = lttng_dynamic_buffer_append(
			&payload->buffer, &comm, sizeof(comm));
	if (ret) {
		goto end;
	}

	assert(action_snapshot_session->session_name);
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

		/* Adjust action length in header. */
		comm_in_payload = (typeof(comm_in_payload))(
				payload->buffer.data + size_before_comm);
		comm_in_payload->snapshot_output_len =
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
	free(action_snapshot_session);

end:
	return;
}

ssize_t lttng_action_snapshot_session_create_from_payload(
		struct lttng_payload_view *view,
		struct lttng_action **p_action)
{
	ssize_t consumed_len;
	const struct lttng_action_snapshot_session_comm *comm;
	const char *variable_data;
	struct lttng_action *action;
	enum lttng_action_status status;
	struct lttng_snapshot_output *snapshot_output = NULL;

	action = lttng_action_snapshot_session_create();
	if (!action) {
		goto error;
	}

	comm = (typeof(comm)) view->buffer.data;
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

		if (!snapshot_output_buffer_view.buffer.data) {
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
	*p_action = action;
	action = NULL;

	goto end;

error:
	consumed_len = -1;

end:
	lttng_action_snapshot_session_destroy(action);
	lttng_snapshot_output_destroy(snapshot_output);

	return consumed_len;
}

struct lttng_action *lttng_action_snapshot_session_create(void)
{
	struct lttng_action *action;

	action = zmalloc(sizeof(struct lttng_action_snapshot_session));
	if (!action) {
		goto end;
	}

	lttng_action_init(action, LTTNG_ACTION_TYPE_SNAPSHOT_SESSION,
			lttng_action_snapshot_session_validate,
			lttng_action_snapshot_session_serialize,
			lttng_action_snapshot_session_is_equal,
			lttng_action_snapshot_session_destroy);

end:
	return action;
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
