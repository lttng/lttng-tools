/*
 * Copyright (C) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <common/error.h>
#include <common/macros.h>
#include <common/mi-lttng.h>
#include <float.h>
#include <lttng/condition/condition-internal.h>
#include <lttng/condition/session-consumed-size-internal.h>
#include <lttng/constant.h>
#include <math.h>
#include <time.h>

#define IS_CONSUMED_SIZE_CONDITION(condition) ( \
	lttng_condition_get_type(condition) == LTTNG_CONDITION_TYPE_SESSION_CONSUMED_SIZE \
	)

#define IS_CONSUMED_SIZE_EVALUATION(evaluation) ( \
	lttng_evaluation_get_type(evaluation) == LTTNG_CONDITION_TYPE_SESSION_CONSUMED_SIZE \
	)

static
void lttng_condition_session_consumed_size_destroy(struct lttng_condition *condition)
{
	struct lttng_condition_session_consumed_size *consumed_size;

	consumed_size = container_of(condition,
			struct lttng_condition_session_consumed_size, parent);

	free(consumed_size->session_name);
	free(consumed_size);
}

static
bool lttng_condition_session_consumed_size_validate(
		const struct lttng_condition *condition)
{
	bool valid = false;
	struct lttng_condition_session_consumed_size *consumed;

	if (!condition) {
		goto end;
	}

	consumed = container_of(condition, struct lttng_condition_session_consumed_size,
			parent);
	if (!consumed->session_name) {
		ERR("Invalid session consumed size condition: a target session name must be set.");
		goto end;
	}
	if (!consumed->consumed_threshold_bytes.set) {
		ERR("Invalid session consumed size condition: a threshold must be set.");
		goto end;
	}

	valid = true;
end:
	return valid;
}

static
int lttng_condition_session_consumed_size_serialize(
		const struct lttng_condition *condition,
		struct lttng_payload *payload)
{
	int ret;
	size_t session_name_len;
	struct lttng_condition_session_consumed_size *consumed;
	struct lttng_condition_session_consumed_size_comm consumed_comm;

	if (!condition || !IS_CONSUMED_SIZE_CONDITION(condition)) {
		ret = -1;
		goto end;
	}

	DBG("Serializing session consumed size condition");
	consumed = container_of(condition,
			struct lttng_condition_session_consumed_size,
			parent);

	session_name_len = strlen(consumed->session_name) + 1;
	if (session_name_len > LTTNG_NAME_MAX) {
		ret = -1;
		goto end;
	}

	consumed_comm.consumed_threshold_bytes =
			consumed->consumed_threshold_bytes.value;
	consumed_comm.session_name_len = (uint32_t) session_name_len;

	ret = lttng_dynamic_buffer_append(&payload->buffer, &consumed_comm,
			sizeof(consumed_comm));
	if (ret) {
		goto end;
	}

	ret = lttng_dynamic_buffer_append(&payload->buffer, consumed->session_name,
			session_name_len);
	if (ret) {
		goto end;
	}
end:
	return ret;
}

static
bool lttng_condition_session_consumed_size_is_equal(const struct lttng_condition *_a,
		const struct lttng_condition *_b)
{
	bool is_equal = false;
	struct lttng_condition_session_consumed_size *a, *b;

	a = container_of(_a, struct lttng_condition_session_consumed_size, parent);
	b = container_of(_b, struct lttng_condition_session_consumed_size, parent);

	if (a->consumed_threshold_bytes.set && b->consumed_threshold_bytes.set) {
		uint64_t a_value, b_value;

		a_value = a->consumed_threshold_bytes.value;
		b_value = b->consumed_threshold_bytes.value;
		if (a_value != b_value) {
			goto end;
		}
	}

	LTTNG_ASSERT(a->session_name);
	LTTNG_ASSERT(b->session_name);
	if (strcmp(a->session_name, b->session_name)) {
		goto end;
	}

	is_equal = true;
end:
	return is_equal;
}

static
enum lttng_error_code lttng_condition_session_consumed_size_mi_serialize(
		const struct lttng_condition *condition,
		struct mi_writer *writer)
{
	int ret;
	enum lttng_error_code ret_code;
	enum lttng_condition_status status;
	const char *session_name = NULL;
	uint64_t threshold_bytes;

	LTTNG_ASSERT(condition);
	LTTNG_ASSERT(writer);
	LTTNG_ASSERT(IS_CONSUMED_SIZE_CONDITION(condition));

	status = lttng_condition_session_consumed_size_get_session_name(
			condition, &session_name);
	LTTNG_ASSERT(status == LTTNG_CONDITION_STATUS_OK);
	LTTNG_ASSERT(session_name);

	status = lttng_condition_session_consumed_size_get_threshold(
			condition, &threshold_bytes);
	LTTNG_ASSERT(status == LTTNG_CONDITION_STATUS_OK);

	/* Open condition session consumed size element. */
	ret = mi_lttng_writer_open_element(writer,
			mi_lttng_element_condition_session_consumed_size);
	if (ret) {
		goto mi_error;
	}

	/* Session name. */
	ret = mi_lttng_writer_write_element_string(
			writer, mi_lttng_element_session_name, session_name);
	if (ret) {
		goto mi_error;
	}

	/* Threshold in bytes. */
	ret = mi_lttng_writer_write_element_unsigned_int(writer,
			mi_lttng_element_condition_threshold_bytes,
			threshold_bytes);
	if (ret) {
		goto mi_error;
	}

	/* Close condition session consumed size element. */
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

struct lttng_condition *lttng_condition_session_consumed_size_create(void)
{
	struct lttng_condition_session_consumed_size *condition;

	condition = zmalloc(sizeof(struct lttng_condition_session_consumed_size));
	if (!condition) {
		return NULL;
	}

	lttng_condition_init(&condition->parent, LTTNG_CONDITION_TYPE_SESSION_CONSUMED_SIZE);
	condition->parent.validate = lttng_condition_session_consumed_size_validate;
	condition->parent.serialize = lttng_condition_session_consumed_size_serialize;
	condition->parent.equal = lttng_condition_session_consumed_size_is_equal;
	condition->parent.destroy = lttng_condition_session_consumed_size_destroy;
	condition->parent.mi_serialize = lttng_condition_session_consumed_size_mi_serialize;
	return &condition->parent;
}

static
ssize_t init_condition_from_payload(struct lttng_condition *condition,
		struct lttng_payload_view *src_view)
{
	ssize_t ret, condition_size;
	enum lttng_condition_status status;
	const char *session_name;
	struct lttng_buffer_view session_name_view;
	const struct lttng_condition_session_consumed_size_comm *condition_comm;
	struct lttng_payload_view condition_comm_view = lttng_payload_view_from_view(
			src_view, 0, sizeof(*condition_comm));

	if (!lttng_payload_view_is_valid(&condition_comm_view)) {
		ERR("Failed to initialize from malformed condition buffer: buffer too short to contain header");
		ret = -1;
		goto end;
	}

	condition_comm = (typeof(condition_comm)) condition_comm_view.buffer.data;
	session_name_view = lttng_buffer_view_from_view(&src_view->buffer,
			sizeof(*condition_comm), condition_comm->session_name_len);

	if (condition_comm->session_name_len > LTTNG_NAME_MAX) {
		ERR("Failed to initialize from malformed condition buffer: name exceeds LTTNG_MAX_NAME");
		ret = -1;
		goto end;
	}

	if (!lttng_buffer_view_is_valid(&session_name_view)) {
		ERR("Failed to initialize from malformed condition buffer: buffer too short to contain element names");
		ret = -1;
		goto end;
	}

	status = lttng_condition_session_consumed_size_set_threshold(condition,
			condition_comm->consumed_threshold_bytes);
	if (status != LTTNG_CONDITION_STATUS_OK) {
		ERR("Failed to initialize session consumed size condition threshold");
		ret = -1;
		goto end;
	}

	session_name = session_name_view.data;
	if (*(session_name + condition_comm->session_name_len - 1) != '\0') {
		ERR("Malformed session name encountered in condition buffer");
		ret = -1;
		goto end;
	}

	status = lttng_condition_session_consumed_size_set_session_name(condition,
			session_name);
	if (status != LTTNG_CONDITION_STATUS_OK) {
		ERR("Failed to set session consumed size condition's session name");
		ret = -1;
		goto end;
	}

	if (!lttng_condition_validate(condition)) {
		ret = -1;
		goto end;
	}

	condition_size = sizeof(*condition_comm) +
			(ssize_t) condition_comm->session_name_len;
	ret = condition_size;
end:
	return ret;
}

ssize_t lttng_condition_session_consumed_size_create_from_payload(
		struct lttng_payload_view *view,
		struct lttng_condition **_condition)
{
	ssize_t ret;
	struct lttng_condition *condition =
			lttng_condition_session_consumed_size_create();

	if (!_condition || !condition) {
		ret = -1;
		goto error;
	}

	ret = init_condition_from_payload(condition, view);
	if (ret < 0) {
		goto error;
	}

	*_condition = condition;
	return ret;
error:
	lttng_condition_destroy(condition);
	return ret;
}

static
struct lttng_evaluation *create_evaluation_from_payload(
		const struct lttng_payload_view *view)
{
	const struct lttng_evaluation_session_consumed_size_comm *comm =
			(typeof(comm)) view->buffer.data;
	struct lttng_evaluation *evaluation = NULL;

	if (view->buffer.size < sizeof(*comm)) {
		goto end;
	}

	evaluation = lttng_evaluation_session_consumed_size_create(
			comm->session_consumed);
end:
	return evaluation;
}

ssize_t lttng_evaluation_session_consumed_size_create_from_payload(
		struct lttng_payload_view *view,
		struct lttng_evaluation **_evaluation)
{
	ssize_t ret;
	struct lttng_evaluation *evaluation = NULL;

	if (!_evaluation) {
		ret = -1;
		goto error;
	}

	evaluation = create_evaluation_from_payload(view);
	if (!evaluation) {
		ret = -1;
		goto error;
	}

	*_evaluation = evaluation;
	ret = sizeof(struct lttng_evaluation_session_consumed_size_comm);
	return ret;
error:
	lttng_evaluation_destroy(evaluation);
	return ret;
}

enum lttng_condition_status
lttng_condition_session_consumed_size_get_threshold(
		const struct lttng_condition *condition,
		uint64_t *consumed_threshold_bytes)
{
	struct lttng_condition_session_consumed_size *consumed;
	enum lttng_condition_status status = LTTNG_CONDITION_STATUS_OK;

	if (!condition || !IS_CONSUMED_SIZE_CONDITION(condition) || !consumed_threshold_bytes) {
		status = LTTNG_CONDITION_STATUS_INVALID;
		goto end;
	}

	consumed = container_of(condition, struct lttng_condition_session_consumed_size,
			parent);
	if (!consumed->consumed_threshold_bytes.set) {
		status = LTTNG_CONDITION_STATUS_UNSET;
		goto end;
	}
	*consumed_threshold_bytes = consumed->consumed_threshold_bytes.value;
end:
	return status;
}

enum lttng_condition_status
lttng_condition_session_consumed_size_set_threshold(
		struct lttng_condition *condition, uint64_t consumed_threshold_bytes)
{
	struct lttng_condition_session_consumed_size *consumed;
	enum lttng_condition_status status = LTTNG_CONDITION_STATUS_OK;

	if (!condition || !IS_CONSUMED_SIZE_CONDITION(condition)) {
		status = LTTNG_CONDITION_STATUS_INVALID;
		goto end;
	}

	consumed = container_of(condition, struct lttng_condition_session_consumed_size,
			parent);
	consumed->consumed_threshold_bytes.set = true;
	consumed->consumed_threshold_bytes.value = consumed_threshold_bytes;
end:
	return status;
}

enum lttng_condition_status
lttng_condition_session_consumed_size_get_session_name(
		const struct lttng_condition *condition,
		const char **session_name)
{
	struct lttng_condition_session_consumed_size *consumed;
	enum lttng_condition_status status = LTTNG_CONDITION_STATUS_OK;

	if (!condition || !IS_CONSUMED_SIZE_CONDITION(condition) || !session_name) {
		status = LTTNG_CONDITION_STATUS_INVALID;
		goto end;
	}

	consumed = container_of(condition, struct lttng_condition_session_consumed_size,
			parent);
	if (!consumed->session_name) {
		status = LTTNG_CONDITION_STATUS_UNSET;
		goto end;
	}
	*session_name = consumed->session_name;
end:
	return status;
}

enum lttng_condition_status
lttng_condition_session_consumed_size_set_session_name(
		struct lttng_condition *condition, const char *session_name)
{
	char *session_name_copy;
	struct lttng_condition_session_consumed_size *consumed;
	enum lttng_condition_status status = LTTNG_CONDITION_STATUS_OK;

	if (!condition || !IS_CONSUMED_SIZE_CONDITION(condition) ||
			!session_name || strlen(session_name) == 0) {
		status = LTTNG_CONDITION_STATUS_INVALID;
		goto end;
	}

	consumed = container_of(condition, struct lttng_condition_session_consumed_size,
			parent);
	session_name_copy = strdup(session_name);
	if (!session_name_copy) {
		status = LTTNG_CONDITION_STATUS_ERROR;
		goto end;
	}

	if (consumed->session_name) {
		free(consumed->session_name);
	}
	consumed->session_name = session_name_copy;
end:
	return status;
}

static
int lttng_evaluation_session_consumed_size_serialize(
		const struct lttng_evaluation *evaluation,
		struct lttng_payload *payload)
{
	struct lttng_evaluation_session_consumed_size *consumed;
	struct lttng_evaluation_session_consumed_size_comm comm;

	consumed = container_of(evaluation,
			struct lttng_evaluation_session_consumed_size, parent);
	comm.session_consumed = consumed->session_consumed;
	return lttng_dynamic_buffer_append(
			&payload->buffer, &comm, sizeof(comm));
}

static
void lttng_evaluation_session_consumed_size_destroy(
		struct lttng_evaluation *evaluation)
{
	struct lttng_evaluation_session_consumed_size *consumed;

	consumed = container_of(evaluation, struct lttng_evaluation_session_consumed_size,
			parent);
	free(consumed);
}

struct lttng_evaluation *lttng_evaluation_session_consumed_size_create(
		uint64_t consumed)
{
	struct lttng_evaluation_session_consumed_size *consumed_eval;

	consumed_eval = zmalloc(sizeof(struct lttng_evaluation_session_consumed_size));
	if (!consumed_eval) {
		goto end;
	}

	consumed_eval->parent.type = LTTNG_CONDITION_TYPE_SESSION_CONSUMED_SIZE;
	consumed_eval->session_consumed = consumed;
	consumed_eval->parent.serialize = lttng_evaluation_session_consumed_size_serialize;
	consumed_eval->parent.destroy = lttng_evaluation_session_consumed_size_destroy;
end:
	return &consumed_eval->parent;
}

enum lttng_evaluation_status
lttng_evaluation_session_consumed_size_get_consumed_size(
		const struct lttng_evaluation *evaluation,
		uint64_t *session_consumed)
{
	struct lttng_evaluation_session_consumed_size *consumed;
	enum lttng_evaluation_status status = LTTNG_EVALUATION_STATUS_OK;

	if (!evaluation || !IS_CONSUMED_SIZE_EVALUATION(evaluation) ||
			!session_consumed) {
		status = LTTNG_EVALUATION_STATUS_INVALID;
		goto end;
	}

	consumed = container_of(evaluation, struct lttng_evaluation_session_consumed_size,
			parent);
	*session_consumed = consumed->session_consumed;
end:
	return status;
}
