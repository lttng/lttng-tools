/*
 * Copyright (C) 2017 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License, version 2.1 only,
 * as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <lttng/condition/condition-internal.h>
#include <lttng/condition/session-consumed-size-internal.h>
#include <common/macros.h>
#include <common/error.h>
#include <assert.h>
#include <math.h>
#include <float.h>
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
		ERR("Invalid buffer condition: a target session name must be set.");
		goto end;
	}
	if (!consumed->consumed_threshold_bytes.set) {
		ERR("Invalid session condition: a threshold must be set.");
		goto end;
	}

	valid = true;
end:
	return valid;
}

static
ssize_t lttng_condition_session_consumed_size_serialize(
		const struct lttng_condition *condition, char *buf)
{
	struct lttng_condition_session_consumed_size *consumed;
	ssize_t ret, size;
	size_t session_name_len;

	if (!condition || !IS_CONSUMED_SIZE_CONDITION(condition)) {
		ret = -1;
		goto end;
	}

	DBG("Serializing session consumed condition");
	consumed = container_of(condition, struct lttng_condition_session_consumed_size,
			parent);
	size = sizeof(struct lttng_condition_session_consumed_size_comm);
	session_name_len = strlen(consumed->session_name) + 1;
	if (session_name_len > LTTNG_NAME_MAX) {
		ret = -1;
		goto end;
	}
	size += session_name_len;
	if (buf) {
		struct lttng_condition_session_consumed_size_comm consumed_comm = {
			.consumed_threshold_bytes = consumed->consumed_threshold_bytes.value,
			.session_name_len = session_name_len,
		};

		memcpy(buf, &consumed_comm, sizeof(consumed_comm));
		buf += sizeof(consumed_comm);
		memcpy(buf, consumed->session_name, session_name_len);
		buf += session_name_len;
	}
	ret = size;
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

	if ((a->session_name && !b->session_name) ||
			(!a->session_name && b->session_name)) {
		goto end;
	}

	is_equal = true;
end:
	return is_equal;
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
	return &condition->parent;
}

static
ssize_t init_condition_from_buffer(struct lttng_condition *condition,
		const struct lttng_buffer_view *src_view)
{
	ssize_t ret, condition_size;
	enum lttng_condition_status status;
	const struct lttng_condition_session_consumed_size_comm *condition_comm;
	const char *session_name;
	struct lttng_buffer_view names_view;

	if (src_view->size < sizeof(*condition_comm)) {
		ERR("Failed to initialize from malformed condition buffer: buffer too short to contain header");
		ret = -1;
		goto end;
	}

	condition_comm = (const struct lttng_condition_session_consumed_size_comm *) src_view->data;
	names_view = lttng_buffer_view_from_view(src_view,
			sizeof(*condition_comm), -1);

	if (condition_comm->session_name_len > LTTNG_NAME_MAX) {
		ERR("Failed to initialize from malformed condition buffer: name exceeds LTTNG_MAX_NAME");
		ret = -1;
		goto end;
	}

	if (names_view.size < condition_comm->session_name_len) {
		ERR("Failed to initialize from malformed condition buffer: buffer too short to contain element names");
		ret = -1;
		goto end;
	}

	status = lttng_condition_session_consumed_size_set_threshold(condition,
			condition_comm->consumed_threshold_bytes);
	if (status != LTTNG_CONDITION_STATUS_OK) {
		ERR("Failed to initialize session consumed condition threshold");
		ret = -1;
		goto end;
	}

	session_name = names_view.data;
	if (*(session_name + condition_comm->session_name_len - 1) != '\0') {
		ERR("Malformed session name encountered in condition buffer");
		ret = -1;
		goto end;
	}

	status = lttng_condition_session_consumed_size_set_session_name(condition,
			session_name);
	if (status != LTTNG_CONDITION_STATUS_OK) {
		ERR("Failed to set buffer consumed session name");
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

LTTNG_HIDDEN
ssize_t lttng_condition_session_consumed_size_create_from_buffer(
		const struct lttng_buffer_view *view,
		struct lttng_condition **_condition)
{
	ssize_t ret;
	struct lttng_condition *condition =
			lttng_condition_session_consumed_size_create();

	if (!_condition || !condition) {
		ret = -1;
		goto error;
	}

	ret = init_condition_from_buffer(condition, view);
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
struct lttng_evaluation *create_evaluation_from_buffer(
		enum lttng_condition_type type,
		const struct lttng_buffer_view *view)
{
	const struct lttng_evaluation_session_consumed_size_comm *comm =
			(const struct lttng_evaluation_session_consumed_size_comm *) view->data;
	struct lttng_evaluation *evaluation = NULL;

	if (view->size < sizeof(*comm)) {
		goto end;
	}

	evaluation = lttng_evaluation_session_consumed_size_create(type,
			comm->session_consumed);
end:
	return evaluation;
}

LTTNG_HIDDEN
ssize_t lttng_evaluation_session_consumed_size_create_from_buffer(
		const struct lttng_buffer_view *view,
		struct lttng_evaluation **_evaluation)
{
	ssize_t ret;
	struct lttng_evaluation *evaluation = NULL;

	if (!_evaluation) {
		ret = -1;
		goto error;
	}

	evaluation = create_evaluation_from_buffer(
			LTTNG_CONDITION_TYPE_SESSION_CONSUMED_SIZE, view);
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
ssize_t lttng_evaluation_session_consumed_size_serialize(
		struct lttng_evaluation *evaluation, char *buf)
{
	ssize_t ret;
	struct lttng_evaluation_session_consumed_size *consumed;

	consumed = container_of(evaluation, struct lttng_evaluation_session_consumed_size,
			parent);
	if (buf) {
		struct lttng_evaluation_session_consumed_size_comm comm = {
			.session_consumed = consumed->session_consumed,
		};

		memcpy(buf, &comm, sizeof(comm));
	}

	ret = sizeof(struct lttng_evaluation_session_consumed_size_comm);
	return ret;
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

LTTNG_HIDDEN
struct lttng_evaluation *lttng_evaluation_session_consumed_size_create(
		enum lttng_condition_type type, uint64_t consumed)
{
	struct lttng_evaluation_session_consumed_size *consumed_eval;

	consumed_eval = zmalloc(sizeof(struct lttng_evaluation_session_consumed_size));
	if (!consumed_eval) {
		goto end;
	}

	consumed_eval->parent.type = type;
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
