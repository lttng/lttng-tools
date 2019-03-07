/*
 * Copyright (C) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <lttng/condition/evaluation-internal.h>
#include <lttng/condition/buffer-usage-internal.h>
#include <lttng/condition/session-consumed-size-internal.h>
#include <lttng/condition/session-rotation-internal.h>
#include <common/macros.h>
#include <common/error.h>
#include <stdbool.h>
#include <assert.h>

LTTNG_HIDDEN
void lttng_evaluation_init(struct lttng_evaluation *evaluation,
		enum lttng_condition_type type)
{
	evaluation->type = type;
}

LTTNG_HIDDEN
int lttng_evaluation_serialize(const struct lttng_evaluation *evaluation,
		struct lttng_dynamic_buffer *buf)
{
	int ret;
	struct lttng_evaluation_comm evaluation_comm = {
		.type = (int8_t) evaluation->type
	};

	ret = lttng_dynamic_buffer_append(buf, &evaluation_comm,
			sizeof(evaluation_comm));
	if (ret) {
		goto end;
	}

	if (evaluation->serialize) {
		ret = evaluation->serialize(evaluation, buf);
		if (ret) {
			goto end;
		}
	}
end:
	return ret;
}

LTTNG_HIDDEN
ssize_t lttng_evaluation_create_from_buffer(
		const struct lttng_buffer_view *src_view,
		struct lttng_evaluation **evaluation)
{
	ssize_t ret, evaluation_size = 0;
	const struct lttng_evaluation_comm *evaluation_comm;
	const struct lttng_buffer_view evaluation_view =
			lttng_buffer_view_from_view(src_view,
			sizeof(*evaluation_comm), -1);

	if (!src_view || !evaluation) {
		ret = -1;
		goto end;
	}

	evaluation_comm = (const struct lttng_evaluation_comm *) src_view->data;
	evaluation_size += sizeof(*evaluation_comm);

	switch ((enum lttng_condition_type) evaluation_comm->type) {
	case LTTNG_CONDITION_TYPE_BUFFER_USAGE_LOW:
		ret = lttng_evaluation_buffer_usage_low_create_from_buffer(
				&evaluation_view, evaluation);
		if (ret < 0) {
			goto end;
		}
		evaluation_size += ret;
		break;
	case LTTNG_CONDITION_TYPE_BUFFER_USAGE_HIGH:
		ret = lttng_evaluation_buffer_usage_high_create_from_buffer(
				&evaluation_view, evaluation);
		if (ret < 0) {
			goto end;
		}
		evaluation_size += ret;
		break;
	case LTTNG_CONDITION_TYPE_SESSION_CONSUMED_SIZE:
		ret = lttng_evaluation_session_consumed_size_create_from_buffer(
				&evaluation_view, evaluation);
		if (ret < 0) {
			goto end;
		}
		evaluation_size += ret;
		break;
	case LTTNG_CONDITION_TYPE_SESSION_ROTATION_ONGOING:
		ret = lttng_evaluation_session_rotation_ongoing_create_from_buffer(
				&evaluation_view, evaluation);
		if (ret < 0) {
			goto end;
		}
		evaluation_size += ret;
		break;
	case LTTNG_CONDITION_TYPE_SESSION_ROTATION_COMPLETED:
		ret = lttng_evaluation_session_rotation_completed_create_from_buffer(
				&evaluation_view, evaluation);
		if (ret < 0) {
			goto end;
		}
		evaluation_size += ret;
		break;
	default:
		ERR("Attempted to create evaluation of unknown type (%i)",
				(int) evaluation_comm->type);
		ret = -1;
		goto end;
	}
	ret = evaluation_size;
end:
	return ret;
}

enum lttng_condition_type lttng_evaluation_get_type(
		const struct lttng_evaluation *evaluation)
{
	return evaluation ? evaluation->type : LTTNG_CONDITION_TYPE_UNKNOWN;
}

void lttng_evaluation_destroy(struct lttng_evaluation *evaluation)
{
	if (!evaluation) {
		return;
	}

	assert(evaluation->destroy);
	evaluation->destroy(evaluation);
}
