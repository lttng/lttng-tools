/*
 * Copyright (C) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <lttng/condition/condition-internal.h>
#include <lttng/condition/evaluation-internal.h>
#include <lttng/condition/buffer-usage-internal.h>
#include <lttng/condition/session-consumed-size-internal.h>
#include <lttng/condition/session-rotation-internal.h>
#include <lttng/condition/event-rule-internal.h>
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
		struct lttng_payload *payload)
{
	int ret;
	struct lttng_evaluation_comm evaluation_comm = {
		.type = (int8_t) evaluation->type
	};

	ret = lttng_dynamic_buffer_append(&payload->buffer, &evaluation_comm,
			sizeof(evaluation_comm));
	if (ret) {
		goto end;
	}

	if (evaluation->serialize) {
		ret = evaluation->serialize(evaluation, payload);
		if (ret) {
			goto end;
		}
	}
end:
	return ret;
}

LTTNG_HIDDEN
ssize_t lttng_evaluation_create_from_payload(
		const struct lttng_condition *condition,
		struct lttng_payload_view *src_view,
		struct lttng_evaluation **evaluation)
{
	ssize_t ret, evaluation_size = 0;
	const struct lttng_evaluation_comm *evaluation_comm;
	struct lttng_payload_view evaluation_comm_view =
			lttng_payload_view_from_view(
					src_view, 0, sizeof(*evaluation_comm));
	struct lttng_payload_view evaluation_view =
			lttng_payload_view_from_view(src_view,
					sizeof(*evaluation_comm), -1);

	if (!src_view || !evaluation) {
		ret = -1;
		goto end;
	}

	if (!lttng_payload_view_is_valid(&evaluation_comm_view)) {
		ret = -1;
		goto end;
	}

	evaluation_comm = (typeof(evaluation_comm)) evaluation_comm_view.buffer.data;
	evaluation_size += sizeof(*evaluation_comm);

	switch ((enum lttng_condition_type) evaluation_comm->type) {
	case LTTNG_CONDITION_TYPE_BUFFER_USAGE_LOW:
		ret = lttng_evaluation_buffer_usage_low_create_from_payload(
				&evaluation_view, evaluation);
		if (ret < 0) {
			goto end;
		}
		evaluation_size += ret;
		break;
	case LTTNG_CONDITION_TYPE_BUFFER_USAGE_HIGH:
		ret = lttng_evaluation_buffer_usage_high_create_from_payload(
				&evaluation_view, evaluation);
		if (ret < 0) {
			goto end;
		}
		evaluation_size += ret;
		break;
	case LTTNG_CONDITION_TYPE_SESSION_CONSUMED_SIZE:
		ret = lttng_evaluation_session_consumed_size_create_from_payload(
				&evaluation_view, evaluation);
		if (ret < 0) {
			goto end;
		}
		evaluation_size += ret;
		break;
	case LTTNG_CONDITION_TYPE_SESSION_ROTATION_ONGOING:
		ret = lttng_evaluation_session_rotation_ongoing_create_from_payload(
				&evaluation_view, evaluation);
		if (ret < 0) {
			goto end;
		}
		evaluation_size += ret;
		break;
	case LTTNG_CONDITION_TYPE_SESSION_ROTATION_COMPLETED:
		ret = lttng_evaluation_session_rotation_completed_create_from_payload(
				&evaluation_view, evaluation);
		if (ret < 0) {
			goto end;
		}
		evaluation_size += ret;
		break;
	case LTTNG_CONDITION_TYPE_EVENT_RULE_HIT:
		assert(condition);
		assert(condition->type == LTTNG_CONDITION_TYPE_EVENT_RULE_HIT);
		ret = lttng_evaluation_event_rule_create_from_payload(
				container_of(condition,
						const struct lttng_condition_event_rule,
						parent),
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
