/*
 * Copyright (C) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <lttng/notification/notification-internal.h>
#include <lttng/condition/condition-internal.h>
#include <lttng/condition/evaluation-internal.h>
#include <lttng/condition/condition.h>
#include <lttng/condition/evaluation.h>
#include <common/payload.h>
#include <common/payload-view.h>
#include <assert.h>

LTTNG_HIDDEN
struct lttng_notification *lttng_notification_create(
		struct lttng_condition *condition,
		struct lttng_evaluation *evaluation)
{
	struct lttng_notification *notification = NULL;

	if (!condition || !evaluation) {
		goto end;
	}

	notification = zmalloc(sizeof(struct lttng_notification));
	if (!notification) {
		goto end;
	}

	notification->condition = condition;
	notification->evaluation = evaluation;
end:
	return notification;
}

LTTNG_HIDDEN
int lttng_notification_serialize(const struct lttng_notification *notification,
		struct lttng_payload *payload)
{
	int ret;
	size_t header_offset, size_before_payload;
	struct lttng_notification_comm notification_comm = { 0 };
	struct lttng_notification_comm *header;

	header_offset = payload->buffer.size;
	ret = lttng_dynamic_buffer_append(&payload->buffer, &notification_comm,
			sizeof(notification_comm));
	if (ret) {
		goto end;
	}

	size_before_payload = payload->buffer.size;
	ret = lttng_condition_serialize(notification->condition,
			payload);
	if (ret) {
		goto end;
	}

	ret = lttng_evaluation_serialize(notification->evaluation, payload);
	if (ret) {
		goto end;
	}

	/* Update payload size. */
	header = (typeof(header)) (payload->buffer.data + header_offset);
	header->length = (uint32_t) (payload->buffer.size - size_before_payload);
end:
	return ret;

}

LTTNG_HIDDEN
ssize_t lttng_notification_create_from_payload(
		struct lttng_payload_view *src_view,
		struct lttng_notification **notification)
{
	ssize_t ret, notification_size = 0, condition_size, evaluation_size;
	struct lttng_condition *condition;
	struct lttng_evaluation *evaluation;
	const struct lttng_notification_comm *notification_comm;
	const struct lttng_payload_view notification_comm_view =
			lttng_payload_view_from_view(
					src_view, 0, sizeof(*notification_comm));

	if (!src_view || !notification) {
		ret = -1;
		goto end;
	}

	if (!lttng_payload_view_is_valid(&notification_comm_view)) {
		/* Payload not large enough to contain the header. */
		ret = -1;
		goto end;
	}

	notification_comm = (typeof(notification_comm)) notification_comm_view.buffer.data;
	notification_size += sizeof(*notification_comm);
	{
		/* struct lttng_condition */
		struct lttng_payload_view condition_view =
				lttng_payload_view_from_view(src_view,
						notification_size, -1);

		condition_size = lttng_condition_create_from_payload(
				&condition_view, &condition);
	}

	if (condition_size < 0) {
		ret = condition_size;
		goto end;
	}

	notification_size += condition_size;

	{
		/* struct lttng_evaluation */
		struct lttng_payload_view evaluation_view =
				lttng_payload_view_from_view(src_view,
						notification_size, -1);

		evaluation_size = lttng_evaluation_create_from_payload(
				condition, &evaluation_view, &evaluation);
	}

	if (evaluation_size < 0) {
		ret = evaluation_size;
		goto end;
	}

	notification_size += evaluation_size;

	/* Unexpected size of inner-elements; the buffer is corrupted. */
	if ((ssize_t) notification_comm->length !=
			condition_size + evaluation_size) {
		ret = -1;
		goto error;
	}

	*notification = lttng_notification_create(condition, evaluation);
	if (!*notification) {
		ret = -1;
		goto error;
	}
	ret = notification_size;
end:
	return ret;
error:
	lttng_condition_destroy(condition);
	lttng_evaluation_destroy(evaluation);
	return ret;
}

void lttng_notification_destroy(struct lttng_notification *notification)
{
	if (!notification) {
		return;
	}

	lttng_condition_destroy(notification->condition);
	lttng_evaluation_destroy(notification->evaluation);
	free(notification);
}

const struct lttng_condition *lttng_notification_get_condition(
		struct lttng_notification *notification)
{
	return notification ? notification->condition : NULL;
}

const struct lttng_evaluation *lttng_notification_get_evaluation(
		struct lttng_notification *notification)
{
	return notification ? notification->evaluation : NULL;
}
