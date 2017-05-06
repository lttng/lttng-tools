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

#include <lttng/condition/evaluation-internal.h>
#include <lttng/condition/buffer-usage-internal.h>
#include <common/macros.h>
#include <common/error.h>
#include <stdbool.h>
#include <assert.h>

LTTNG_HIDDEN
ssize_t lttng_evaluation_serialize(struct lttng_evaluation *evaluation,
		char *buf)
{
	ssize_t ret, offset = 0;
	struct lttng_evaluation_comm evaluation_comm = {
		.type = (int8_t) evaluation->type
	};

	if (buf) {
		memcpy(buf, &evaluation_comm, sizeof(evaluation_comm));
	}
	offset += sizeof(evaluation_comm);

	if (evaluation->serialize) {
		ret = evaluation->serialize(evaluation,
				buf ? (buf + offset) : NULL);
		if (ret < 0) {
			goto end;
		}
		offset += ret;
	}

	ret = offset;
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
