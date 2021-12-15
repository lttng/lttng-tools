/*
 * Copyright (C) 2021 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <lttng/action/path-internal.hpp>

struct lttng_action_path_comm {
	uint32_t index_count;
	uint64_t indexes[];
} LTTNG_PACKED;

struct lttng_action_path *lttng_action_path_create(
		const uint64_t *indexes, size_t index_count)
{
	int ret;
	size_t i;
	struct lttng_action_path *path = NULL;

	if (!indexes && index_count > 0) {
		goto error;
	}

	path = (lttng_action_path *) zmalloc(sizeof(*path));
	if (!path) {
		goto error;
	}

	lttng_dynamic_array_init(&path->indexes, sizeof(uint64_t), NULL);

	for (i = 0; i < index_count; i++) {
		ret = lttng_dynamic_array_add_element(
				&path->indexes, &indexes[i]);
		if (ret) {
			goto error;
		}
	}

	goto end;
error:
	lttng_action_path_destroy(path);
	path = NULL;
end:
	return path;
}

enum lttng_action_path_status lttng_action_path_get_index_count(
		const struct lttng_action_path *path, size_t *index_count)
{
	enum lttng_action_path_status status;

	if (!path || !index_count) {
		status = LTTNG_ACTION_PATH_STATUS_INVALID;
		goto end;
	}

	*index_count = lttng_dynamic_array_get_count(&path->indexes);
	status = LTTNG_ACTION_PATH_STATUS_OK;
end:
	return status;
}

enum lttng_action_path_status lttng_action_path_get_index_at_index(
		const struct lttng_action_path *path,
		size_t path_index,
		uint64_t *out_index)
{
	enum lttng_action_path_status status;

	if (!path || !out_index ||
			path_index >= lttng_dynamic_array_get_count(
				&path->indexes)) {
		status = LTTNG_ACTION_PATH_STATUS_INVALID;
		goto end;
	}

	*out_index = *((typeof(out_index)) lttng_dynamic_array_get_element(
			&path->indexes, path_index));
	status = LTTNG_ACTION_PATH_STATUS_OK;
end:
	return status;
}

void lttng_action_path_destroy(struct lttng_action_path *action_path)
{
	if (!action_path) {
		goto end;
	}

	lttng_dynamic_array_reset(&action_path->indexes);
	free(action_path);
end:
	return;
}

int lttng_action_path_copy(const struct lttng_action_path *src,
		struct lttng_action_path *dst)
{
	int ret;
	size_t i, src_count;

	LTTNG_ASSERT(src);
	LTTNG_ASSERT(dst);

	lttng_dynamic_array_init(&dst->indexes, sizeof(uint64_t), NULL);
	src_count = lttng_dynamic_array_get_count(&src->indexes);

	for (i = 0; i < src_count; i++) {
		const void *index = lttng_dynamic_array_get_element(
				&src->indexes, i);

		ret = lttng_dynamic_array_add_element(&dst->indexes, index);
		if (ret) {
			goto error;
		}
	}

	ret = 0;
	goto end;
error:
	lttng_dynamic_array_reset(&dst->indexes);
end:
	return ret;
}

ssize_t lttng_action_path_create_from_payload(
		struct lttng_payload_view *view,
		struct lttng_action_path **_action_path)
{
	ssize_t consumed_size = 0, ret = -1;
	const struct lttng_action_path_comm *header;
	struct lttng_action_path *action_path = NULL;
	const struct lttng_payload_view header_view =
			lttng_payload_view_from_view(view, 0, sizeof(*header));

	if (!lttng_payload_view_is_valid(&header_view)) {
		goto end;
	}

	header = (typeof(header)) header_view.buffer.data;
	consumed_size += header_view.buffer.size;

	/*
	 * An action path of size 0 can exist and represents a trigger with a
	 * single non-list action. Handle it differently since a payload view of
	 * size 0 is considered invalid.
	 */
	if (header->index_count != 0)
	{
		const struct lttng_payload_view indexes_view =
				lttng_payload_view_from_view(view,
						consumed_size,
						header->index_count *
								sizeof(uint64_t));

		if (!lttng_payload_view_is_valid(&indexes_view)) {
			goto end;
		}

		consumed_size += indexes_view.buffer.size;
		action_path = lttng_action_path_create(
				(const uint64_t *) indexes_view.buffer.data,
				header->index_count);
		if (!action_path) {
			goto end;
		}
	} else {
		action_path = lttng_action_path_create(NULL, 0);
		if (!action_path) {
			goto end;
		}
	}

	ret = consumed_size;
	*_action_path = action_path;
end:
	return ret;
}

int lttng_action_path_serialize(const struct lttng_action_path *action_path,
		struct lttng_payload *payload)
{
	int ret;
	size_t index_count, i;
	enum lttng_action_path_status status;
	lttng_action_path_comm comm;

	status = lttng_action_path_get_index_count(action_path, &index_count);
	if (status != LTTNG_ACTION_PATH_STATUS_OK) {
		ret = -1;
		goto end;
	}

	comm = {
		.index_count = (uint32_t) index_count,
	};
	ret = lttng_dynamic_buffer_append(&payload->buffer,
			&comm,
			sizeof(struct lttng_action_path_comm));

	for (i = 0; i < index_count; i++) {
		uint64_t path_index;

		status = lttng_action_path_get_index_at_index(
				action_path, i, &path_index);
		if (status != LTTNG_ACTION_PATH_STATUS_OK) {
			ret = -1;
			goto end;
		}

		ret = lttng_dynamic_buffer_append(&payload->buffer, &path_index,
				sizeof(path_index));
		if (ret) {
			goto end;
		}
	}

	ret = 0;
end:
	return ret;
}
