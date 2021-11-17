/*
 * Copyright (C) 2019 Simon Marchi <simon.marchi@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <common/dynamic-array.hpp>
#include <common/error.hpp>
#include <common/macros.hpp>
#include <common/mi-lttng.hpp>
#include <common/payload-view.hpp>
#include <common/payload.hpp>
#include <lttng/action/action-internal.hpp>
#include <lttng/action/list-internal.hpp>
#include <lttng/action/list.h>

#define IS_LIST_ACTION(action) \
	(lttng_action_get_type(action) == LTTNG_ACTION_TYPE_LIST)

struct lttng_action_list {
	struct lttng_action parent;

	/* The array owns the action elements. */
	struct lttng_dynamic_pointer_array actions;
};

struct lttng_action_list_comm {
	uint32_t action_count;

	/*
	 * Variable data: each element serialized sequentially.
	 */
	char data[];
} LTTNG_PACKED;

static void destroy_lttng_action_list_element(void *ptr)
{
	struct lttng_action *element = (struct lttng_action *) ptr;

	lttng_action_destroy(element);
}

static struct lttng_action_list *action_list_from_action(
		const struct lttng_action *action)
{
	LTTNG_ASSERT(action);

	return container_of(action, struct lttng_action_list, parent);
}

static const struct lttng_action_list *action_list_from_action_const(
		const struct lttng_action *action)
{
	LTTNG_ASSERT(action);

	return container_of(action, struct lttng_action_list, parent);
}

static bool lttng_action_list_validate(struct lttng_action *action)
{
	unsigned int i, count;
	struct lttng_action_list *action_list;
	bool valid;

	LTTNG_ASSERT(IS_LIST_ACTION(action));

	action_list = action_list_from_action(action);

	count = lttng_dynamic_pointer_array_get_count(&action_list->actions);

	for (i = 0; i < count; i++) {
		struct lttng_action *child =
				(lttng_action *) lttng_dynamic_pointer_array_get_pointer(
						&action_list->actions, i);

		LTTNG_ASSERT(child);

		if (!lttng_action_validate(child)) {
			valid = false;
			goto end;
		}
	}

	valid = true;

end:
	return valid;
}

static bool lttng_action_list_is_equal(
		const struct lttng_action *_a, const struct lttng_action *_b)
{
	bool is_equal = false;
	unsigned int i;
	unsigned int a_count, b_count;

	if (lttng_action_list_get_count(_a, &a_count) !=
			LTTNG_ACTION_STATUS_OK) {
		goto end;
	}

	if (lttng_action_list_get_count(_b, &b_count) !=
			LTTNG_ACTION_STATUS_OK) {
		goto end;
	}

	if (a_count != b_count) {
		goto end;
	}

	for (i = 0; i < a_count; i++) {
		const struct lttng_action *child_a =
			lttng_action_list_get_at_index(_a, i);
		const struct lttng_action *child_b =
			lttng_action_list_get_at_index(_b, i);

		LTTNG_ASSERT(child_a);
		LTTNG_ASSERT(child_b);

		if (!lttng_action_is_equal(child_a, child_b)) {
			goto end;
		}
	}

	is_equal = true;
end:
	return is_equal;
}

static int lttng_action_list_serialize(
		struct lttng_action *action, struct lttng_payload *payload)
{
	struct lttng_action_list *action_list;
	struct lttng_action_list_comm comm;
	int ret;
	unsigned int i, count;

	LTTNG_ASSERT(action);
	LTTNG_ASSERT(payload);
	LTTNG_ASSERT(IS_LIST_ACTION(action));

	action_list = action_list_from_action(action);

	DBG("Serializing action list");

	count = lttng_dynamic_pointer_array_get_count(&action_list->actions);

	comm.action_count = count;

	ret = lttng_dynamic_buffer_append(
			&payload->buffer, &comm, sizeof(comm));
	if (ret) {
		ret = -1;
		goto end;
	}

	for (i = 0; i < count; i++) {
		struct lttng_action *child =
				(lttng_action *) lttng_dynamic_pointer_array_get_pointer(
						&action_list->actions, i);

		LTTNG_ASSERT(child);

		ret = lttng_action_serialize(child, payload);
		if (ret) {
			goto end;
		}
	}

	ret = 0;

end:
	return ret;
}

static void lttng_action_list_destroy(struct lttng_action *action)
{
	struct lttng_action_list *action_list;

	if (!action) {
		goto end;
	}

	action_list = action_list_from_action(action);
	lttng_dynamic_pointer_array_reset(&action_list->actions);
	free(action_list);

end:
	return;
}

ssize_t lttng_action_list_create_from_payload(
		struct lttng_payload_view *view,
		struct lttng_action **p_action)
{
	ssize_t consumed_len;
	const struct lttng_action_list_comm *comm;
	struct lttng_action *list;
	struct lttng_action *child_action = NULL;
	enum lttng_action_status status;
	size_t i;

	list = lttng_action_list_create();
	if (!list) {
		consumed_len = -1;
		goto end;
	}

	comm = (typeof(comm)) view->buffer.data;

	consumed_len = sizeof(struct lttng_action_list_comm);

	for (i = 0; i < comm->action_count; i++) {
		ssize_t consumed_len_child;
		struct lttng_payload_view child_view =
				lttng_payload_view_from_view(view, consumed_len,
						view->buffer.size - consumed_len);

		if (!lttng_payload_view_is_valid(&child_view)) {
			consumed_len = -1;
			goto end;
		}

		consumed_len_child = lttng_action_create_from_payload(
				&child_view, &child_action);
		if (consumed_len_child < 0) {
			consumed_len = -1;
			goto end;
		}

		status = lttng_action_list_add_action(list, child_action);
		if (status != LTTNG_ACTION_STATUS_OK) {
			consumed_len = -1;
			goto end;
		}

		/* Transfer ownership to the action list. */
		lttng_action_put(child_action);
		child_action = NULL;

		consumed_len += consumed_len_child;
	}

	*p_action = list;
	list = NULL;

end:
	lttng_action_list_destroy(list);
	return consumed_len;
}

static enum lttng_action_status lttng_action_list_add_error_query_results(
		const struct lttng_action *action,
		struct lttng_error_query_results *results)
{
	unsigned int i, count;
	enum lttng_action_status action_status;
	const struct lttng_action_list *list =
			container_of(action, typeof(*list), parent);

	action_status = lttng_action_list_get_count(action, &count);
	if (action_status != LTTNG_ACTION_STATUS_OK) {
		goto end;
	}

	for (i = 0; i < count; i++) {
		struct lttng_action *inner_action =
				lttng_action_list_borrow_mutable_at_index(action, i);

		action_status = lttng_action_add_error_query_results(
				inner_action, results);
		if (action_status != LTTNG_ACTION_STATUS_OK) {
			goto end;
		}
	}
end:
	return action_status;
}

enum lttng_error_code lttng_action_list_mi_serialize(
		const struct lttng_trigger *trigger,
		const struct lttng_action *action,
		struct mi_writer *writer,
		const struct mi_lttng_error_query_callbacks
				*error_query_callbacks,
		struct lttng_dynamic_array *action_path_indexes)
{
	int ret;
	struct lttng_action_list *action_list;
	unsigned int i, count;
	enum lttng_error_code ret_code;

	LTTNG_ASSERT(action);
	LTTNG_ASSERT(IS_LIST_ACTION(action));
	LTTNG_ASSERT(writer);

	/* Open action list. */
	ret = mi_lttng_writer_open_element(
			writer, mi_lttng_element_action_list);
	if (ret) {
		goto mi_error;
	}

	/* Serialize every action of the list. */
	action_list = action_list_from_action(action);
	count = lttng_dynamic_pointer_array_get_count(&action_list->actions);
	for (i = 0; i < count; i++) {
		const struct lttng_action *child =
				lttng_action_list_get_at_index(action, i);
		const uint64_t index = (uint64_t) i;

		LTTNG_ASSERT(child);

		/*
		 * Add the index to the action path.
		 *
		 * This index is replaced on every iteration to walk the action
		 * tree in-order and to re-use the dynamic array instead of
		 * copying it at every level.
		 */
		ret = lttng_dynamic_array_add_element(
				action_path_indexes, &index);
		if (ret) {
			ret_code = LTTNG_ERR_NOMEM;
			goto end;
		}

		ret_code = lttng_action_mi_serialize(trigger, child, writer,
				error_query_callbacks, action_path_indexes);
		if (ret_code != LTTNG_OK) {
			goto end;
		}

		ret = lttng_dynamic_array_remove_element(action_path_indexes,
				lttng_dynamic_array_get_count(
						action_path_indexes) -
						1);
		if (ret) {
			ret_code = LTTNG_ERR_UNK;
			goto end;
		}
	}

	/* Close action_list element. */
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

struct lttng_action *lttng_action_list_create(void)
{
	struct lttng_action_list *action_list;
	struct lttng_action *action;

	action_list = zmalloc<lttng_action_list>();
	if (!action_list) {
		action = NULL;
		goto end;
	}

	action = &action_list->parent;

	/*
	 * The mi for the list is handled at the lttng_action_mi level to ease
	 * action path management for error query.
	 */
	lttng_action_init(action, LTTNG_ACTION_TYPE_LIST,
			lttng_action_list_validate, lttng_action_list_serialize,
			lttng_action_list_is_equal, lttng_action_list_destroy,
			NULL, lttng_action_list_add_error_query_results, NULL);

	lttng_dynamic_pointer_array_init(&action_list->actions,
			destroy_lttng_action_list_element);

end:
	return action;
}

enum lttng_action_status lttng_action_list_add_action(
		struct lttng_action *list, struct lttng_action *action)
{
	struct lttng_action_list *action_list;
	enum lttng_action_status status;
	int ret;

	if (!list || !IS_LIST_ACTION(list) || !action) {
		status = LTTNG_ACTION_STATUS_INVALID;
		goto end;
	}

	/*
	 * Don't allow adding lists in lists for now, since we're afraid of
	 * cycles.
	 */
	if (IS_LIST_ACTION(action)) {
		status = LTTNG_ACTION_STATUS_INVALID;
		goto end;
	}

	action_list = action_list_from_action(list);

	ret = lttng_dynamic_pointer_array_add_pointer(&action_list->actions,
			action);
	if (ret < 0) {
		status = LTTNG_ACTION_STATUS_ERROR;
		goto end;
	}

	/* Take ownership of the object. */
	lttng_action_get(action);
	status = LTTNG_ACTION_STATUS_OK;
end:
	return status;
}

enum lttng_action_status lttng_action_list_get_count(
		const struct lttng_action *list, unsigned int *count)
{
	const struct lttng_action_list *action_list;
	enum lttng_action_status status = LTTNG_ACTION_STATUS_OK;

	if (!list || !IS_LIST_ACTION(list)) {
		status = LTTNG_ACTION_STATUS_INVALID;
		*count = 0;
		goto end;
	}

	action_list = action_list_from_action_const(list);
	*count = lttng_dynamic_pointer_array_get_count(&action_list->actions);
end:
	return status;
}

const struct lttng_action *lttng_action_list_get_at_index(
		const struct lttng_action *list, unsigned int index)
{
	return lttng_action_list_borrow_mutable_at_index(list, index);
}

struct lttng_action *lttng_action_list_borrow_mutable_at_index(
		const struct lttng_action *list, unsigned int index)
{
	unsigned int count;
	const struct lttng_action_list *action_list;
	struct lttng_action *action = NULL;

	if (lttng_action_list_get_count(list, &count) !=
			LTTNG_ACTION_STATUS_OK) {
		goto end;
	}

	if (index >= count) {
		goto end;
	}

	action_list = action_list_from_action_const(list);
	action = (lttng_action *) lttng_dynamic_pointer_array_get_pointer(&action_list->actions,
			index);
end:
	return action;
}
