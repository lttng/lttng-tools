/*
 * Copyright (C) 2019 Simon Marchi <simon.marchi@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <assert.h>
#include <common/dynamic-array.h>
#include <common/payload.h>
#include <common/payload-view.h>
#include <common/error.h>
#include <common/macros.h>
#include <lttng/action/action-internal.h>
#include <lttng/action/group-internal.h>
#include <lttng/action/group.h>

#define IS_GROUP_ACTION(action) \
	(lttng_action_get_type(action) == LTTNG_ACTION_TYPE_GROUP)

struct lttng_action_group {
	struct lttng_action parent;

	/* The array owns the action elements. */
	struct lttng_dynamic_pointer_array actions;
};

struct lttng_action_group_comm {
	uint32_t action_count;

	/*
	 * Variable data: each element serialized sequentially.
	 */
	char data[];
} LTTNG_PACKED;

static void destroy_lttng_action_group_element(void *ptr)
{
	struct lttng_action *element = (struct lttng_action *) ptr;

	lttng_action_destroy(element);
}

static struct lttng_action_group *action_group_from_action(
		const struct lttng_action *action)
{
	assert(action);

	return container_of(action, struct lttng_action_group, parent);
}

static const struct lttng_action_group *action_group_from_action_const(
		const struct lttng_action *action)
{
	assert(action);

	return container_of(action, struct lttng_action_group, parent);
}

static bool lttng_action_group_validate(struct lttng_action *action)
{
	unsigned int i, count;
	struct lttng_action_group *action_group;
	bool valid;

	assert(IS_GROUP_ACTION(action));

	action_group = action_group_from_action(action);

	count = lttng_dynamic_pointer_array_get_count(&action_group->actions);

	for (i = 0; i < count; i++) {
		struct lttng_action *child =
				lttng_dynamic_pointer_array_get_pointer(
						&action_group->actions, i);

		assert(child);

		if (!lttng_action_validate(child)) {
			valid = false;
			goto end;
		}
	}

	valid = true;

end:
	return valid;
}

static bool lttng_action_group_is_equal(
		const struct lttng_action *_a, const struct lttng_action *_b)
{
	bool is_equal = false;
	unsigned int i;
	unsigned int a_count, b_count;

	if (lttng_action_group_get_count(_a, &a_count) !=
			LTTNG_ACTION_STATUS_OK) {
		goto end;
	}

	if (lttng_action_group_get_count(_b, &b_count) !=
			LTTNG_ACTION_STATUS_OK) {
		goto end;
	}

	if (a_count != b_count) {
		goto end;
	}

	for (i = 0; i < a_count; i++) {
		const struct lttng_action *child_a =
			lttng_action_group_get_at_index(_a, i);
		const struct lttng_action *child_b =
			lttng_action_group_get_at_index(_b, i);

		assert(child_a);
		assert(child_b);

		if (!lttng_action_is_equal(child_a, child_b)) {
			goto end;
		}
	}

	is_equal = true;
end:
	return is_equal;
}

static int lttng_action_group_serialize(
		struct lttng_action *action, struct lttng_payload *payload)
{
	struct lttng_action_group *action_group;
	struct lttng_action_group_comm comm;
	int ret;
	unsigned int i, count;

	assert(action);
	assert(payload);
	assert(IS_GROUP_ACTION(action));

	action_group = action_group_from_action(action);

	DBG("Serializing action group");

	count = lttng_dynamic_pointer_array_get_count(&action_group->actions);

	comm.action_count = count;

	ret = lttng_dynamic_buffer_append(
			&payload->buffer, &comm, sizeof(comm));
	if (ret) {
		ret = -1;
		goto end;
	}

	for (i = 0; i < count; i++) {
		struct lttng_action *child =
				lttng_dynamic_pointer_array_get_pointer(
						&action_group->actions, i);

		assert(child);

		ret = lttng_action_serialize(child, payload);
		if (ret) {
			goto end;
		}
	}

	ret = 0;

end:
	return ret;
}

static void lttng_action_group_destroy(struct lttng_action *action)
{
	struct lttng_action_group *action_group;

	if (!action) {
		goto end;
	}

	action_group = action_group_from_action(action);
	lttng_dynamic_pointer_array_reset(&action_group->actions);
	free(action_group);

end:
	return;
}

ssize_t lttng_action_group_create_from_payload(
		struct lttng_payload_view *view,
		struct lttng_action **p_action)
{
	ssize_t consumed_len;
	const struct lttng_action_group_comm *comm;
	struct lttng_action *group;
	struct lttng_action *child_action = NULL;
	enum lttng_action_status status;
	size_t i;

	group = lttng_action_group_create();
	if (!group) {
		consumed_len = -1;
		goto end;
	}

	comm = (typeof(comm)) view->buffer.data;

	consumed_len = sizeof(struct lttng_action_group_comm);

	for (i = 0; i < comm->action_count; i++) {
		ssize_t consumed_len_child;
		struct lttng_payload_view child_view =
				lttng_payload_view_from_view(view, consumed_len,
						view->buffer.size - consumed_len);

		consumed_len_child = lttng_action_create_from_payload(
				&child_view, &child_action);
		if (consumed_len_child < 0) {
			consumed_len = -1;
			goto end;
		}

		status = lttng_action_group_add_action(group, child_action);
		if (status != LTTNG_ACTION_STATUS_OK) {
			consumed_len = -1;
			goto end;
		}

		/* Transfer ownership to the action group. */
		lttng_action_put(child_action);
		child_action = NULL;

		consumed_len += consumed_len_child;
	}

	*p_action = group;
	group = NULL;

end:
	lttng_action_group_destroy(group);
	return consumed_len;
}

struct lttng_action *lttng_action_group_create(void)
{
	struct lttng_action_group *action_group;
	struct lttng_action *action;

	action_group = zmalloc(sizeof(struct lttng_action_group));
	if (!action_group) {
		action = NULL;
		goto end;
	}

	action = &action_group->parent;

	lttng_action_init(action, LTTNG_ACTION_TYPE_GROUP,
			lttng_action_group_validate,
			lttng_action_group_serialize,
			lttng_action_group_is_equal,
			lttng_action_group_destroy);

	lttng_dynamic_pointer_array_init(&action_group->actions,
			destroy_lttng_action_group_element);

end:
	return action;
}

enum lttng_action_status lttng_action_group_add_action(
		struct lttng_action *group, struct lttng_action *action)
{
	struct lttng_action_group *action_group;
	enum lttng_action_status status;
	int ret;

	if (!group || !IS_GROUP_ACTION(group) || !action) {
		status = LTTNG_ACTION_STATUS_INVALID;
		goto end;
	}

	/*
	 * Don't allow adding groups in groups for now, since we're afraid of
	 * cycles.
	 */
	if (IS_GROUP_ACTION(action)) {
		status = LTTNG_ACTION_STATUS_INVALID;
		goto end;
	}

	action_group = action_group_from_action(group);

	ret = lttng_dynamic_pointer_array_add_pointer(&action_group->actions,
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

enum lttng_action_status lttng_action_group_get_count(
		const struct lttng_action *group, unsigned int *count)
{
	const struct lttng_action_group *action_group;
	enum lttng_action_status status = LTTNG_ACTION_STATUS_OK;

	if (!group || !IS_GROUP_ACTION(group)) {
		status = LTTNG_ACTION_STATUS_INVALID;
		*count = 0;
		goto end;
	}

	action_group = action_group_from_action_const(group);
	*count = lttng_dynamic_pointer_array_get_count(&action_group->actions);
end:
	return status;
}

const struct lttng_action *lttng_action_group_get_at_index(
		const struct lttng_action *group, unsigned int index)
{
	unsigned int count;
	const struct lttng_action_group *action_group;
	const struct lttng_action * action = NULL;

	if (lttng_action_group_get_count(group, &count) !=
			LTTNG_ACTION_STATUS_OK) {
		goto end;
	}

	if (index >= count) {
		goto end;
	}

	action_group = action_group_from_action_const(group);
	action = lttng_dynamic_pointer_array_get_pointer(&action_group->actions,
			index);
end:
	return action;
}
