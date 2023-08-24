/*
 * error-query.c
 *
 * Copyright (C) 2021 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <common/dynamic-array.hpp>
#include <common/error.hpp>
#include <common/macros.hpp>
#include <common/mi-lttng.hpp>
#include <common/sessiond-comm/sessiond-comm.hpp>

#include <lttng/action/action-internal.hpp>
#include <lttng/action/list-internal.hpp>
#include <lttng/action/path-internal.hpp>
#include <lttng/error-query-internal.hpp>
#include <lttng/error-query.h>
#include <lttng/trigger/trigger-internal.hpp>

#include <stddef.h>

struct lttng_error_query {
	enum lttng_error_query_target_type target_type;
};

struct lttng_error_query_result {
	enum lttng_error_query_result_type type;
	char *name;
	char *description;
};

struct lttng_error_query_results {
	struct lttng_dynamic_pointer_array results;
};

namespace {
struct lttng_error_query_comm {
	/* enum lttng_error_query_target_type */
	int8_t target_type;
	/* Target-specific payload. */
	char payload[];
};

struct lttng_error_query_trigger {
	struct lttng_error_query parent;
	/* Mutable only because of the reference count. */
	struct lttng_trigger *trigger;
};

struct lttng_error_query_condition {
	struct lttng_error_query parent;
	/* Mutable only because of the reference count. */
	struct lttng_trigger *trigger;
};

struct lttng_error_query_action {
	struct lttng_error_query parent;
	/* Mutable only because of the reference count. */
	struct lttng_trigger *trigger;
	struct lttng_action_path *action_path;
};

struct lttng_error_query_result_comm {
	/* enum lttng_error_query_result_type */
	uint8_t type;
	/* Length of name (including null-terminator). */
	uint32_t name_len;
	/* Length of description (including null-terminator). */
	uint32_t description_len;
	/* Name, description, and type-specific payload follow. */
	char payload[];
} LTTNG_PACKED;

struct lttng_error_query_result_counter_comm {
	uint64_t value;
} LTTNG_PACKED;

struct lttng_error_query_result_counter {
	struct lttng_error_query_result parent;
	uint64_t value;
};

struct lttng_error_query_results_comm {
	uint32_t count;
	/* `count` instances of `struct lttng_error_query_result` follow. */
	char payload[];
} LTTNG_PACKED;
} /* namespace */

static enum lttng_error_code
lttng_error_query_result_mi_serialize(const struct lttng_error_query_result *result,
				      struct mi_writer *writer);

static enum lttng_error_code
lttng_error_query_result_counter_mi_serialize(const struct lttng_error_query_result *result,
					      struct mi_writer *writer);

struct lttng_error_query *lttng_error_query_trigger_create(const struct lttng_trigger *trigger)
{
	struct lttng_error_query_trigger *query = nullptr;
	struct lttng_trigger *trigger_copy = nullptr;

	if (!trigger) {
		goto end;
	}

	trigger_copy = lttng_trigger_copy(trigger);
	if (!trigger_copy) {
		goto end;
	}

	query = zmalloc<lttng_error_query_trigger>();
	if (!query) {
		PERROR("Failed to allocate trigger error query");
		goto error;
	}

	query->parent.target_type = LTTNG_ERROR_QUERY_TARGET_TYPE_TRIGGER;
	query->trigger = trigger_copy;
	trigger_copy = nullptr;

error:
	lttng_trigger_put(trigger_copy);
end:
	return query ? &query->parent : nullptr;
}

struct lttng_error_query *lttng_error_query_condition_create(const struct lttng_trigger *trigger)
{
	struct lttng_error_query_condition *query = nullptr;
	struct lttng_trigger *trigger_copy = nullptr;

	if (!trigger) {
		goto end;
	}

	trigger_copy = lttng_trigger_copy(trigger);
	if (!trigger_copy) {
		goto end;
	}

	query = zmalloc<lttng_error_query_condition>();
	if (!query) {
		PERROR("Failed to allocate condition error query");
		goto error;
	}

	query->parent.target_type = LTTNG_ERROR_QUERY_TARGET_TYPE_CONDITION;
	query->trigger = trigger_copy;
	trigger_copy = nullptr;

error:
	lttng_trigger_put(trigger_copy);
end:
	return query ? &query->parent : nullptr;
}

static struct lttng_action *
get_trigger_action_from_path(struct lttng_trigger *trigger,
			     const struct lttng_action_path *action_path)
{
	size_t index_count, i;
	enum lttng_action_path_status path_status;
	struct lttng_action *current_action = nullptr;

	path_status = lttng_action_path_get_index_count(action_path, &index_count);
	if (path_status != LTTNG_ACTION_PATH_STATUS_OK) {
		goto end;
	}

	current_action = lttng_trigger_get_action(trigger);
	for (i = 0; i < index_count; i++) {
		uint64_t path_index;

		path_status = lttng_action_path_get_index_at_index(action_path, i, &path_index);
		current_action =
			lttng_action_list_borrow_mutable_at_index(current_action, path_index);
		if (!current_action) {
			/* Invalid action path. */
			goto end;
		}
	}

end:
	return current_action;
}

static bool is_valid_action_path(const struct lttng_trigger *trigger,
				 const struct lttng_action_path *action_path)
{
	/*
	 * While 'trigger's constness is casted-away, the trigger and resulting
	 * action are not modified; we merely check for the action's existence.
	 */
	return !!get_trigger_action_from_path((struct lttng_trigger *) trigger, action_path);
}

struct lttng_error_query *
lttng_error_query_action_create(const struct lttng_trigger *trigger,
				const struct lttng_action_path *action_path)
{
	struct lttng_error_query_action *query = nullptr;
	struct lttng_trigger *trigger_copy = nullptr;
	int ret_copy;

	if (!trigger || !action_path || !is_valid_action_path(trigger, action_path)) {
		goto end;
	}

	trigger_copy = lttng_trigger_copy(trigger);
	if (!trigger_copy) {
		goto end;
	}

	query = zmalloc<lttng_error_query_action>();
	if (!query) {
		PERROR("Failed to allocate action error query");
		goto error;
	}

	ret_copy = lttng_action_path_copy(action_path, &query->action_path);
	if (ret_copy) {
		goto error;
	}

	query->parent.target_type = LTTNG_ERROR_QUERY_TARGET_TYPE_ACTION;
	query->trigger = trigger_copy;
	trigger_copy = nullptr;
	goto end;

error:
	lttng_trigger_put(trigger_copy);
	lttng_error_query_destroy(query ? &query->parent : nullptr);
end:
	return query ? &query->parent : nullptr;
}

void lttng_error_query_destroy(struct lttng_error_query *query)
{
	if (!query) {
		return;
	}

	switch (query->target_type) {
	case LTTNG_ERROR_QUERY_TARGET_TYPE_TRIGGER:
	{
		struct lttng_error_query_trigger *trigger_query =
			lttng::utils::container_of(query, &lttng_error_query_trigger::parent);

		lttng_trigger_put(trigger_query->trigger);
		free(trigger_query);
		break;
	}
	case LTTNG_ERROR_QUERY_TARGET_TYPE_CONDITION:
	{
		struct lttng_error_query_condition *condition_query =
			lttng::utils::container_of(query, &lttng_error_query_condition::parent);

		lttng_trigger_put(condition_query->trigger);
		free(condition_query);
		break;
	}
	case LTTNG_ERROR_QUERY_TARGET_TYPE_ACTION:
	{
		struct lttng_error_query_action *action_query =
			lttng::utils::container_of(query, &lttng_error_query_action::parent);

		lttng_trigger_put(action_query->trigger);
		lttng_action_path_destroy(action_query->action_path);
		free(action_query);
		break;
	}
	default:
		abort();
	}
}

static int lttng_error_query_result_counter_serialize(const struct lttng_error_query_result *result,
						      struct lttng_payload *payload)
{
	const struct lttng_error_query_result_counter *counter_result;

	LTTNG_ASSERT(result->type == LTTNG_ERROR_QUERY_RESULT_TYPE_COUNTER);
	counter_result =
		lttng::utils::container_of(result, &lttng_error_query_result_counter::parent);

	lttng_error_query_result_counter_comm comm = {
		.value = counter_result->value,
	};

	return lttng_dynamic_buffer_append(
		&payload->buffer, &comm, sizeof(struct lttng_error_query_result_counter_comm));
}

int lttng_error_query_result_serialize(const struct lttng_error_query_result *result,
				       struct lttng_payload *payload)
{
	int ret;
	struct lttng_error_query_result_comm header;

	header.type = (uint8_t) result->type;
	header.name_len = (typeof(header.name_len)) strlen(result->name) + 1;
	header.description_len = (typeof(header.name_len)) strlen(result->description) + 1;

	/* Header. */
	ret = lttng_dynamic_buffer_append(&payload->buffer, &header, sizeof(header));
	if (ret) {
		ERR("Failed to append error query result communication header to payload");
		goto end;
	}

	/* Name. */
	ret = lttng_dynamic_buffer_append(&payload->buffer, result->name, header.name_len);
	if (ret) {
		ERR("Failed to append error query result name to payload");
		goto end;
	}

	/* Description. */
	ret = lttng_dynamic_buffer_append(
		&payload->buffer, result->description, header.description_len);
	if (ret) {
		ERR("Failed to append error query result description to payload");
		goto end;
	}

	/* Type-specific payload. */
	switch (result->type) {
	case LTTNG_ERROR_QUERY_RESULT_TYPE_COUNTER:
		ret = lttng_error_query_result_counter_serialize(result, payload);
		if (ret) {
			ERR("Failed to serialize counter error query result");
			goto end;
		}
		break;
	default:
		abort();
	}

end:
	return ret;
}

static int lttng_error_query_result_init(struct lttng_error_query_result *result,
					 enum lttng_error_query_result_type result_type,
					 const char *name,
					 const char *description)
{
	int ret;

	LTTNG_ASSERT(name);
	LTTNG_ASSERT(description);

	result->type = result_type;

	result->name = strdup(name);
	if (!result->name) {
		PERROR("Failed to copy error query result name");
		ret = -1;
		goto end;
	}

	result->description = strdup(description);
	if (!result->description) {
		PERROR("Failed to copy error query result description");
		ret = -1;
		goto end;
	}

	ret = 0;
end:
	return ret;
}

void lttng_error_query_result_destroy(struct lttng_error_query_result *counter)
{
	if (!counter) {
		return;
	}

	switch (counter->type) {
	case LTTNG_ERROR_QUERY_RESULT_TYPE_COUNTER:
		/* Nothing to tear down. */
		break;
	default:
		abort();
	}

	free(counter->name);
	free(counter->description);
	free(counter);
}

struct lttng_error_query_result *
lttng_error_query_result_counter_create(const char *name, const char *description, uint64_t value)
{
	int init_ret;
	struct lttng_error_query_result_counter *counter;

	counter = zmalloc<lttng_error_query_result_counter>();
	if (!counter) {
		PERROR("Failed to allocate error query counter result");
		goto end;
	}

	init_ret = lttng_error_query_result_init(
		&counter->parent, LTTNG_ERROR_QUERY_RESULT_TYPE_COUNTER, name, description);
	if (init_ret) {
		goto error;
	}

	counter->value = value;
	goto end;
error:
	lttng_error_query_result_destroy(&counter->parent);
end:
	return counter ? &counter->parent : nullptr;
}

static void destroy_result(void *ptr)
{
	struct lttng_error_query_result *result = (typeof(result)) ptr;

	lttng_error_query_result_destroy(result);
}

struct lttng_error_query_results *lttng_error_query_results_create()
{
	struct lttng_error_query_results *set = zmalloc<lttng_error_query_results>();

	if (!set) {
		PERROR("Failed to allocate an error query result set");
		goto end;
	}

	lttng_dynamic_pointer_array_init(&set->results, destroy_result);
end:
	return set;
}

int lttng_error_query_results_add_result(struct lttng_error_query_results *results,
					 struct lttng_error_query_result *result)
{
	return lttng_dynamic_pointer_array_add_pointer(&results->results, result);
}

ssize_t lttng_error_query_result_create_from_payload(struct lttng_payload_view *view,
						     struct lttng_error_query_result **result)
{
	ssize_t used_size = 0;
	struct lttng_error_query_result_comm *header;
	struct lttng_payload_view header_view =
		lttng_payload_view_from_view(view, 0, sizeof(*header));
	const char *name;
	const char *description;

	if (!lttng_payload_view_is_valid(&header_view)) {
		used_size = -1;
		goto end;
	}

	header = (typeof(header)) header_view.buffer.data;
	used_size += sizeof(*header);

	{
		struct lttng_payload_view name_view =
			lttng_payload_view_from_view(view, used_size, header->name_len);

		if (!lttng_payload_view_is_valid(&name_view) ||
		    !lttng_buffer_view_contains_string(
			    &name_view.buffer, name_view.buffer.data, header->name_len)) {
			used_size = -1;
			goto end;
		}

		name = name_view.buffer.data;
		used_size += header->name_len;
	}

	{
		struct lttng_payload_view description_view =
			lttng_payload_view_from_view(view, used_size, header->description_len);

		if (!lttng_payload_view_is_valid(&description_view) ||
		    !lttng_buffer_view_contains_string(&description_view.buffer,
						       description_view.buffer.data,
						       header->description_len)) {
			used_size = -1;
			goto end;
		}

		description = description_view.buffer.data;
		used_size += header->description_len;
	}

	switch (header->type) {
	case LTTNG_ERROR_QUERY_RESULT_TYPE_COUNTER:
	{
		struct lttng_error_query_result_counter_comm *counter;
		struct lttng_payload_view counter_payload_view =
			lttng_payload_view_from_view(view, used_size, sizeof(*counter));

		if (!lttng_payload_view_is_valid(&counter_payload_view)) {
			used_size = -1;
			goto end;
		}

		counter = (typeof(counter)) counter_payload_view.buffer.data;
		*result =
			lttng_error_query_result_counter_create(name, description, counter->value);
		if (!*result) {
			used_size = -1;
			goto end;
		}

		used_size += sizeof(*counter);
		break;
	}
	default:
		used_size = -1;
		goto end;
	}

end:
	return used_size;
}

int lttng_error_query_results_serialize(const struct lttng_error_query_results *results,
					struct lttng_payload *payload)
{
	int ret;
	size_t result_index;
	const size_t result_count = lttng_dynamic_pointer_array_get_count(&results->results);
	struct lttng_error_query_results_comm header;

	header.count = (decltype(header.count)) result_count;

	/* Header. */
	ret = lttng_dynamic_buffer_append(&payload->buffer, &header, sizeof(header));
	if (ret) {
		ERR("Failed to append error query result set header to payload");
		goto end;
	}

	/* Results. */
	for (result_index = 0; result_index < result_count; result_index++) {
		const struct lttng_error_query_result *result =
			(typeof(result)) lttng_dynamic_pointer_array_get_pointer(&results->results,
										 result_index);

		ret = lttng_error_query_result_serialize(result, payload);
		if (ret) {
			ERR("Failed to append error query result to payload");
			goto end;
		}
	}
end:
	return ret;
}

ssize_t lttng_error_query_results_create_from_payload(struct lttng_payload_view *view,
						      struct lttng_error_query_results **_results)
{
	size_t result_index;
	ssize_t total_used_size = 0;
	struct lttng_error_query_results_comm *header;
	struct lttng_payload_view header_view =
		lttng_payload_view_from_view(view, 0, sizeof(*header));
	struct lttng_error_query_results *results = nullptr;

	if (!lttng_payload_view_is_valid(&header_view)) {
		ERR("Failed to map view to error query result set header");
		total_used_size = -1;
		goto end;
	}

	header = (typeof(header)) header_view.buffer.data;
	total_used_size += sizeof(*header);
	results = lttng_error_query_results_create();
	if (!results) {
		total_used_size = -1;
		goto end;
	}

	for (result_index = 0; result_index < header->count; result_index++) {
		ssize_t used_size;
		struct lttng_error_query_result *result;
		struct lttng_payload_view result_view =
			lttng_payload_view_from_view(view, total_used_size, -1);

		if (!lttng_payload_view_is_valid(&result_view)) {
			total_used_size = -1;
			goto end;
		}

		used_size = lttng_error_query_result_create_from_payload(&result_view, &result);
		if (used_size < 0) {
			total_used_size = -1;
			goto end;
		}

		total_used_size += used_size;

		if (lttng_dynamic_pointer_array_add_pointer(&results->results, result)) {
			lttng_error_query_result_destroy(result);
			total_used_size = -1;
			goto end;
		}
	}

	*_results = results;
	results = nullptr;
end:
	lttng_error_query_results_destroy(results);
	return total_used_size;
}

static int lttng_error_query_trigger_serialize(const struct lttng_error_query *query,
					       struct lttng_payload *payload)
{
	int ret;
	const struct lttng_error_query_trigger *query_trigger =
		lttng::utils::container_of(query, &lttng_error_query_trigger::parent);

	if (!lttng_trigger_validate(query_trigger->trigger)) {
		ret = -1;
		goto end;
	}

	ret = lttng_trigger_serialize(query_trigger->trigger, payload);
	if (ret) {
		goto end;
	}

end:
	return ret;
}

static int lttng_error_query_condition_serialize(const struct lttng_error_query *query,
						 struct lttng_payload *payload)
{
	int ret;
	const struct lttng_error_query_condition *query_trigger =
		lttng::utils::container_of(query, &lttng_error_query_condition::parent);

	if (!lttng_trigger_validate(query_trigger->trigger)) {
		ret = -1;
		goto end;
	}

	ret = lttng_trigger_serialize(query_trigger->trigger, payload);
	if (ret) {
		goto end;
	}

end:
	return ret;
}

static int lttng_error_query_action_serialize(const struct lttng_error_query *query,
					      struct lttng_payload *payload)
{
	int ret;
	const struct lttng_error_query_action *query_action =
		lttng::utils::container_of(query, &lttng_error_query_action::parent);

	if (!lttng_trigger_validate(query_action->trigger)) {
		ret = -1;
		goto end;
	}

	ret = lttng_trigger_serialize(query_action->trigger, payload);
	if (ret) {
		goto end;
	}

	ret = lttng_action_path_serialize(query_action->action_path, payload);
	if (ret) {
		goto end;
	}

end:
	return ret;
}

enum lttng_error_query_target_type
lttng_error_query_get_target_type(const struct lttng_error_query *query)
{
	return query->target_type;
}

const struct lttng_trigger *
lttng_error_query_trigger_borrow_target(const struct lttng_error_query *query)
{
	const struct lttng_error_query_trigger *query_trigger =
		lttng::utils::container_of(query, &lttng_error_query_trigger::parent);

	return query_trigger->trigger;
}

const struct lttng_trigger *
lttng_error_query_condition_borrow_target(const struct lttng_error_query *query)
{
	const struct lttng_error_query_condition *query_trigger =
		lttng::utils::container_of(query, &lttng_error_query_condition::parent);

	return query_trigger->trigger;
}

const struct lttng_trigger *
lttng_error_query_action_borrow_trigger_target(const struct lttng_error_query *query)
{
	const struct lttng_error_query_action *query_action =
		lttng::utils::container_of(query, &lttng_error_query_action::parent);

	return query_action->trigger;
}

struct lttng_action *
lttng_error_query_action_borrow_action_target(const struct lttng_error_query *query,
					      struct lttng_trigger *trigger)
{
	const struct lttng_error_query_action *query_action =
		lttng::utils::container_of(query, &lttng_error_query_action::parent);

	return get_trigger_action_from_path(trigger, query_action->action_path);
}

int lttng_error_query_serialize(const struct lttng_error_query *query,
				struct lttng_payload *payload)
{
	int ret;
	struct lttng_error_query_comm header;

	header.target_type = (decltype(header.target_type)) query->target_type;

	ret = lttng_dynamic_buffer_append(&payload->buffer, &header, sizeof(header));
	if (ret) {
		ERR("Failed to append error query header to payload");
		goto end;
	}

	switch (query->target_type) {
	case LTTNG_ERROR_QUERY_TARGET_TYPE_TRIGGER:
		ret = lttng_error_query_trigger_serialize(query, payload);
		if (ret) {
			goto end;
		}

		break;
	case LTTNG_ERROR_QUERY_TARGET_TYPE_CONDITION:
		ret = lttng_error_query_condition_serialize(query, payload);
		if (ret) {
			goto end;
		}

		break;
	case LTTNG_ERROR_QUERY_TARGET_TYPE_ACTION:
		ret = lttng_error_query_action_serialize(query, payload);
		if (ret) {
			goto end;
		}

		break;
	default:
		abort();
	}
end:
	return ret;
}

ssize_t lttng_error_query_create_from_payload(struct lttng_payload_view *view,
					      struct lttng_error_query **query)
{
	ssize_t used_size = 0;
	struct lttng_error_query_comm *header;
	struct lttng_trigger *trigger = nullptr;
	struct lttng_payload_view header_view =
		lttng_payload_view_from_view(view, 0, sizeof(*header));

	if (!lttng_payload_view_is_valid(&header_view)) {
		ERR("Failed to map error query header");
		used_size = -1;
		goto end;
	}

	used_size = sizeof(*header);

	header = (typeof(header)) header_view.buffer.data;
	switch ((enum lttng_error_query_target_type) header->target_type) {
	case LTTNG_ERROR_QUERY_TARGET_TYPE_TRIGGER:
	{
		ssize_t trigger_used_size;
		struct lttng_payload_view trigger_view =
			lttng_payload_view_from_view(view, used_size, -1);

		if (!lttng_payload_view_is_valid(&trigger_view)) {
			used_size = -1;
			goto end;
		}

		trigger_used_size = lttng_trigger_create_from_payload(&trigger_view, &trigger);
		if (trigger_used_size < 0) {
			used_size = -1;
			goto end;
		}

		used_size += trigger_used_size;

		*query = lttng_error_query_trigger_create(trigger);
		if (!*query) {
			used_size = -1;
			goto end;
		}

		break;
	}
	case LTTNG_ERROR_QUERY_TARGET_TYPE_CONDITION:
	{
		ssize_t trigger_used_size;
		struct lttng_payload_view trigger_view =
			lttng_payload_view_from_view(view, used_size, -1);

		if (!lttng_payload_view_is_valid(&trigger_view)) {
			used_size = -1;
			goto end;
		}

		trigger_used_size = lttng_trigger_create_from_payload(&trigger_view, &trigger);
		if (trigger_used_size < 0) {
			used_size = -1;
			goto end;
		}

		used_size += trigger_used_size;

		*query = lttng_error_query_condition_create(trigger);
		if (!*query) {
			used_size = -1;
			goto end;
		}

		break;
	}
	case LTTNG_ERROR_QUERY_TARGET_TYPE_ACTION:
	{
		struct lttng_action_path *action_path = nullptr;

		{
			ssize_t trigger_used_size;
			struct lttng_payload_view trigger_view =
				lttng_payload_view_from_view(view, used_size, -1);

			if (!lttng_payload_view_is_valid(&trigger_view)) {
				used_size = -1;
				goto end;
			}

			trigger_used_size =
				lttng_trigger_create_from_payload(&trigger_view, &trigger);
			if (trigger_used_size < 0) {
				used_size = -1;
				goto end;
			}

			used_size += trigger_used_size;
		}

		{
			ssize_t action_path_used_size;
			struct lttng_payload_view action_path_view =
				lttng_payload_view_from_view(view, used_size, -1);

			if (!lttng_payload_view_is_valid(&action_path_view)) {
				used_size = -1;
				goto end;
			}

			action_path_used_size = lttng_action_path_create_from_payload(
				&action_path_view, &action_path);
			if (action_path_used_size < 0) {
				used_size = -1;
				goto end;
			}

			used_size += action_path_used_size;
		}

		*query = lttng_error_query_action_create(trigger, action_path);
		lttng_action_path_destroy(action_path);
		if (!*query) {
			used_size = -1;
			goto end;
		}

		break;
	}
	default:
		used_size = -1;
		goto end;
	}

end:
	lttng_trigger_put(trigger);
	return used_size;
}

enum lttng_error_query_results_status
lttng_error_query_results_get_count(const struct lttng_error_query_results *results,
				    unsigned int *count)
{
	enum lttng_error_query_results_status status;

	if (!results || !count) {
		status = LTTNG_ERROR_QUERY_RESULTS_STATUS_INVALID_PARAMETER;
		goto end;
	}

	*count = lttng_dynamic_pointer_array_get_count(&results->results);
	status = LTTNG_ERROR_QUERY_RESULTS_STATUS_OK;
end:
	return status;
}

enum lttng_error_query_results_status
lttng_error_query_results_get_result(const struct lttng_error_query_results *results,
				     const struct lttng_error_query_result **result,
				     unsigned int index)
{
	unsigned int result_count;
	enum lttng_error_query_results_status status;

	if (!results || !result) {
		status = LTTNG_ERROR_QUERY_RESULTS_STATUS_INVALID_PARAMETER;
		goto end;
	}

	status = lttng_error_query_results_get_count(results, &result_count);
	if (status != LTTNG_ERROR_QUERY_RESULTS_STATUS_OK) {
		goto end;
	}

	if (index >= result_count) {
		status = LTTNG_ERROR_QUERY_RESULTS_STATUS_INVALID_PARAMETER;
		goto end;
	}

	*result =
		(typeof(*result)) lttng_dynamic_pointer_array_get_pointer(&results->results, index);
	LTTNG_ASSERT(*result);
	status = LTTNG_ERROR_QUERY_RESULTS_STATUS_OK;
end:
	return status;
}

void lttng_error_query_results_destroy(struct lttng_error_query_results *results)
{
	if (!results) {
		return;
	}

	lttng_dynamic_pointer_array_reset(&results->results);
	free(results);
}

enum lttng_error_query_result_type
lttng_error_query_result_get_type(const struct lttng_error_query_result *result)
{
	return result ? result->type : LTTNG_ERROR_QUERY_RESULT_TYPE_UNKNOWN;
}

enum lttng_error_query_result_status
lttng_error_query_result_get_name(const struct lttng_error_query_result *result, const char **name)
{
	enum lttng_error_query_result_status status;

	if (!result || !name) {
		status = LTTNG_ERROR_QUERY_RESULT_STATUS_INVALID_PARAMETER;
		goto end;
	}

	*name = result->name;
	status = LTTNG_ERROR_QUERY_RESULT_STATUS_OK;
end:
	return status;
}

enum lttng_error_query_result_status
lttng_error_query_result_get_description(const struct lttng_error_query_result *result,
					 const char **description)
{
	enum lttng_error_query_result_status status;

	if (!result || !description) {
		status = LTTNG_ERROR_QUERY_RESULT_STATUS_INVALID_PARAMETER;
		goto end;
	}

	*description = result->description;
	status = LTTNG_ERROR_QUERY_RESULT_STATUS_OK;
end:
	return status;
}

enum lttng_error_query_result_status
lttng_error_query_result_counter_get_value(const struct lttng_error_query_result *result,
					   uint64_t *value)
{
	enum lttng_error_query_result_status status;
	const struct lttng_error_query_result_counter *counter_result;

	if (!result || !value || result->type != LTTNG_ERROR_QUERY_RESULT_TYPE_COUNTER) {
		status = LTTNG_ERROR_QUERY_RESULT_STATUS_INVALID_PARAMETER;
		goto end;
	}

	counter_result =
		lttng::utils::container_of(result, &lttng_error_query_result_counter::parent);

	*value = counter_result->value;
	status = LTTNG_ERROR_QUERY_RESULT_STATUS_OK;
end:
	return status;
}

static enum lttng_error_code
lttng_error_query_result_counter_mi_serialize(const struct lttng_error_query_result *result,
					      struct mi_writer *writer)
{
	int ret;
	enum lttng_error_code ret_code;
	enum lttng_error_query_result_status status;
	uint64_t value;

	LTTNG_ASSERT(result);
	LTTNG_ASSERT(writer);

	status = lttng_error_query_result_counter_get_value(result, &value);
	LTTNG_ASSERT(status == LTTNG_ERROR_QUERY_RESULT_STATUS_OK);

	/* Open error query result counter element. */
	ret = mi_lttng_writer_open_element(writer, mi_lttng_element_error_query_result_counter);
	if (ret) {
		goto mi_error;
	}

	/* Value. */
	ret = mi_lttng_writer_write_element_unsigned_int(
		writer, mi_lttng_element_error_query_result_counter_value, value);
	if (ret) {
		goto mi_error;
	}

	/* Close error query result counter element. */
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

static enum lttng_error_code
lttng_error_query_result_mi_serialize(const struct lttng_error_query_result *result,
				      struct mi_writer *writer)
{
	int ret;
	enum lttng_error_code ret_code;
	enum lttng_error_query_result_status result_status;
	enum lttng_error_query_result_type type;
	const char *name = nullptr;
	const char *description = nullptr;

	LTTNG_ASSERT(result);
	LTTNG_ASSERT(writer);

	type = lttng_error_query_result_get_type(result);

	result_status = lttng_error_query_result_get_name(result, &name);
	LTTNG_ASSERT(result_status == LTTNG_ERROR_QUERY_RESULT_STATUS_OK);

	result_status = lttng_error_query_result_get_description(result, &description);
	LTTNG_ASSERT(result_status == LTTNG_ERROR_QUERY_RESULT_STATUS_OK);

	/* Open error query result element. */
	ret = mi_lttng_writer_open_element(writer, mi_lttng_element_error_query_result);
	if (ret) {
		goto mi_error;
	}

	/* Name. */
	ret = mi_lttng_writer_write_element_string(
		writer, mi_lttng_element_error_query_result_name, name);
	if (ret) {
		goto mi_error;
	}

	/* Description. */
	ret = mi_lttng_writer_write_element_string(
		writer, mi_lttng_element_error_query_result_description, description);
	if (ret) {
		goto mi_error;
	}

	/* Serialize the result according to its sub type. */
	switch (type) {
	case LTTNG_ERROR_QUERY_RESULT_TYPE_COUNTER:
		ret_code = lttng_error_query_result_counter_mi_serialize(result, writer);
		break;
	default:
		abort();
	}

	if (ret_code != LTTNG_OK) {
		goto end;
	}

	/* Close error query result element. */
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

enum lttng_error_code
lttng_error_query_results_mi_serialize(const struct lttng_error_query_results *results,
				       struct mi_writer *writer)
{
	int ret;
	enum lttng_error_code ret_code;
	unsigned int i, count;
	enum lttng_error_query_results_status results_status;

	LTTNG_ASSERT(results);
	LTTNG_ASSERT(writer);

	/* Open error query results element. */
	ret = mi_lttng_writer_open_element(writer, mi_lttng_element_error_query_results);
	if (ret) {
		goto mi_error;
	}

	results_status = lttng_error_query_results_get_count(results, &count);
	LTTNG_ASSERT(results_status == LTTNG_ERROR_QUERY_RESULTS_STATUS_OK);

	for (i = 0; i < count; i++) {
		const struct lttng_error_query_result *result;

		results_status = lttng_error_query_results_get_result(results, &result, i);
		LTTNG_ASSERT(results_status == LTTNG_ERROR_QUERY_RESULTS_STATUS_OK);

		/* A single error query result. */
		ret_code = lttng_error_query_result_mi_serialize(result, writer);
		if (ret_code != LTTNG_OK) {
			goto end;
		}
	}

	/* Close error query results. */
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
