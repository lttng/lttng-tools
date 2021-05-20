/*
 * error-query.c
 *
 * Copyright (C) 2021 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.1-only
 *
 */

#include <common/dynamic-array.h>
#include <common/error.h>
#include <common/macros.h>
#include <common/sessiond-comm/sessiond-comm.h>
#include <lttng/action/action-internal.h>
#include <lttng/action/list-internal.h>
#include <lttng/action/path-internal.h>
#include <lttng/error-query-internal.h>
#include <lttng/error-query.h>
#include <lttng/trigger/trigger-internal.h>
#include <stddef.h>

struct lttng_error_query {
	enum lttng_error_query_target_type target_type;
};

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

struct lttng_error_query_action_comm {
	LTTNG_OPTIONAL_COMM(uint32_t) action_index;
	/* Trigger payload. */
	char payload[];
};

struct lttng_error_query_action {
	struct lttng_error_query parent;
	/* Mutable only because of the reference count. */
	struct lttng_trigger *trigger;
	/*
	 * Index of the target action. Since action lists can't be nested,
	 * the targetted action is the top-level list if the action_index is
	 * unset. Otherwise, the index refers to the index within the top-level
	 * list.
	 */
	LTTNG_OPTIONAL(unsigned int) action_index;
};

struct lttng_error_query_result {
	enum lttng_error_query_result_type type;
	char *name;
	char *description;
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

struct lttng_error_query_results {
	struct lttng_dynamic_pointer_array results;
};


struct lttng_error_query *lttng_error_query_trigger_create(
		const struct lttng_trigger *trigger)
{
	struct lttng_error_query_trigger *query = NULL;
	struct lttng_trigger *trigger_copy = NULL;

	if (!trigger) {
		goto end;
	}

	trigger_copy = lttng_trigger_copy(trigger);
	if (!trigger_copy) {
		goto end;
	}

	query = zmalloc(sizeof(*query));
	if (!query) {
		PERROR("Failed to allocate trigger error query");
		goto error;
	}

	query->parent.target_type = LTTNG_ERROR_QUERY_TARGET_TYPE_TRIGGER;
	query->trigger = trigger_copy;
	trigger_copy = NULL;

error:
	lttng_trigger_put(trigger_copy);
end:
	return query ? &query->parent : NULL;
}

extern struct lttng_error_query *lttng_error_query_action_create(
		const struct lttng_trigger *trigger,
		const struct lttng_action *action)
{
	struct lttng_error_query_action *query = NULL;
	typeof(query->action_index) action_index = {};
	struct lttng_trigger *trigger_copy = NULL;

	if (!trigger || !action) {
		goto end;
	}

	trigger_copy = lttng_trigger_copy(trigger);
	if (!trigger_copy) {
		goto end;
	}

	/*
	 * If an action is not the top-level action of the trigger, our only
	 * hope of finding its position is if the top-level action is an
	 * action list.
	 *
	 * Note that action comparisons are performed by pointer since multiple
	 * otherwise identical actions can be found in an action list (two
	 * notify actions, for example).
	 */
	if (action != trigger->action &&
			lttng_action_get_type(trigger->action) ==
					LTTNG_ACTION_TYPE_LIST) {
		unsigned int i, action_list_count;
		enum lttng_action_status action_status;

		action_status = lttng_action_list_get_count(
				trigger->action, &action_list_count);
		if (action_status != LTTNG_ACTION_STATUS_OK) {
			goto error;
		}

		for (i = 0; i < action_list_count; i++) {
			const struct lttng_action *candidate_action =
					lttng_action_list_get_at_index(
							trigger->action, i);

			assert(candidate_action);
			if (candidate_action == action) {
				LTTNG_OPTIONAL_SET(&action_index, i);
				break;
			}
		}

		if (!action_index.is_set) {
			/* Not found; invalid action. */
			goto error;
		}
	} else {
		/*
		 * Trigger action is not a list and not equal to the target
		 * action; invalid action provided.
		 */
		goto error;
	}

	query = zmalloc(sizeof(*query));
	if (!query) {
		PERROR("Failed to allocate action error query");
		goto error;
	}

	query->parent.target_type = LTTNG_ERROR_QUERY_TARGET_TYPE_ACTION;
	query->trigger = trigger_copy;
	trigger_copy = NULL;
	query->action_index = action_index;
error:
	lttng_trigger_put(trigger_copy);
end:
	return query ? &query->parent : NULL;
}

void lttng_error_query_destroy(struct lttng_error_query *query)
{
	struct lttng_error_query_trigger *trigger_query;

	if (!query) {
		return;
	}

	trigger_query = container_of(query, typeof(*trigger_query), parent);
	lttng_trigger_put(trigger_query->trigger);
	free(trigger_query);
}

static
int lttng_error_query_result_counter_serialize(
		const struct lttng_error_query_result *result,
		struct lttng_payload *payload)
{
	const struct lttng_error_query_result_counter *counter_result;

	assert(result->type == LTTNG_ERROR_QUERY_RESULT_TYPE_COUNTER);
	counter_result = container_of(result, typeof(*counter_result), parent);

	return lttng_dynamic_buffer_append(&payload->buffer,
			&(struct lttng_error_query_result_counter_comm) {
					.value = counter_result->value
			},
			sizeof(struct lttng_error_query_result_counter_comm));
}

LTTNG_HIDDEN
int lttng_error_query_result_serialize(
		const struct lttng_error_query_result *result,
		struct lttng_payload *payload)
{
	int ret;
	struct lttng_error_query_result_comm header = {
		.type = (uint8_t) result->type,
		.name_len = (typeof(header.name_len)) strlen(result->name) + 1,
		.description_len = (typeof(header.name_len)) strlen(result->description) + 1,
	};

	/* Header. */
	ret = lttng_dynamic_buffer_append(
			&payload->buffer, &header, sizeof(header));
	if (ret) {
		ERR("Failed to append error query result communication header to payload");
		goto end;
	}

	/* Name. */
	ret = lttng_dynamic_buffer_append(
			&payload->buffer, result->name, header.name_len);
	if (ret) {
		ERR("Failed to append error query result name to payload");
		goto end;
	}

	/* Description. */
	ret = lttng_dynamic_buffer_append(&payload->buffer, result->description,
			header.description_len);
	if (ret) {
		ERR("Failed to append error query result description to payload");
		goto end;
	}

	/* Type-specific payload. */
	switch (result->type) {
	case LTTNG_ERROR_QUERY_RESULT_TYPE_COUNTER:
		ret = lttng_error_query_result_counter_serialize(
				result, payload);
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

static
int lttng_error_query_result_init(
		struct lttng_error_query_result *result,
		enum lttng_error_query_result_type result_type,
		const char *name,
		const char *description)
{
	int ret;

	assert(name);
	assert(description);

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

LTTNG_HIDDEN
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

LTTNG_HIDDEN
struct lttng_error_query_result *
lttng_error_query_result_counter_create(
		const char *name, const char *description, uint64_t value)
{
	int init_ret;
	struct lttng_error_query_result_counter *counter;

	counter = zmalloc(sizeof(*counter));
	if (!counter) {
		PERROR("Failed to allocate error query counter result");
		goto end;
	}

	init_ret = lttng_error_query_result_init(&counter->parent,
			LTTNG_ERROR_QUERY_RESULT_TYPE_COUNTER, name,
			description);
	if (init_ret) {
		goto error;
	}

	counter->value = value;
	goto end;
error:
	lttng_error_query_result_destroy(&counter->parent);
end:
	return counter ? &counter->parent : NULL;
}

static
void destroy_result(void *ptr)
{
	struct lttng_error_query_result *result = (typeof(result)) ptr;

	lttng_error_query_result_destroy(result);
}

LTTNG_HIDDEN
struct lttng_error_query_results *lttng_error_query_results_create(void)
{
	struct lttng_error_query_results *set = zmalloc(sizeof(*set));

	if (!set) {
		PERROR("Failed to allocate an error query result set");
		goto end;
	}

	lttng_dynamic_pointer_array_init(&set->results, destroy_result);
end:
	return set;
}

LTTNG_HIDDEN
int lttng_error_query_results_add_result(
		struct lttng_error_query_results *results,
		struct lttng_error_query_result *result)
{
	return lttng_dynamic_pointer_array_add_pointer(
			&results->results, result);
}

LTTNG_HIDDEN
ssize_t lttng_error_query_result_create_from_payload(
		struct lttng_payload_view *view,
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
				lttng_payload_view_from_view(view, used_size,
						header->name_len);

		if (!lttng_payload_view_is_valid(&name_view) ||
				!lttng_buffer_view_contains_string(
						&name_view.buffer,
						name_view.buffer.data,
						header->name_len)) {
			used_size = -1;
			goto end;
		}

		name = name_view.buffer.data;
		used_size += header->name_len;
	}

	{
		struct lttng_payload_view description_view =
				lttng_payload_view_from_view(view, used_size,
						header->description_len);

		if (!lttng_payload_view_is_valid(&description_view) ||
				!lttng_buffer_view_contains_string(
						&description_view.buffer,
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
				lttng_payload_view_from_view(view, used_size,
						sizeof(*counter));

		if (!lttng_payload_view_is_valid(&counter_payload_view)) {
			used_size = -1;
			goto end;
		}

		counter = (typeof(counter)) counter_payload_view.buffer.data;
		*result = lttng_error_query_result_counter_create(
				name, description, counter->value);
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

LTTNG_HIDDEN
int lttng_error_query_results_serialize(
		const struct lttng_error_query_results *results,
		struct lttng_payload *payload)
{
	int ret;
	size_t result_index;
	const size_t result_count = lttng_dynamic_pointer_array_get_count(
			&results->results);
	const struct lttng_error_query_results_comm header = {
		.count = (typeof(header.count)) result_count,
	};

	/* Header. */
	ret = lttng_dynamic_buffer_append(&payload->buffer, &header, sizeof(header));
	if (ret) {
		ERR("Failed to append error query result set header to payload");
		goto end;
	}

	/* Results. */
	for (result_index = 0; result_index < result_count; result_index++) {
		const struct lttng_error_query_result *result = (typeof(result))
				lttng_dynamic_pointer_array_get_pointer(
						&results->results,
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

LTTNG_HIDDEN
ssize_t lttng_error_query_results_create_from_payload(
		struct lttng_payload_view *view,
		struct lttng_error_query_results **_results)
{
	size_t result_index;
	ssize_t total_used_size = 0;
	struct lttng_error_query_results_comm *header;
	struct lttng_payload_view header_view =
			lttng_payload_view_from_view(view, 0, sizeof(*header));
	struct lttng_error_query_results *results = NULL;

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
				lttng_payload_view_from_view(
						view, total_used_size, -1);

		if (!lttng_payload_view_is_valid(&result_view)) {
			total_used_size = -1;
			goto end;
		}

		used_size = lttng_error_query_result_create_from_payload(
				&result_view, &result);
		if (used_size < 0) {
			total_used_size = -1;
			goto end;
		}

		total_used_size += used_size;

		if (lttng_dynamic_pointer_array_add_pointer(
				    &results->results, result)) {
			lttng_error_query_result_destroy(result);
			total_used_size = -1;
			goto end;
		}
	}

	*_results = results;
	results = NULL;
end:
	lttng_error_query_results_destroy(results);
	return total_used_size;
}

static
int lttng_error_query_trigger_serialize(const struct lttng_error_query *query,
		struct lttng_payload *payload)
{
	int ret;
	const struct lttng_error_query_trigger *query_trigger =
			container_of(query, typeof(*query_trigger), parent);

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

static
int lttng_error_query_action_serialize(const struct lttng_error_query *query,
		struct lttng_payload *payload)
{
	int ret;
	const struct lttng_error_query_action *query_action =
			container_of(query, typeof(*query_action), parent);
	struct lttng_error_query_action_comm header = {
		.action_index.is_set = query_action->action_index.is_set,
		.action_index.value = query_action->action_index.value,
	};

	if (!lttng_trigger_validate(query_action->trigger)) {
		ret = -1;
		goto end;
	}

	ret = lttng_dynamic_buffer_append(
			&payload->buffer, &header, sizeof(header));
	if (ret) {
		goto end;
	}

	ret = lttng_trigger_serialize(query_action->trigger, payload);
	if (ret) {
		goto end;
	}
end:
	return ret;
}

LTTNG_HIDDEN
enum lttng_error_query_target_type lttng_error_query_get_target_type(
		const struct lttng_error_query *query)
{
	return query->target_type;
}

LTTNG_HIDDEN
const struct lttng_trigger *lttng_error_query_trigger_borrow_target(
		const struct lttng_error_query *query)
{
	const struct lttng_error_query_trigger *query_trigger =
			container_of(query, typeof(*query_trigger), parent);

	return query_trigger->trigger;
}

LTTNG_HIDDEN
const struct lttng_trigger *lttng_error_query_action_borrow_trigger_target(
		const struct lttng_error_query *query)
{
	const struct lttng_error_query_action *query_action =
			container_of(query, typeof(*query_action), parent);

	return query_action->trigger;
}

LTTNG_HIDDEN
struct lttng_action *lttng_error_query_action_borrow_action_target(
	const struct lttng_error_query *query,
	struct lttng_trigger *trigger)
{
	struct lttng_action *target_action = NULL;
	const struct lttng_error_query_action *query_action =
			container_of(query, typeof(*query_action), parent);
	struct lttng_action *trigger_action =
			lttng_trigger_get_action(trigger);

	if (!query_action->action_index.is_set) {
		target_action = trigger_action;
	} else {
		if (lttng_action_get_type(trigger_action) !=
				LTTNG_ACTION_TYPE_LIST) {
			ERR("Invalid action error query target index: trigger action is not a list");
			goto end;
		}

		target_action = lttng_action_list_borrow_mutable_at_index(
				trigger_action,
				LTTNG_OPTIONAL_GET(query_action->action_index));
	}

end:
	return target_action;
}

LTTNG_HIDDEN
int lttng_error_query_serialize(const struct lttng_error_query *query,
		struct lttng_payload *payload)
{
	int ret;
	struct lttng_error_query_comm header = {
		.target_type = (typeof(header.target_type)) query->target_type,
	};

	ret = lttng_dynamic_buffer_append(
			&payload->buffer, &header, sizeof(header));
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

LTTNG_HIDDEN
ssize_t lttng_error_query_create_from_payload(struct lttng_payload_view *view,
		struct lttng_error_query **query)
{
	ssize_t used_size = 0;
	struct lttng_error_query_comm *header;
	struct lttng_trigger *trigger = NULL;
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
				lttng_payload_view_from_view(
						view, used_size, -1);

		if (!lttng_payload_view_is_valid(&trigger_view)) {
			used_size = -1;
			goto end;
		}

		trigger_used_size = lttng_trigger_create_from_payload(
				&trigger_view, &trigger);
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
	case LTTNG_ERROR_QUERY_TARGET_TYPE_ACTION:
	{
		const struct lttng_action *target_action;
		ssize_t trigger_used_size;
		struct lttng_error_query_action_comm *action_header;

		{
			struct lttng_payload_view action_header_view =
					lttng_payload_view_from_view(view,
							used_size,
							sizeof(*action_header));

			if (!lttng_payload_view_is_valid(&action_header_view)) {
				used_size = -1;
				goto end;
			}

			action_header = (typeof(action_header)) action_header_view.buffer.data;
			used_size += sizeof(*action_header);
		}

		{
			struct lttng_payload_view trigger_view =
					lttng_payload_view_from_view(
							view, used_size, -1);

			if (!lttng_payload_view_is_valid(&trigger_view)) {
				used_size = -1;
				goto end;
			}

			trigger_used_size = lttng_trigger_create_from_payload(
					&trigger_view, &trigger);
			if (trigger_used_size < 0) {
				used_size = -1;
				goto end;
			}

			used_size += trigger_used_size;
		}

		if (!action_header->action_index.is_set) {
			target_action = trigger->action;
		} else {
			if (lttng_action_get_type(trigger->action) !=
					LTTNG_ACTION_TYPE_LIST) {
				used_size = -1;
				goto end;
			}

			target_action = lttng_action_list_get_at_index(
					trigger->action,
					action_header->action_index.value);
		}

		*query = lttng_error_query_action_create(
				trigger, target_action);
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

enum lttng_error_query_results_status lttng_error_query_results_get_count(
		const struct lttng_error_query_results *results,
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
lttng_error_query_results_get_result(
		const struct lttng_error_query_results *results,
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

	*result = (typeof(*result)) lttng_dynamic_pointer_array_get_pointer(
			&results->results, index);
	assert(*result);
	status = LTTNG_ERROR_QUERY_RESULTS_STATUS_OK;
end:
	return status;
}

void lttng_error_query_results_destroy(
		struct lttng_error_query_results *results)
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

enum lttng_error_query_result_status lttng_error_query_result_get_name(
		const struct lttng_error_query_result *result,
		const char **name)
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

enum lttng_error_query_result_status lttng_error_query_result_get_description(
		const struct lttng_error_query_result *result,
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

enum lttng_error_query_result_status lttng_error_query_result_counter_get_value(
		const struct lttng_error_query_result *result,
		uint64_t *value)
{
	enum lttng_error_query_result_status status;
	const struct lttng_error_query_result_counter *counter_result;

	if (!result || !value ||
			result->type != LTTNG_ERROR_QUERY_RESULT_TYPE_COUNTER) {
		status = LTTNG_ERROR_QUERY_RESULT_STATUS_INVALID_PARAMETER;
		goto end;
	}

	counter_result = container_of(result, typeof(*counter_result), parent);

	*value = counter_result->value;
	status = LTTNG_ERROR_QUERY_RESULT_STATUS_OK;
end:
	return status;
}
