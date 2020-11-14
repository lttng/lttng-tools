/*
 * Copyright (C) 2019 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 * Copyright (C) 2020 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <lttng/domain.h>
#include <lttng/lttng-error.h>
#include <lttng/tracker.h>

#include <common/dynamic-array.h>
#include <common/error.h>
#include <common/hashtable/hashtable.h>
#include <common/hashtable/utils.h>
#include <common/tracker.h>

#include <stdbool.h>

struct process_attr_tracker_values_comm_header {
	uint32_t count;
};

struct process_attr_tracker_value_comm {
	/* enum lttng_process_attr_value_type */
	int32_t type;
	union {
		struct process_attr_integral_value_comm integral;
		/* Includes the '\0' terminator. */
		uint32_t name_len;
	} value;
};

#define GET_INTEGRAL_COMM_VALUE(value_ptr, as_type)              \
	((as_type)(is_signed(as_type) ? (value_ptr)->u._signed : \
					(value_ptr)->u._unsigned))

#define SET_INTEGRAL_COMM_VALUE(comm_value, value)                         \
	if (is_signed(typeof(value))) {                                    \
		(comm_value)->u._signed =                                  \
				(typeof((comm_value)->u._signed)) value;   \
	} else {                                                           \
		(comm_value)->u._unsigned =                                \
				(typeof((comm_value)->u._unsigned)) value; \
	}

static inline bool is_virtual_process_attr(enum lttng_process_attr process_attr)
{
	return process_attr == LTTNG_PROCESS_ATTR_VIRTUAL_PROCESS_ID ||
	       process_attr == LTTNG_PROCESS_ATTR_VIRTUAL_USER_ID ||
	       process_attr == LTTNG_PROCESS_ATTR_VIRTUAL_GROUP_ID;
}

static inline bool is_value_type_name(
		enum lttng_process_attr_value_type value_type)
{
	return value_type == LTTNG_PROCESS_ATTR_VALUE_TYPE_USER_NAME ||
	       value_type == LTTNG_PROCESS_ATTR_VALUE_TYPE_GROUP_NAME;
}

LTTNG_HIDDEN
enum lttng_error_code process_attr_value_from_comm(
		enum lttng_domain_type domain,
		enum lttng_process_attr process_attr,
		enum lttng_process_attr_value_type value_type,
		const struct process_attr_integral_value_comm *integral_value,
		const struct lttng_buffer_view *value_view,
		struct process_attr_value **_value)
{
	char *name = NULL;
	enum lttng_error_code ret = LTTNG_OK;
	struct process_attr_value *value = zmalloc(sizeof(*value));

	if (!value) {
		ret = LTTNG_ERR_NOMEM;
		goto error;
	}

	if (value_view && value_view->size > 0) {
		if (value_view->data[value_view->size - 1] != '\0') {
			ret = LTTNG_ERR_INVALID;
			goto error;
		}
		name = strdup(value_view->data);
		if (!name) {
			ret = LTTNG_ERR_NOMEM;
			goto error;
		}
	}

	if (domain != LTTNG_DOMAIN_UST && domain != LTTNG_DOMAIN_KERNEL) {
		ERR("Only the user space and kernel space domains may be specified to configure process attribute trackers");
		ret = LTTNG_ERR_UNSUPPORTED_DOMAIN;
		goto error;
	}

	if (!is_virtual_process_attr(process_attr) &&
			domain != LTTNG_DOMAIN_KERNEL) {
		ERR("Non-virtual process attributes can only be used in the kernel domain");
		ret = LTTNG_ERR_UNSUPPORTED_DOMAIN;
		goto error;
	}

	/* Only expect a payload for name value types. */
	if (is_value_type_name(value_type) &&
			(!value_view || value_view->size == 0)) {
		ret = LTTNG_ERR_INVALID_PROTOCOL;
		goto error;
	} else if (!is_value_type_name(value_type) && value_view &&
			value_view->size != 0) {
		ret = LTTNG_ERR_INVALID_PROTOCOL;
		goto error;
	}

	value->type = value_type;
	switch (process_attr) {
	case LTTNG_PROCESS_ATTR_PROCESS_ID:
	case LTTNG_PROCESS_ATTR_VIRTUAL_PROCESS_ID:
		if (value_type != LTTNG_PROCESS_ATTR_VALUE_TYPE_PID) {
			ERR("Invalid value type used for process ID process attribute");
			ret = LTTNG_ERR_INVALID;
			goto error;
		}
		value->value.pid =
				GET_INTEGRAL_COMM_VALUE(integral_value, pid_t);
		break;
	case LTTNG_PROCESS_ATTR_USER_ID:
	case LTTNG_PROCESS_ATTR_VIRTUAL_USER_ID:
		switch (value_type) {
		case LTTNG_PROCESS_ATTR_VALUE_TYPE_UID:
			value->value.uid = GET_INTEGRAL_COMM_VALUE(
					integral_value, uid_t);
			break;
		case LTTNG_PROCESS_ATTR_VALUE_TYPE_USER_NAME:
			if (!name) {
				ret = LTTNG_ERR_INVALID;
				goto error;
			}

			value->value.user_name = name;
			name = NULL;
			break;
		default:
			ERR("Invalid value type used for user ID process attribute");
			ret = LTTNG_ERR_INVALID;
			goto error;
		}
		break;
	case LTTNG_PROCESS_ATTR_GROUP_ID:
	case LTTNG_PROCESS_ATTR_VIRTUAL_GROUP_ID:
		switch (value_type) {
		case LTTNG_PROCESS_ATTR_VALUE_TYPE_GID:
			value->value.gid = GET_INTEGRAL_COMM_VALUE(
					integral_value, gid_t);
			break;
		case LTTNG_PROCESS_ATTR_VALUE_TYPE_GROUP_NAME:
			if (!name) {
				ret = LTTNG_ERR_INVALID;
				goto error;
			}

			value->value.group_name = name;
			name = NULL;
			break;
		default:
			ERR("Invalid value type used for group ID process attribute");
			ret = LTTNG_ERR_INVALID;
			goto error;
		}
		break;
	default:
		ret = LTTNG_ERR_INVALID_PROTOCOL;
		goto error;
	}

	*_value = value;
	value = NULL;
	free(name);
	return LTTNG_OK;
error:
	free(name);
	process_attr_value_destroy(value);
	return ret;
}

LTTNG_HIDDEN
const char *lttng_process_attr_to_string(enum lttng_process_attr process_attr)
{
	switch (process_attr) {
	case LTTNG_PROCESS_ATTR_PROCESS_ID:
		return "process ID";
	case LTTNG_PROCESS_ATTR_VIRTUAL_PROCESS_ID:
		return "virtual process ID";
	case LTTNG_PROCESS_ATTR_USER_ID:
		return "user ID";
	case LTTNG_PROCESS_ATTR_VIRTUAL_USER_ID:
		return "virtual user ID";
	case LTTNG_PROCESS_ATTR_GROUP_ID:
		return "group ID";
	case LTTNG_PROCESS_ATTR_VIRTUAL_GROUP_ID:
		return "virtual group ID";
	default:
		return "unknown process attribute";
	}
}

static void process_attr_tracker_value_destructor(void *ptr)
{
	struct process_attr_value *value = (typeof(value)) ptr;

	process_attr_value_destroy(value);
}

LTTNG_HIDDEN
struct lttng_process_attr_values *lttng_process_attr_values_create(void)
{
	struct lttng_process_attr_values *values = zmalloc(sizeof(*values));

	if (!values) {
		goto end;
	}

	lttng_dynamic_pointer_array_init(
			&values->array, process_attr_tracker_value_destructor);
end:
	return values;
}

LTTNG_HIDDEN
unsigned int _lttng_process_attr_values_get_count(
		const struct lttng_process_attr_values *values)
{
	return (unsigned int) lttng_dynamic_pointer_array_get_count(
			&values->array);
}

LTTNG_HIDDEN
const struct process_attr_value *lttng_process_attr_tracker_values_get_at_index(
		const struct lttng_process_attr_values *values,
		unsigned int index)
{
	return lttng_dynamic_pointer_array_get_pointer(&values->array, index);
}

static
int process_attr_tracker_value_serialize(const struct process_attr_value *value,
		struct lttng_dynamic_buffer *buffer)
{
	int ret;
	struct process_attr_tracker_value_comm value_comm = {
			.type = (int32_t) value->type,
	};
	const char *name = NULL;

	switch (value->type) {
	case LTTNG_PROCESS_ATTR_VALUE_TYPE_PID:
		SET_INTEGRAL_COMM_VALUE(
				&value_comm.value.integral, value->value.pid);
		break;
	case LTTNG_PROCESS_ATTR_VALUE_TYPE_UID:
		SET_INTEGRAL_COMM_VALUE(
				&value_comm.value.integral, value->value.uid);
		break;
	case LTTNG_PROCESS_ATTR_VALUE_TYPE_GID:
		SET_INTEGRAL_COMM_VALUE(
				&value_comm.value.integral, value->value.gid);
		break;
	case LTTNG_PROCESS_ATTR_VALUE_TYPE_USER_NAME:
		name = value->value.user_name;
		break;
	case LTTNG_PROCESS_ATTR_VALUE_TYPE_GROUP_NAME:
		name = value->value.group_name;
		break;
	default:
		abort();
	}

	if (name) {
		value_comm.value.name_len = strlen(name) + 1;
	}

	ret = lttng_dynamic_buffer_append(
			buffer, &value_comm, sizeof(value_comm));
	if (ret) {
		goto end;
	}

	if (name) {
		ret = lttng_dynamic_buffer_append(
				buffer, name, value_comm.value.name_len);
	}
end:
	return ret;
}

LTTNG_HIDDEN
int lttng_process_attr_values_serialize(
		const struct lttng_process_attr_values *values,
		struct lttng_dynamic_buffer *buffer)
{
	int ret;
	unsigned int count, i;
	struct process_attr_tracker_values_comm_header header = {};

	count = _lttng_process_attr_values_get_count(values);
	header.count = (uint32_t) count;

	ret = lttng_dynamic_buffer_append(buffer, &header, sizeof(header));
	if (ret) {
		goto end;
	}

	for (i = 0; i < count; i++) {
		const struct process_attr_value *value =
				lttng_process_attr_tracker_values_get_at_index(
						values, i);

		ret = process_attr_tracker_value_serialize(value, buffer);
		if (ret) {
			goto end;
		}
	}
end:
	return ret;
}

LTTNG_HIDDEN
ssize_t lttng_process_attr_values_create_from_buffer(
		enum lttng_domain_type domain,
		enum lttng_process_attr process_attr,
		const struct lttng_buffer_view *buffer_view,
		struct lttng_process_attr_values **_values)
{
	ssize_t offset;
	unsigned int i;
	struct lttng_process_attr_values *values;
	struct lttng_buffer_view header_view;
	const struct process_attr_tracker_values_comm_header *header;

	values = lttng_process_attr_values_create();
	if (!values) {
		goto error;
	}

	header_view = lttng_buffer_view_from_view(
			buffer_view, 0, sizeof(*header));
	if (!lttng_buffer_view_is_valid(&header_view)) {
		goto error;
	}

	offset = header_view.size;
	header = (typeof(header)) header_view.data;

	/*
	 * Check that the number of values is not absurdly large with respect to
	 * the received buffer's size.
	 */
	if (buffer_view->size <
			header->count * sizeof(struct process_attr_tracker_value_comm)) {
		goto error;
	}
	for (i = 0; i < (unsigned int) header->count; i++) {
		int ret;
		enum lttng_error_code ret_code;
		const struct process_attr_tracker_value_comm *value_comm;
		struct process_attr_value *value;
		enum lttng_process_attr_value_type type;
		struct lttng_buffer_view value_view;
		struct lttng_buffer_view value_name_view = {};

		value_view = lttng_buffer_view_from_view(
				buffer_view, offset, sizeof(*value_comm));
		if (!lttng_buffer_view_is_valid(&value_view)) {
			goto error;
		}

		offset += value_view.size;
		value_comm = (typeof(value_comm)) value_view.data;
		type = (typeof(type)) value_comm->type;

		if (is_value_type_name(type)) {
			value_name_view = lttng_buffer_view_from_view(
					buffer_view, offset,
					value_comm->value.name_len);
			if (!lttng_buffer_view_is_valid(&value_name_view)) {
				goto error;
			}

			offset += value_name_view.size;
		}

		ret_code = process_attr_value_from_comm(domain, process_attr,
				type, &value_comm->value.integral,
				&value_name_view, &value);
		if (ret_code != LTTNG_OK) {
			goto error;
		}

		ret = lttng_dynamic_pointer_array_add_pointer(
				&values->array, value);
		if (ret) {
			process_attr_value_destroy(value);
			goto error;
		}
	}

	*_values = values;
	return offset;
error:
	lttng_process_attr_values_destroy(values);
	return -1;
}

LTTNG_HIDDEN
void lttng_process_attr_values_destroy(struct lttng_process_attr_values *values)
{
	if (!values) {
		return;
	}
	lttng_dynamic_pointer_array_reset(&values->array);
	free(values);
}

LTTNG_HIDDEN
struct process_attr_value *process_attr_value_copy(
		const struct process_attr_value *value)
{
	struct process_attr_value *new_value = NULL;

	if (!value) {
		goto end;
	}

	new_value = zmalloc(sizeof(*new_value));
	if (!new_value) {
		goto end;
	}
	if (is_value_type_name(value->type)) {
		const char *src =
				value->type == LTTNG_PROCESS_ATTR_VALUE_TYPE_USER_NAME ?
						value->value.user_name :
						value->value.group_name;
		char **dst = value->type == LTTNG_PROCESS_ATTR_VALUE_TYPE_USER_NAME ?
					     &new_value->value.user_name :
					     &new_value->value.group_name;

		new_value->type = value->type;
		*dst = strdup(src);
		if (!*dst) {
			goto error;
		}
	} else {
		*new_value = *value;
	}
end:
	return new_value;
error:
	free(new_value);
	return NULL;
}

LTTNG_HIDDEN
unsigned long process_attr_value_hash(const struct process_attr_value *a)
{
	unsigned long hash = hash_key_ulong((void *) a->type, lttng_ht_seed);

	switch (a->type) {
	case LTTNG_PROCESS_ATTR_VALUE_TYPE_PID:
		hash ^= hash_key_ulong((void *) (unsigned long) a->value.pid,
				lttng_ht_seed);
		break;
	case LTTNG_PROCESS_ATTR_VALUE_TYPE_UID:
		hash ^= hash_key_ulong((void *) (unsigned long) a->value.uid,
				lttng_ht_seed);
		break;
	case LTTNG_PROCESS_ATTR_VALUE_TYPE_GID:
		hash ^= hash_key_ulong((void *) (unsigned long) a->value.gid,
				lttng_ht_seed);
		break;
	case LTTNG_PROCESS_ATTR_VALUE_TYPE_USER_NAME:
		hash ^= hash_key_str(a->value.user_name, lttng_ht_seed);
		break;
	case LTTNG_PROCESS_ATTR_VALUE_TYPE_GROUP_NAME:
		hash ^= hash_key_str(a->value.group_name, lttng_ht_seed);
		break;
	default:
		abort();
	}

	return hash;
}

LTTNG_HIDDEN
bool process_attr_tracker_value_equal(const struct process_attr_value *a,
		const struct process_attr_value *b)
{
	if (a->type != b->type) {
		return false;
	}
	switch (a->type) {
	case LTTNG_PROCESS_ATTR_VALUE_TYPE_PID:
		return a->value.pid == b->value.pid;
	case LTTNG_PROCESS_ATTR_VALUE_TYPE_UID:
		return a->value.uid == b->value.uid;
	case LTTNG_PROCESS_ATTR_VALUE_TYPE_GID:
		return a->value.gid == b->value.gid;
	case LTTNG_PROCESS_ATTR_VALUE_TYPE_USER_NAME:
		return !strcmp(a->value.user_name, b->value.user_name);
	case LTTNG_PROCESS_ATTR_VALUE_TYPE_GROUP_NAME:
		return !strcmp(a->value.group_name, b->value.group_name);
	default:
		abort();
	}
}

LTTNG_HIDDEN
void process_attr_value_destroy(struct process_attr_value *value)
{
	if (!value) {
		return;
	}
	if (is_value_type_name(value->type)) {
		free(value->type == LTTNG_PROCESS_ATTR_VALUE_TYPE_USER_NAME ?
						value->value.user_name :
						value->value.group_name);
	}
	free(value);
}
