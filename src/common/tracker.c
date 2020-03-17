/*
 * Copyright (C) 2019 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <assert.h>
#include <common/defaults.h>
#include <common/error.h>
#include <common/macros.h>
#include <common/sessiond-comm/sessiond-comm.h>
#include <common/uri.h>
#include <lttng/tracker-internal.h>
#include <stdio.h>
#include <time.h>

struct lttng_tracker_id *lttng_tracker_id_create(void)
{
	struct lttng_tracker_id *id;

	id = zmalloc(sizeof(*id));
	if (!id) {
		goto error;
	}

	id->type = LTTNG_ID_UNKNOWN;
	id->string = NULL;
	id->value = -1;
	return id;
error:
	lttng_tracker_id_destroy(id);
	return NULL;
}

enum lttng_tracker_id_status lttng_tracker_id_set_value(
		struct lttng_tracker_id *id, int value)
{
	assert(id);

	if (value < 0) {
		return LTTNG_TRACKER_ID_STATUS_INVALID;
	}

	id->type = LTTNG_ID_VALUE;
	id->value = value;
	return LTTNG_TRACKER_ID_STATUS_OK;
}

enum lttng_tracker_id_status lttng_tracker_id_set_string(
		struct lttng_tracker_id *id, const char *value)
{
	assert(id);
	assert(value);

	id->type = LTTNG_ID_STRING;
	id->string = strdup(value);
	if (id->string == NULL) {
		/* No memory left */
		goto error;
	}

	return LTTNG_TRACKER_ID_STATUS_OK;
error:
	return LTTNG_TRACKER_ID_STATUS_INVALID;
}

enum lttng_tracker_id_status lttng_tracker_id_set_all(
		struct lttng_tracker_id *id)
{
	assert(id);

	id->type = LTTNG_ID_ALL;

	return LTTNG_TRACKER_ID_STATUS_OK;
}

static void lttng_tracker_id_reset(struct lttng_tracker_id *id)
{
	if (id == NULL) {
		return;
	}

	if (id->string != NULL) {
		free(id->string);
		id->string = NULL;
	}

	id->type = LTTNG_ID_UNKNOWN;
	id->value = -1;
}

void lttng_tracker_id_destroy(struct lttng_tracker_id *id)
{
	if (id == NULL) {
		return;
	}

	lttng_tracker_id_reset(id);

	free(id);
}

enum lttng_tracker_id_type lttng_tracker_id_get_type(
		const struct lttng_tracker_id *id)
{
	assert(id);
	return id->type;
}

enum lttng_tracker_id_status lttng_tracker_id_get_value(
		const struct lttng_tracker_id *id, int *value)
{
	assert(id);
	if (id->type == LTTNG_ID_UNKNOWN) {
		return LTTNG_TRACKER_ID_STATUS_UNSET;
	}

	if (id->type != LTTNG_ID_VALUE) {
		return LTTNG_TRACKER_ID_STATUS_INVALID;
	}

	*value = id->value;
	return LTTNG_TRACKER_ID_STATUS_OK;
}

bool lttng_tracker_id_is_equal(const struct lttng_tracker_id *left,
		const struct lttng_tracker_id *right)
{
	if (left->type != right->type) {
		return 0;
	}

	switch (left->type) {
	case LTTNG_ID_ALL:
		return 1;
	case LTTNG_ID_VALUE:
		if (left->value != right->value) {
			return 0;
		}
		break;
	case LTTNG_ID_STRING:
		if (strcmp(left->string, right->string) != 0) {
			return 0;
		}
		break;
	default:
		/*
		 * Normally this should return true, but comparing unset tracker
		 * id is "invalid".
		 */
		return 0;
	}
	return 1;
}

int lttng_tracker_id_copy(struct lttng_tracker_id *dest,
		const struct lttng_tracker_id *orig)
{
	int ret = 0;
	enum lttng_tracker_id_status status;

	assert(dest);
	assert(orig);

	switch (orig->type) {
	case LTTNG_ID_ALL:
		status = lttng_tracker_id_set_all(dest);
		break;
	case LTTNG_ID_VALUE:
		status = lttng_tracker_id_set_value(dest, orig->value);
		break;
	case LTTNG_ID_STRING:
		status = lttng_tracker_id_set_string(dest, orig->string);
		break;
	default:
		status = LTTNG_TRACKER_ID_STATUS_OK;
		break;
	}

	if (status != LTTNG_TRACKER_ID_STATUS_OK) {
		ret = -1;
		goto error;
	}
error:
	return ret;
}

struct lttng_tracker_id *lttng_tracker_id_duplicate(
		const struct lttng_tracker_id *orig)
{
	int ret;
	struct lttng_tracker_id *copy = NULL;

	copy = lttng_tracker_id_create();
	if (copy == NULL) {
		goto error;
	}

	ret = lttng_tracker_id_copy(copy, orig);
	if (ret) {
		goto error;
	}

	return copy;
error:
	lttng_tracker_id_destroy(copy);
	return NULL;
}

enum lttng_tracker_id_status lttng_tracker_id_get_string(
		const struct lttng_tracker_id *id, const char **value)
{
	assert(id);
	if (id->type == LTTNG_ID_UNKNOWN) {
		*value = NULL;
		return LTTNG_TRACKER_ID_STATUS_UNSET;
	}

	if (id->type != LTTNG_ID_STRING) {
		*value = NULL;
		return LTTNG_TRACKER_ID_STATUS_INVALID;
	}

	*value = id->string;
	return LTTNG_TRACKER_ID_STATUS_OK;
}

struct lttng_tracker_ids *lttng_tracker_ids_create(unsigned int count)
{
	struct lttng_tracker_ids *ids = NULL;

	ids = zmalloc(sizeof(*ids));
	if (!ids) {
		goto error;
	}

	ids->id_array = zmalloc(sizeof(struct lttng_tracker_id) * count);
	if (!ids->id_array) {
		goto error;
	}

	ids->count = count;

	return ids;
error:
	free(ids);
	return NULL;
}

LTTNG_HIDDEN
struct lttng_tracker_id *lttng_tracker_ids_get_pointer_of_index(
		const struct lttng_tracker_ids *ids, unsigned int index)
{
	assert(ids);
	if (index >= ids->count) {
		return NULL;
	}

	return &ids->id_array[index];
}

const struct lttng_tracker_id *lttng_tracker_ids_get_at_index(
		const struct lttng_tracker_ids *ids, unsigned int index)
{
	assert(ids);
	return lttng_tracker_ids_get_pointer_of_index(ids, index);
}

enum lttng_tracker_id_status lttng_tracker_ids_get_count(const struct lttng_tracker_ids *ids, unsigned int *count)
{

	enum lttng_tracker_id_status status = LTTNG_TRACKER_ID_STATUS_OK;

	if (!ids || !count) {
		status = LTTNG_TRACKER_ID_STATUS_INVALID;
		goto end;
	}

	*count = ids->count;
end:
	return status;
}

void lttng_tracker_ids_destroy(struct lttng_tracker_ids *ids)
{
	int i;

	if (!ids) {
		return;
	}

	for (i = 0; i < ids->count; i++) {
		lttng_tracker_id_reset(&ids->id_array[i]);
	}
	free(ids->id_array);
	free(ids);
}

int lttng_tracker_ids_serialize(const struct lttng_tracker_ids *ids,
		struct lttng_dynamic_buffer *buffer)
{
	int ret = 0;
	int value;
	const char *string = NULL;
	unsigned int count;
	enum lttng_tracker_id_status status;
	const struct lttng_tracker_id *id;
	unsigned int i;

	status = lttng_tracker_ids_get_count(ids, &count);
	if (status != LTTNG_TRACKER_ID_STATUS_OK) {
		ret = LTTNG_ERR_INVALID;
		goto error;
	}

	for (i = 0; i < count; i++) {
		struct lttcomm_tracker_id_header id_hdr;
		size_t var_data_len = 0;

		id = lttng_tracker_ids_get_at_index(ids, i);
		if (!id) {
			ret = -LTTNG_ERR_INVALID;
			goto error;
		}

		memset(&id_hdr, 0, sizeof(id_hdr));
		id_hdr.type = lttng_tracker_id_get_type(id);
		switch (id_hdr.type) {
		case LTTNG_ID_ALL:
			break;
		case LTTNG_ID_VALUE:
			status = lttng_tracker_id_get_value(id, &value);
			id_hdr.u.value = value;
			if (status != LTTNG_TRACKER_ID_STATUS_OK) {
				ret = -LTTNG_ERR_INVALID;
				goto error;
			}
			break;
		case LTTNG_ID_STRING:
			status = lttng_tracker_id_get_string(
					id, &string);
			if (status != LTTNG_TRACKER_ID_STATUS_OK) {
				ret = -LTTNG_ERR_INVALID;
				goto error;
			}

			id_hdr.u.var_data_len = var_data_len =
					strlen(string) + 1;
			break;
		default:
			ret = -LTTNG_ERR_INVALID;
			goto error;
		}
		ret = lttng_dynamic_buffer_append(
				buffer, &id_hdr, sizeof(id_hdr));
		if (ret) {
			ret = -LTTNG_ERR_NOMEM;
			goto error;
		}
		ret = lttng_dynamic_buffer_append(
				buffer, string, var_data_len);
		if (ret) {
			ret = -LTTNG_ERR_NOMEM;
			goto error;
		}
	}
error:
	return ret;
}
