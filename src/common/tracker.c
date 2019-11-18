/*
 * Copyright (C) 2019 - Jonathan Rajotte-Julien <jonathan.rajotte-julien@efficios.com>
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

void lttng_tracker_id_destroy(struct lttng_tracker_id *id)
{
	if (id == NULL) {
		return;
	}

	if (id->string != NULL) {
		free(id->string);
	}

	free(id);
}

void lttng_tracker_ids_destroy(struct lttng_tracker_id **ids, size_t nr_ids)
{
	if (ids == NULL) {
		return;
	}

	for (int i = 0; i < nr_ids; i++) {
		lttng_tracker_id_destroy(ids[i]);
	}
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

struct lttng_tracker_id *lttng_tracker_id_copy(
		const struct lttng_tracker_id *orig)
{
	struct lttng_tracker_id *copy = NULL;
	enum lttng_tracker_id_status status;

	copy = lttng_tracker_id_create();
	if (copy == NULL) {
		goto error;
	}

	switch (orig->type) {
	case LTTNG_ID_ALL:
		status = lttng_tracker_id_set_all(copy);
		break;
	case LTTNG_ID_VALUE:
		status = lttng_tracker_id_set_value(copy, orig->value);
		if (status != LTTNG_TRACKER_ID_STATUS_OK) {
			goto error;
		}
		break;
	case LTTNG_ID_STRING:
		status = lttng_tracker_id_set_string(copy, orig->string);
		if (status != LTTNG_TRACKER_ID_STATUS_OK) {
			goto error;
		}
		break;
	default:
		status = LTTNG_TRACKER_ID_STATUS_OK;
		break;
	}

	if (status != LTTNG_TRACKER_ID_STATUS_OK) {
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
