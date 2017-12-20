/*
 * Copyright (C) 2017 - Julien Desfossez <jdesfossez@efficios.com>
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

#define _LGPL_SOURCE
#include <assert.h>
#include <string.h>

#include <lttng/lttng-error.h>
#include <lttng/rotation.h>
#include <lttng/rotate-internal.h>
#include <common/sessiond-comm/sessiond-comm.h>

#include "lttng-ctl-helper.h"

struct lttng_rotation_manual_attr *lttng_rotation_manual_attr_create(void)
{
	return zmalloc(sizeof(struct lttng_rotation_manual_attr));
}

struct lttng_rotation_schedule_attr *lttng_rotation_schedule_attr_create(void)
{
	return zmalloc(sizeof(struct lttng_rotation_schedule_attr));
}

void lttng_rotation_manual_attr_destroy(struct lttng_rotation_manual_attr *attr)
{
	if (attr) {
		free(attr);
		attr = NULL;
	}
}

void lttng_rotation_schedule_attr_destroy(struct lttng_rotation_schedule_attr *attr)
{
	if (attr) {
		free(attr);
		attr = NULL;
	}
}

int lttng_rotation_manual_attr_set_session_name(
		struct lttng_rotation_manual_attr *attr,
		const char *session_name)
{
	int ret = 0;
	size_t len;

	if (!attr || !session_name) {
		ret = -LTTNG_ERR_INVALID;
		goto error;
	}

	len = strlen(session_name);
	if (len >= LTTNG_NAME_MAX) {
		ret = -LTTNG_ERR_INVALID;
		goto error;
	}

	strncpy(attr->session_name, session_name, len);

error:
	return ret;
}

int lttng_rotation_schedule_attr_set_session_name(
		struct lttng_rotation_schedule_attr *attr,
		const char *session_name)
{
	int ret = 0;
	size_t len;

	if (!attr || !session_name) {
		ret = -LTTNG_ERR_INVALID;
		goto error;
	}

	len = strlen(session_name);
	if (len >= LTTNG_NAME_MAX) {
		ret = -LTTNG_ERR_INVALID;
		goto error;
	}

	strncpy(attr->session_name, session_name, len);

error:
	return ret;
}

void lttng_rotation_schedule_attr_set_timer_period(
		struct lttng_rotation_schedule_attr *attr,
		uint64_t timer)
{
	attr->timer_us = timer;
}

enum lttng_rotation_status lttng_rotation_handle_get_status(
		struct lttng_rotation_handle *rotation_handle)
{
	if (!rotation_handle) {
		return LTTNG_ROTATION_STATUS_ERROR;
	}
	return rotation_handle->status;
}

int lttng_rotation_handle_get_output_path(
		struct lttng_rotation_handle *rotation_handle,
		char **path)
{
	int ret;

	*path = zmalloc(PATH_MAX);
	if (!*path) {
		ret = -1;
		goto end;
	}

	if (rotation_handle->status == LTTNG_ROTATION_STATUS_COMPLETED) {
		ret = snprintf(*path, PATH_MAX, "%s", rotation_handle->output_path);
		if (ret < 0 || ret >= PATH_MAX) {
			ret = -1;
			goto end;
		}
		ret = 0;
	} else {
		ret = -1;
	}

end:
	return ret;
}

void lttng_rotation_handle_destroy(
		struct lttng_rotation_handle *rotation_handle)
{
	if (!rotation_handle) {
		return;
	}
	free(rotation_handle);
	rotation_handle = NULL;
}

static
void init_rotation_handle(struct lttng_rotation_handle *rotation_handle,
		struct lttng_rotate_session_return *rotate_return,
		struct lttng_rotation_manual_attr *attr)
{
	(void) snprintf(rotation_handle->session_name, LTTNG_NAME_MAX, "%s",
			attr->session_name);
	rotation_handle->rotate_id = rotate_return->rotate_id;
	rotation_handle->status = rotate_return->status;
}

/*
 * Rotate the output folder of the session.
 *
 * Return 0 on success else a negative LTTng error code.
 */
int lttng_rotate_session(struct lttng_rotation_manual_attr *attr,
		struct lttng_rotation_handle **rotation_handle)
{
	struct lttcomm_session_msg lsm;
	struct lttng_rotate_session_return *rotate_return = NULL;
	int ret;

	if (!attr) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	memset(&lsm, 0, sizeof(lsm));
	lsm.cmd_type = LTTNG_ROTATE_SESSION;
	lttng_ctl_copy_string(lsm.session.name, attr->session_name,
			sizeof(lsm.session.name));

	ret = lttng_ctl_ask_sessiond(&lsm, (void **) &rotate_return);
	if (ret < 0) {
		*rotation_handle = NULL;
		goto end;
	}

	*rotation_handle = zmalloc(sizeof(struct lttng_rotation_handle));
	if (!*rotation_handle) {
		ret = -LTTNG_ERR_NOMEM;
		goto end;
	}

	init_rotation_handle(*rotation_handle, rotate_return, attr);

	ret = 0;

end:
	free(rotate_return);
	return ret;
}

/*
 * Ask the session daemon if the current rotation is complete.
 * If it is, return 0 and populate the output_path with the path of the
 * rotated chunk. Return 1 if the rotation is pending.
 */
int lttng_rotation_is_pending(struct lttng_rotation_handle *rotation_handle)
{
	/* lsm.rotate_pending.rotate_id */
	struct lttcomm_session_msg lsm;
	struct lttng_rotation_manual_attr attr;
	int ret;
	struct lttng_rotation_is_pending_return *pending_return = NULL;

	ret = snprintf(attr.session_name, LTTNG_NAME_MAX, "%s",
			rotation_handle->session_name);
	if (ret < 0 || ret >= LTTNG_NAME_MAX) {
		rotation_handle->status = LTTNG_ROTATION_STATUS_ERROR;
		ret = -1;
		goto end;
	}

	memset(&lsm, 0, sizeof(lsm));
	lsm.cmd_type = LTTNG_ROTATION_IS_PENDING;
	lsm.u.rotate_pending.rotate_id = rotation_handle->rotate_id;
	lttng_ctl_copy_string(lsm.session.name, attr.session_name,
			sizeof(lsm.session.name));

	ret = lttng_ctl_ask_sessiond(&lsm, (void **) &pending_return);
	if (ret < 0) {
		rotation_handle->status = LTTNG_ROTATION_STATUS_ERROR;
		goto end;
	}

	rotation_handle->status = pending_return->status;
	switch(pending_return->status) {
	/* Not pending anymore */
	case LTTNG_ROTATION_STATUS_COMPLETED:
		ret = snprintf(rotation_handle->output_path, PATH_MAX, "%s",
				pending_return->output_path);
		if (ret < 0 || ret >= PATH_MAX) {
			rotation_handle->status = LTTNG_ROTATION_STATUS_ERROR;
			ret = -1;
			goto end;
		}
		break;
	case LTTNG_ROTATION_STATUS_EXPIRED:
		ret = 0;
		break;
	/* Still pending */
	case LTTNG_ROTATION_STATUS_STARTED:
		ret = 1;
		break;
	/* Error */
	default:
		ret = -1;
		break;
	}

end:
	free(pending_return);
	return ret;
}

/*
 * Configure the automatic rotate parameters.
 *
 * Return 0 on success else a negative LTTng error code.
 */
int lttng_rotation_set_schedule(struct lttng_rotation_schedule_attr *attr)
{
	struct lttcomm_session_msg lsm;
	int ret;

	if (!attr) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	memset(&lsm, 0, sizeof(lsm));
	lsm.cmd_type = LTTNG_ROTATION_SET_SCHEDULE;
	lttng_ctl_copy_string(lsm.session.name, attr->session_name,
			sizeof(lsm.session.name));
	lsm.u.rotate_setup.timer_us = attr->timer_us;

	ret = lttng_ctl_ask_sessiond(&lsm, NULL);

end:
	return ret;
}

int lttng_rotation_get_current_path(const char *session_name,
		char **chunk_path)
{
	struct lttcomm_session_msg lsm;
	struct lttng_rotation_get_current_path *get_return = NULL;
	int ret;

	memset(&lsm, 0, sizeof(lsm));
	lsm.cmd_type = LTTNG_ROTATION_GET_CURRENT_PATH;
	lttng_ctl_copy_string(lsm.session.name, session_name,
			sizeof(lsm.session.name));

	ret = lttng_ctl_ask_sessiond(&lsm, (void **) &get_return);
	if (ret < 0) {
		ret = -1;
		goto end;
	}

	if (get_return->status == LTTNG_ROTATION_STATUS_NO_ROTATION) {
		ret = 1;
		goto end;
	} else if (get_return->status != LTTNG_ROTATION_STATUS_COMPLETED) {
		ret = -1;
		goto end;
	}
	*chunk_path = zmalloc(PATH_MAX * sizeof(char));
	if (!*chunk_path) {
		ret = -1;
		goto end;
	}
	strncpy(*chunk_path, get_return->output_path, PATH_MAX);

	ret = 0;

end:
	free(get_return);
	return ret;

}
