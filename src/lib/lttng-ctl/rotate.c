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
#include <lttng/rotate.h>
#include <lttng/rotate-internal.h>
#include <common/sessiond-comm/sessiond-comm.h>

#include "lttng-ctl-helper.h"

struct lttng_rotate_session_attr *lttng_rotate_session_attr_create(void)
{
	return zmalloc(sizeof(struct lttng_rotate_session_attr));
}

void lttng_rotate_session_attr_destroy(struct lttng_rotate_session_attr *attr)
{
	if (attr) {
		free(attr);
		attr = NULL;
	}
}

int lttng_rotate_session_attr_set_session_name(
		struct lttng_rotate_session_attr *attr,
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

enum lttng_rotate_status lttng_rotate_session_get_status(
		struct lttng_rotate_session_handle *rotate_handle)
{
	if (!rotate_handle) {
		return LTTNG_ROTATE_ERROR;
	}
	return rotate_handle->status;
}

int lttng_rotate_session_get_output_path(
		struct lttng_rotate_session_handle *rotate_handle,
		char **path)
{
	int ret;

	*path = zmalloc(PATH_MAX);
	if (!*path) {
		ret = -1;
		goto end;
	}

	if (rotate_handle->status == LTTNG_ROTATE_COMPLETED) {
		ret = snprintf(*path, PATH_MAX, "%s", rotate_handle->output_path);
		if (ret < 0) {
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

void lttng_rotate_session_handle_destroy(
		struct lttng_rotate_session_handle *rotate_handle)
{
	if (!rotate_handle) {
		return;
	}
	free(rotate_handle);
	rotate_handle = NULL;
}

static
void init_rotate_handle(struct lttng_rotate_session_handle *rotate_handle,
		struct lttng_rotate_session_return *rotate_return,
		struct lttng_rotate_session_attr *attr)
{
	(void) snprintf(rotate_handle->session_name, LTTNG_NAME_MAX, "%s",
			attr->session_name);
	rotate_handle->rotate_id = rotate_return->rotate_id;
	rotate_handle->status = rotate_return->status;
}

/*
 * Rotate the output folder of the session.
 *
 * Return 0 on success else a negative LTTng error code.
 */
int lttng_rotate_session(struct lttng_rotate_session_attr *attr,
		struct lttng_rotate_session_handle **rotate_handle)
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
		*rotate_handle = NULL;
		goto end;
	}

	*rotate_handle = zmalloc(sizeof(struct lttng_rotate_session_handle));
	if (!*rotate_handle) {
		ret = -LTTNG_ERR_NOMEM;
		goto end;
	}

	init_rotate_handle(*rotate_handle, rotate_return, attr);

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
int lttng_rotate_session_pending(
		struct lttng_rotate_session_handle *rotate_handle)
{
	/* lsm.rotate_pending.rotate_id */
	struct lttcomm_session_msg lsm;
	struct lttng_rotate_session_attr attr;
	int ret;
	struct lttng_rotate_pending_return *pending_return = NULL;

	ret = snprintf(attr.session_name, LTTNG_NAME_MAX, "%s",
			rotate_handle->session_name);
	if (ret < 0) {
		rotate_handle->status = LTTNG_ROTATE_ERROR;
		ret = -1;
		goto end;
	}

	memset(&lsm, 0, sizeof(lsm));
	lsm.cmd_type = LTTNG_ROTATE_PENDING;
	lsm.u.rotate_pending.rotate_id = rotate_handle->rotate_id;
	lttng_ctl_copy_string(lsm.session.name, attr.session_name,
			sizeof(lsm.session.name));

	ret = lttng_ctl_ask_sessiond(&lsm, (void **) &pending_return);
	if (ret < 0) {
		rotate_handle->status = LTTNG_ROTATE_ERROR;
		goto end;
	}

	rotate_handle->status = pending_return->status;
	switch(pending_return->status) {
	/* Not pending anymore */
	case LTTNG_ROTATE_COMPLETED:
		ret = snprintf(rotate_handle->output_path, PATH_MAX, "%s",
				pending_return->output_path);
		if (ret < 0) {
			rotate_handle->status = LTTNG_ROTATE_ERROR;
			ret = -1;
			goto end;
		}
	case LTTNG_ROTATE_EXPIRED:
		ret = 0;
		break;
	/* Still pending */
	case LTTNG_ROTATE_STARTED:
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

int lttng_rotate_get_current_path(const char *session_name,
		char **chunk_path)
{
	struct lttcomm_session_msg lsm;
	struct lttng_rotate_get_current_path *get_return = NULL;
	int ret;

	memset(&lsm, 0, sizeof(lsm));
	lsm.cmd_type = LTTNG_ROTATE_GET_CURRENT_PATH;
	lttng_ctl_copy_string(lsm.session.name, session_name,
			sizeof(lsm.session.name));

	ret = lttng_ctl_ask_sessiond(&lsm, (void **) &get_return);
	if (ret < 0) {
		ret = -1;
		goto end;
	}

	if (get_return->status == LTTNG_ROTATE_NO_ROTATION) {
		ret = 1;
		goto end;
	} else if (get_return->status != LTTNG_ROTATE_COMPLETED) {
		ret = -1;
		goto end;
	}
	*chunk_path = zmalloc(PATH_MAX * sizeof(char));
	strncpy(*chunk_path, get_return->output_path, PATH_MAX);

	ret = 0;

end:
	free(get_return);
	return ret;

}
