/*
 * Copyright (C) 2013 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
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
#include <lttng/save.h>
#include <lttng/save-internal.h>
#include <common/sessiond-comm/sessiond-comm.h>

#include "lttng-ctl-helper.h"

struct lttng_save_session_attr *lttng_save_session_attr_create(void)
{
	return zmalloc(sizeof(struct lttng_save_session_attr));
}

void lttng_save_session_attr_destroy(struct lttng_save_session_attr *output)
{
	if (output) {
		free(output);
	}
}

const char *lttng_save_session_attr_get_session_name(
	struct lttng_save_session_attr *attr)
{
	const char *ret = NULL;

	if (attr && attr->session_name[0]) {
		ret = attr->session_name;
	}

	return ret;
}

const char *lttng_save_session_attr_get_output_url(
	struct lttng_save_session_attr *attr)
{
	const char *ret = NULL;

	if (attr && attr->configuration_url[0]) {
		ret = attr->configuration_url;
	}

	return ret;
}

int lttng_save_session_attr_get_overwrite(
	struct lttng_save_session_attr *attr)
{
	return attr ? attr->overwrite : -LTTNG_ERR_INVALID;
}

int lttng_save_session_attr_get_omit_name(
	struct lttng_save_session_attr *attr)
{
	return attr ? attr->omit_name : -LTTNG_ERR_INVALID;
}

int lttng_save_session_attr_get_omit_output(
	struct lttng_save_session_attr *attr)
{
	return attr ? attr->omit_output : -LTTNG_ERR_INVALID;
}

int lttng_save_session_attr_set_session_name(
	struct lttng_save_session_attr *attr, const char *session_name)
{
	int ret = 0;

	if (!attr) {
		ret = -LTTNG_ERR_INVALID;
		goto error;
	}

	if (session_name) {
		size_t len;

		len = strlen(session_name);
		if (len >= LTTNG_NAME_MAX) {
			ret = -LTTNG_ERR_INVALID;
			goto error;
		}

		strncpy(attr->session_name, session_name, len);
	} else {
		attr->session_name[0] = '\0';
	}
error:
	return ret;
}

int lttng_save_session_attr_set_output_url(
	struct lttng_save_session_attr *attr, const char *url)
{
	int ret = 0;
	size_t len;
	ssize_t size;
	struct lttng_uri *uris = NULL;

	if (!attr) {
		ret = -LTTNG_ERR_INVALID;
		goto error;
	}

	if (!url) {
		attr->configuration_url[0] = '\0';
		ret = 0;
		goto end;
	}

	len = strlen(url);
	if (len >= PATH_MAX) {
		ret = -LTTNG_ERR_INVALID;
		goto error;
	}

	size = uri_parse_str_urls(url, NULL, &uris);
	if (size <= 0 || uris[0].dtype != LTTNG_DST_PATH) {
		ret = -LTTNG_ERR_INVALID;
		goto error;
	}

	/* Copy string plus the NULL terminated byte. */
	lttng_ctl_copy_string(attr->configuration_url, uris[0].dst.path,
			sizeof(attr->configuration_url));

end:
error:
	free(uris);
	return ret;
}

int lttng_save_session_attr_set_overwrite(
	struct lttng_save_session_attr *attr, int overwrite)
{
	int ret = 0;

	if (!attr) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	attr->overwrite = !!overwrite;
end:
	return ret;
}

int lttng_save_session_attr_set_omit_name(
	struct lttng_save_session_attr *attr, int omit_name)
{
	int ret = 0;

	if (!attr) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	attr->omit_name = !!omit_name;
end:
	return ret;
}

int lttng_save_session_attr_set_omit_output(
	struct lttng_save_session_attr *attr, int omit_output)
{
	int ret = 0;

	if (!attr) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	attr->omit_output = !!omit_output;
end:
	return ret;
}

/*
 * The lttng-ctl API does not expose all the information needed to save the
 * session configurations. Thus, we must send a save command to the session
 * daemon which will, in turn, save its current session configuration.
 */
int lttng_save_session(struct lttng_save_session_attr *attr)
{
	struct lttcomm_session_msg lsm;
	int ret;

	if (!attr) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	memset(&lsm, 0, sizeof(lsm));
	lsm.cmd_type = LTTNG_SAVE_SESSION;

	memcpy(&lsm.u.save_session.attr, attr,
		sizeof(struct lttng_save_session_attr));
	ret = lttng_ctl_ask_sessiond(&lsm, NULL);
end:
	return ret;
}
