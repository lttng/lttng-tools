/*
 * Copyright (C) 2014 - David Goulet <dgoulet@efficios.com>
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
#include <lttng/load.h>
#include <lttng/load-internal.h>
#include <common/sessiond-comm/sessiond-comm.h>
#include <common/config/session-config.h>

#include "lttng-ctl-helper.h"

struct lttng_load_session_attr *lttng_load_session_attr_create(void)
{
	return zmalloc(sizeof(struct lttng_load_session_attr));
}

void lttng_load_session_attr_destroy(struct lttng_load_session_attr *attr)
{
	if (attr) {
		free(attr);
	}
}

const char *lttng_load_session_attr_get_session_name(
	struct lttng_load_session_attr *attr)
{
	const char *ret = NULL;

	if (attr && attr->session_name[0]) {
		ret = attr->session_name;
	}

	return ret;
}

const char *lttng_load_session_attr_get_input_url(
	struct lttng_load_session_attr *attr)
{
	const char *ret = NULL;

	if (attr && attr->input_url[0]) {
		ret = attr->input_url;
	}

	return ret;
}

int lttng_load_session_attr_get_overwrite(
	struct lttng_load_session_attr *attr)
{
	return attr ? attr->overwrite : -LTTNG_ERR_INVALID;
}

int lttng_load_session_attr_set_session_name(
	struct lttng_load_session_attr *attr, const char *session_name)
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

int lttng_load_session_attr_set_input_url(
	struct lttng_load_session_attr *attr, const char *url)
{
	int ret = 0;
	size_t len, size;
	struct lttng_uri *uris = NULL;

	if (!attr) {
		ret = -LTTNG_ERR_INVALID;
		goto error;
	}

	if (!url) {
		attr->input_url[0] = '\0';
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
	lttng_ctl_copy_string(attr->input_url, uris[0].dst.path,
			sizeof(attr->input_url));

end:
error:
	free(uris);
	return ret;
}

int lttng_load_session_attr_set_overwrite(
	struct lttng_load_session_attr *attr, int overwrite)
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

/*
 * The lttng-ctl API does not expose all the information needed to load the
 * session configurations. Thus, we must send a load command to the session
 * daemon which will, in turn, load its current session configuration.
 */
int lttng_load_session(struct lttng_load_session_attr *attr)
{
	int ret;
	const char *url, *session_name;

	if (!attr) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	url = attr->input_url[0] != '\0' ? attr->input_url : NULL;
	session_name = attr->session_name[0] != '\0' ?
			attr->session_name : NULL;

	ret = config_load_session(url, session_name, attr->overwrite, 0);

end:
	return ret;
}
