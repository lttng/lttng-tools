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
#include <limits.h>

#include <lttng/lttng-error.h>
#include <lttng/load.h>
#include <lttng/load-internal.h>
#include <common/sessiond-comm/sessiond-comm.h>
#include <common/config/session-config.h>
#include <common/uri.h>
#include <common/macros.h>
#include <common/compat/string.h>

#include "lttng-ctl-helper.h"

struct lttng_load_session_attr *lttng_load_session_attr_create(void)
{
	return zmalloc(sizeof(struct lttng_load_session_attr));
}

static
void reset_load_session_attr_urls(struct lttng_load_session_attr *attr)
{
	free(attr->raw_override_url);
	free(attr->raw_override_path_url);
	free(attr->raw_override_ctrl_url);
	free(attr->raw_override_data_url);
	if (attr->override_attr) {
		free(attr->override_attr->path_url);
		free(attr->override_attr->ctrl_url);
		free(attr->override_attr->data_url);
		free(attr->override_attr->session_name);
	}
}

void lttng_load_session_attr_destroy(struct lttng_load_session_attr *attr)
{
	if (attr) {
		reset_load_session_attr_urls(attr);
		free(attr->override_attr);
		free(attr);
	}
}

static int validate_attr(const struct lttng_load_session_attr *attr)
{
	int ret = 0;

	if (!attr) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	if (!attr->override_attr) {
		goto end;
	}

	/*
	 * Refuse override name if the objective is to load multiple session
	 * since this operation is ambiguous while loading multiple session.
	 */
	if (attr->override_attr->session_name
			&& attr->session_name[0] == '\0') {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}
end:
	return ret;
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

const char *lttng_load_session_attr_get_override_ctrl_url(
	struct lttng_load_session_attr *attr)
{
	const char *ret = NULL;

	if (!attr || !attr->override_attr) {
		goto end;
	}

	ret = attr->raw_override_ctrl_url;
end:
	return ret;
}

const char *lttng_load_session_attr_get_override_data_url(
	struct lttng_load_session_attr *attr)
{
	const char *ret = NULL;

	if (!attr || !attr->override_attr) {
		goto end;
	}

	ret = attr->raw_override_data_url;
end:
	return ret;
}

const char *lttng_load_session_attr_get_override_url(
		struct lttng_load_session_attr *attr)
{
	const char *ret = NULL;

	if (!attr || !attr->override_attr) {
		goto end;
	}

	if ((attr->override_attr->path_url ||
		(attr->override_attr->ctrl_url &&
		 attr->override_attr->data_url))) {
		ret = attr->raw_override_url;
	}
end:
	return ret;
}

const char *lttng_load_session_attr_get_override_session_name(
		struct lttng_load_session_attr *attr)
{
	const char *ret = NULL;

	if (!attr || !attr->override_attr) {
		goto end;
	}

	ret = attr->override_attr->session_name;
end:
	return ret;
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
	size_t len;
	ssize_t size;
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

int lttng_load_session_attr_set_override_ctrl_url(
	struct lttng_load_session_attr *attr, const char *url)
{
	int ret = 0;
	ssize_t ret_size;
	struct lttng_uri *uri = NULL;
	char *url_str = NULL;
	char *raw_str = NULL;

	if (!attr) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	if (!attr->override_attr) {
		attr->override_attr = zmalloc(
			sizeof(struct config_load_session_override_attr));
		if (!attr->override_attr) {
			ret = -LTTNG_ERR_NOMEM;
			goto end;
		}
	}

	if (attr->override_attr->path_url) {
		/*
		 * Setting a ctrl override after a path override makes no sense.
		 */
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	/*
	 * FIXME: uri_parse should be able to take as parameter the protocol
	 * type to validate "url". For now only check the parsing goes through;
	 * it will fail later on.
	 */
	ret_size = uri_parse(url, &uri);
	if (ret_size < 0) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	if (uri[0].port == 0) {
		uri[0].port = DEFAULT_NETWORK_CONTROL_PORT;
	}

	url_str = zmalloc(PATH_MAX);
	if (!url_str) {
		/* FIXME: return valid error */
		ret = -LTTNG_ERR_NOMEM;
		goto end;
	}

	ret = uri_to_str_url(&uri[0], url_str, PATH_MAX);
	if (ret < 0) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}
	ret = 0;

	raw_str = lttng_strndup(url, PATH_MAX);
	if (!raw_str) {
		ret = -LTTNG_ERR_NOMEM;
		goto end;
	}

	/* Squash old value if any */
	free(attr->override_attr->ctrl_url);
	free(attr->raw_override_ctrl_url);

	/* Populate the object */
	attr->override_attr->ctrl_url = url_str;
	attr->raw_override_ctrl_url = raw_str;

	/* Ownership passed to attr. */
	url_str = NULL;
	raw_str = NULL;

end:
	free(raw_str);
	free(url_str);
	free(uri);
	return ret;
}

int lttng_load_session_attr_set_override_data_url(
	struct lttng_load_session_attr *attr, const char *url)
{
	int ret = 0;
	ssize_t ret_size;
	struct lttng_uri *uri = NULL;
	char *url_str = NULL;
	char *raw_str = NULL;

	if (!attr) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	if (!attr->override_attr) {
		attr->override_attr = zmalloc(
			sizeof(struct config_load_session_override_attr));
		if (!attr->override_attr) {
			ret = -LTTNG_ERR_NOMEM;
			goto end;
		}
	}

	if (attr->override_attr->path_url) {
		/*
		 * Setting a data override after a path override makes no sense.
		 */
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	/*
	 * FIXME: uri_parse should be able to take as parameter the protocol
	 * type to validate "url". For now only check the parsing goes through;
	 * it will fail later on.
	 */
	ret_size = uri_parse(url, &uri);
	if (ret_size < 0) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	if (uri[0].port == 0) {
		uri[0].port = DEFAULT_NETWORK_DATA_PORT;
	}

	url_str = zmalloc(PATH_MAX);
	if (!url_str) {
		ret = -LTTNG_ERR_NOMEM;
		goto end;
	}

	ret = uri_to_str_url(&uri[0], url_str, PATH_MAX);
	if (ret < 0) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}
	ret = 0;

	raw_str = lttng_strndup(url, PATH_MAX);
	if (!raw_str) {
		ret = -LTTNG_ERR_NOMEM;
		goto end;
	}

	/* Squash old value if any */
	free(attr->override_attr->data_url);
	free(attr->raw_override_data_url);

	/* Populate the object */
	attr->override_attr->data_url = url_str;
	attr->raw_override_data_url = raw_str;

	/* Ownership passed to attr. */
	url_str = NULL;
	raw_str = NULL;
end:
	free(raw_str);
	free(url_str);
	free(uri);
	return ret;
}

int lttng_load_session_attr_set_override_url(
		struct lttng_load_session_attr *attr, const char *url)
{
	int ret = 0;
	ssize_t ret_size;
	struct lttng_uri *uri = NULL;
	char *raw_url_str = NULL;
	char *raw_path_str = NULL;
	char *path_str = NULL;
	char *raw_ctrl_str = NULL;
	char *ctrl_str = NULL;
	char *raw_data_str = NULL;
	char *data_str = NULL;
	char buffer[PATH_MAX];

	if (!attr || !url || strlen(url) >= PATH_MAX) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	if (!attr->override_attr) {
		attr->override_attr = zmalloc(
			sizeof(struct config_load_session_override_attr));
		if (!attr->override_attr) {
			ret = -LTTNG_ERR_NOMEM;
			goto end;
		}
	}

	/*
	 * FIXME: uri_parse should be able to take as parameter the protocol
	 * type to validate "url". For now only check the parsing goes through;
	 * it will fail later on.
	 */
	ret_size = uri_parse_str_urls(url, NULL, &uri);
	if (ret_size < 0 || ret_size > 2) {
		/* Unexpected URL format. */
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	raw_url_str = lttng_strndup(url, PATH_MAX);
	if (!raw_url_str) {
		ret = -LTTNG_ERR_NOMEM;
		goto end;
	}

	/* Get path | ctrl && data string URL. */
	ret = uri_to_str_url(&uri[0], buffer, sizeof(buffer));
	if (ret < 0 || ret >= PATH_MAX) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}
	ret = 0;

	switch (uri[0].dtype) {
	case LTTNG_DST_PATH:
		raw_path_str = lttng_strndup(buffer, PATH_MAX);
		if (!raw_path_str) {
			ret = -LTTNG_ERR_NOMEM;
			goto end;
		}

		path_str = lttng_strndup(raw_path_str, PATH_MAX);
		if (!path_str) {
			ret = -LTTNG_ERR_NOMEM;
			goto end;
		}
		break;
	case LTTNG_DST_IPV4:
	case LTTNG_DST_IPV6:
		if (ret_size != 2) {
			ret = -LTTNG_ERR_INVALID;
			goto end;
		}

		raw_ctrl_str = lttng_strndup(buffer, PATH_MAX);
		if (!raw_ctrl_str) {
			ret = -LTTNG_ERR_NOMEM;
			goto end;
		}

		ctrl_str = lttng_strndup(raw_ctrl_str, PATH_MAX);
		if (!ctrl_str) {
			ret = -LTTNG_ERR_NOMEM;
			goto end;
		}

		/* Get the data uri. */
		ret = uri_to_str_url(&uri[1], buffer, sizeof(buffer));
		if (ret < 0) {
			ret = -LTTNG_ERR_INVALID;
			goto end;
		}
		ret = 0;

		raw_data_str = lttng_strndup(buffer, PATH_MAX);
		if (!raw_data_str) {
			ret = -LTTNG_ERR_NOMEM;
			goto end;
		}

		data_str = lttng_strndup(raw_data_str, PATH_MAX);
		if (!data_str) {
			ret = -LTTNG_ERR_NOMEM;
			goto end;
		}

		break;
	default:
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	reset_load_session_attr_urls(attr);

	attr->override_attr->path_url = path_str;
	attr->override_attr->ctrl_url = ctrl_str;
	attr->override_attr->data_url = data_str;

	attr->raw_override_url = raw_url_str;
	attr->raw_override_path_url = raw_path_str;
	attr->raw_override_ctrl_url = raw_ctrl_str;
	attr->raw_override_data_url = raw_data_str;

	/* Pass data ownership to attr. */
	raw_url_str = NULL;
	raw_path_str = NULL;
	path_str = NULL;
	raw_ctrl_str = NULL;
	ctrl_str = NULL;
	raw_data_str = NULL;
	data_str = NULL;

end:
	free(raw_path_str);
	free(path_str);
	free(raw_ctrl_str);
	free(ctrl_str);
	free(raw_data_str);
	free(data_str);
	free(raw_url_str);
	free(uri);
	return ret;
}

int lttng_load_session_attr_set_override_session_name(
	struct lttng_load_session_attr *attr, const char *session_name)
{
	int ret = 0;
	size_t len;

	if (!attr ||!session_name) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	if (!attr->override_attr) {
		attr->override_attr = zmalloc(
			sizeof(struct config_load_session_override_attr));
		if (!attr->override_attr) {
			ret = -LTTNG_ERR_NOMEM;
			goto end;
		}
	}

	len = strlen(session_name);
	if (len >= LTTNG_NAME_MAX) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	attr->override_attr->session_name = lttng_strndup(session_name,
		len);
	if (!attr->override_attr->session_name) {
		ret = -LTTNG_ERR_NOMEM;
		goto end;
	}
end:
	return ret;
}

int lttng_load_session(struct lttng_load_session_attr *attr)
{
	int ret;
	const char *url, *session_name;

	if (!attr) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	ret = validate_attr(attr);
	if (ret) {
		goto end;
	}

	url = attr->input_url[0] != '\0' ? attr->input_url : NULL;
	session_name = attr->session_name[0] != '\0' ?
			attr->session_name : NULL;

	ret = config_load_session(url, session_name, attr->overwrite, 0,
			attr->override_attr);

end:
	return ret;
}
