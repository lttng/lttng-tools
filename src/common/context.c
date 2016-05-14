/*
 * context.c
 *
 * LTTng context utilities.
 *
 * Copyright 2016 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License, version 2.1 only,
 * as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "context.h"
#include <stddef.h>
#include <string.h>
#include <common/error.h>
#include <common/macros.h>

LTTNG_HIDDEN
int parse_application_context(const char *str, char **out_provider_name,
		char **out_ctx_name)
{
	const char app_ctx_prefix[] = "$app.";
	char *provider_name = NULL, *ctx_name = NULL;
	size_t i, len, colon_pos = 0, provider_name_len, ctx_name_len;

	if (!str || !out_provider_name || !out_ctx_name) {
		goto not_found;
	}

	len = strlen(str);
	if (len <= sizeof(app_ctx_prefix) - 1) {
		goto not_found;
	}

	/* String starts with $app. */
	if (strncmp(str, app_ctx_prefix, sizeof(app_ctx_prefix) - 1)) {
		goto not_found;
	}

	/* Validate that the ':' separator is present. */
	for (i = sizeof(app_ctx_prefix); i < len; i++) {
		const char c = str[i];

		if (c == ':') {
			colon_pos = i;
			break;
		}
	}

	/*
	 * No colon found or no ctx name ("$app.provider:") or no provider name
	 * given ("$app.:..."), which is invalid.
	 */
	if (!colon_pos || colon_pos == len ||
			colon_pos == sizeof(app_ctx_prefix)) {
		goto not_found;
	}

	provider_name_len = colon_pos - sizeof(app_ctx_prefix) + 2;
	provider_name = zmalloc(provider_name_len);
	if (!provider_name) {
		PERROR("malloc provider_name");
		goto not_found;
	}
	strncpy(provider_name, str + sizeof(app_ctx_prefix) - 1,
			provider_name_len - 1);

	ctx_name_len = len - colon_pos;
	ctx_name = zmalloc(ctx_name_len);
	if (!ctx_name) {
		PERROR("malloc ctx_name");
		goto not_found;
	}
	strncpy(ctx_name, str + colon_pos + 1, ctx_name_len - 1);

	*out_provider_name = provider_name;
	*out_ctx_name = ctx_name;
	return 0;
not_found:
	free(provider_name);
	free(ctx_name);
	return -1;
}

