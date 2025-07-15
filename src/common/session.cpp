/*
 * SPDX-FileCopyrightText: 2025 Kienan Stewart <kstewart@efficios.com>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "common.hpp"
#include "session.hpp"

#include <stdlib.h>
#include <string.h>

/* These characters are forbidden in a session name. Used by validate_name. */
const char *forbidden_name_chars = "/";

int session_validate_name(const char *name)
{
	int ret;
	char *tok, *tmp_name;

	LTTNG_ASSERT(name);

	tmp_name = strdup(name);
	if (!tmp_name) {
		/* ENOMEM here. */
		ret = -1;
		goto error;
	}

	tok = strpbrk(tmp_name, forbidden_name_chars);
	if (tok) {
		DBG("Session name %s contains a forbidden character", name);
		/* Forbidden character has been found. */
		ret = -1;
		goto error;
	}
	ret = 0;

error:
	free(tmp_name);
	return ret;
}
