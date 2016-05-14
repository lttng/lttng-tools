/*
 * Copyright 2016 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef LTTNG_COMMON_CONTEXT_H
#define LTTNG_COMMON_CONTEXT_H

#include <common/macros.h>

/*
 * Parse string as an application context of the form
 * "$app.provider_name:context_name" and return the provider name and context
 * name separately.
 *
 * provider_name and ctx_name are returned only if an application context name
 * was successfully parsed and must be freed by the caller.
 *
 * Returns 0 if the string is a valid application context, else a negative
 * value on error.
 */
LTTNG_HIDDEN
int parse_application_context(const char *str, char **provider_name,
		char **ctx_name);

#endif /* LTTNG_COMMON_CONTEXT_H */
