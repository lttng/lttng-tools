/*
 * Copyright 2016 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_COMMON_CONTEXT_H
#define LTTNG_COMMON_CONTEXT_H

#include <common/macros.hpp>

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
int parse_application_context(const char *str, char **provider_name, char **ctx_name);

#endif /* LTTNG_COMMON_CONTEXT_H */
