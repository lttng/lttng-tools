/*
 * Copyright (C) 2012 - Christian Babeux <christian.babeux@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef NTESTPOINT

#define _LGPL_SOURCE
#include <dlfcn.h>  /* for dlsym   */
#include <stdlib.h> /* for getenv  */
#include <string.h> /* for strncmp */

#include "testpoint.h"

/* Environment variable used to enable the testpoints facilities. */
static const char *lttng_testpoint_env_var = "LTTNG_TESTPOINT_ENABLE";

/* Testpoint toggle flag */
int lttng_testpoint_activated;

/*
 * Toggle the support for testpoints on the application startup.
 */
static void __attribute__((constructor)) lttng_testpoint_check(void)
{
	char *testpoint_env_val = NULL;

	testpoint_env_val = getenv(lttng_testpoint_env_var);
	if (testpoint_env_val != NULL
			&& (strncmp(testpoint_env_val, "1", 1) == 0)) {
		lttng_testpoint_activated = 1;
	}
}

/*
 * Lookup a symbol by name.
 *
 * Return the address where the symbol is loaded or NULL if the symbol was not
 * found.
 */
void *lttng_testpoint_lookup(const char *name)
{
	if (!name) {
		return NULL;
	}

	return dlsym(RTLD_DEFAULT, name);
}

#endif /* NTESTPOINT */
