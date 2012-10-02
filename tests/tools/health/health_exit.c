/*
 * Copyright (C) 2012 - Christian Babeux <christian.babeux@efficios.com>
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

#include <stdlib.h>
#include <string.h>
#include <pthread.h>

/*
 * Check if the specified environment variable is set.
 * Return 1 if set, otherwise 0.
 */
int check_env_var(const char *env)
{
	if (env) {
		char *env_val = getenv(env);
		if (env_val && (strncmp(env_val, "1", 1) == 0)) {
			return 1;
		}
	}

	return 0;
}

void __testpoint_thread_manage_clients(void)
{
	const char *var = "LTTNG_THREAD_MANAGE_CLIENTS_EXIT";

	if (check_env_var(var)) {
		pthread_exit(NULL);
	}
}

void __testpoint_thread_registration_apps(void)
{
	const char *var = "LTTNG_THREAD_REG_APPS_EXIT";

	if (check_env_var(var)) {
		pthread_exit(NULL);
	}
}

void __testpoint_thread_manage_apps(void)
{
	const char *var = "LTTNG_THREAD_MANAGE_APPS_EXIT";

	if (check_env_var(var)) {
		pthread_exit(NULL);
	}
}

void __testpoint_thread_manage_kernel(void)
{
	const char *var = "LTTNG_THREAD_MANAGE_KERNEL_EXIT";

	if (check_env_var(var)) {
		pthread_exit(NULL);
	}
}

void __testpoint_thread_manage_consumer(void)
{
	const char *var = "LTTNG_THREAD_MANAGE_CONSUMER_EXIT";

	if (check_env_var(var)) {
		pthread_exit(NULL);
	}
}
