/*
 * SPDX-FileCopyrightText: 2012 Christian Babeux <christian.babeux@efficios.com>
 * SPDX-FileCopyrightText: 2014 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include <lttng/lttng-export.h>

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <urcu.h>

/*
 * Check if the specified environment variable is set.
 * Return 1 if set, otherwise 0.
 */
static int check_env_var(const char *env)
{
	if (env) {
		char *env_val = getenv(env);
		if (env_val && (strncmp(env_val, "1", 1) == 0)) {
			return 1;
		}
	}

	return 0;
}

/* Session daemon */

LTTNG_EXPORT int __testpoint_sessiond_thread_manage_clients(void);
int __testpoint_sessiond_thread_manage_clients(void)
{
	const char *var = "LTTNG_SESSIOND_THREAD_MANAGE_CLIENTS_TP_FAIL";

	if (check_env_var(var)) {
		return 1;
	}

	return 0;
}

LTTNG_EXPORT int __testpoint_sessiond_thread_registration_apps(void);
int __testpoint_sessiond_thread_registration_apps(void)
{
	const char *var = "LTTNG_SESSIOND_THREAD_REG_APPS_TP_FAIL";

	if (check_env_var(var)) {
		return 1;
	}

	return 0;
}

LTTNG_EXPORT int __testpoint_sessiond_thread_manage_apps(void);
int __testpoint_sessiond_thread_manage_apps(void)
{
	const char *var = "LTTNG_SESSIOND_THREAD_MANAGE_APPS_TP_FAIL";

	if (check_env_var(var)) {
		return 1;
	}

	return 0;
}

LTTNG_EXPORT int __testpoint_sessiond_thread_manage_kernel(void);
int __testpoint_sessiond_thread_manage_kernel(void)
{
	const char *var = "LTTNG_SESSIOND_THREAD_MANAGE_KERNEL_TP_FAIL";

	if (check_env_var(var)) {
		return 1;
	}

	return 0;
}

LTTNG_EXPORT int __testpoint_sessiond_thread_manage_consumer(void);
int __testpoint_sessiond_thread_manage_consumer(void)
{
	const char *var = "LTTNG_SESSIOND_THREAD_MANAGE_CONSUMER_TP_FAIL";

	if (check_env_var(var)) {
		return 1;
	}

	return 0;
}

LTTNG_EXPORT int __testpoint_sessiond_thread_app_manage_notify(void);
int __testpoint_sessiond_thread_app_manage_notify(void)
{
	const char *var = "LTTNG_SESSIOND_THREAD_APP_MANAGE_NOTIFY_TP_FAIL";

	if (check_env_var(var)) {
		return 1;
	}

	return 0;
}

LTTNG_EXPORT int __testpoint_sessiond_thread_app_reg_dispatch(void);
int __testpoint_sessiond_thread_app_reg_dispatch(void)
{
	const char *var = "LTTNG_SESSIOND_THREAD_APP_REG_DISPATCH_TP_FAIL";

	if (check_env_var(var)) {
		return 1;
	}

	return 0;
}

/* Consumer daemon */

LTTNG_EXPORT int __testpoint_consumerd_thread_channel(void);
int __testpoint_consumerd_thread_channel(void)
{
	const char *var = "LTTNG_CONSUMERD_THREAD_CHANNEL_TP_FAIL";

	if (check_env_var(var)) {
		return 1;
	}

	return 0;
}

LTTNG_EXPORT int __testpoint_consumerd_thread_metadata(void);
int __testpoint_consumerd_thread_metadata(void)
{
	const char *var = "LTTNG_CONSUMERD_THREAD_METADATA_TP_FAIL";

	if (check_env_var(var)) {
		return 1;
	}

	return 0;
}

LTTNG_EXPORT int __testpoint_consumerd_thread_data(void);
int __testpoint_consumerd_thread_data(void)
{
	const char *var = "LTTNG_CONSUMERD_THREAD_DATA_TP_FAIL";

	if (check_env_var(var)) {
		return 1;
	}

	return 0;
}

LTTNG_EXPORT int __testpoint_consumerd_thread_sessiond(void);
int __testpoint_consumerd_thread_sessiond(void)
{
	const char *var = "LTTNG_CONSUMERD_THREAD_SESSIOND_TP_FAIL";

	if (check_env_var(var)) {
		return 1;
	}

	return 0;
}

/* Relay daemon */

LTTNG_EXPORT int __testpoint_relayd_thread_dispatcher(void);
int __testpoint_relayd_thread_dispatcher(void)
{
	const char *var = "LTTNG_RELAYD_THREAD_DISPATCHER_TP_FAIL";

	if (check_env_var(var)) {
		return 1;
	}

	return 0;
}

LTTNG_EXPORT int __testpoint_relayd_thread_worker(void);
int __testpoint_relayd_thread_worker(void)
{
	const char *var = "LTTNG_RELAYD_THREAD_WORKER_TP_FAIL";

	if (check_env_var(var)) {
		return 1;
	}

	return 0;
}

LTTNG_EXPORT int __testpoint_relayd_thread_listener(void);
int __testpoint_relayd_thread_listener(void)
{
	const char *var = "LTTNG_RELAYD_THREAD_LISTENER_TP_FAIL";

	if (check_env_var(var)) {
		return 1;
	}

	return 0;
}

LTTNG_EXPORT int __testpoint_relayd_thread_live_dispatcher(void);
int __testpoint_relayd_thread_live_dispatcher(void)
{
	const char *var = "LTTNG_RELAYD_THREAD_LIVE_DISPATCHER_TP_FAIL";

	if (check_env_var(var)) {
		return 1;
	}

	return 0;
}

LTTNG_EXPORT int __testpoint_relayd_thread_live_worker(void);
int __testpoint_relayd_thread_live_worker(void)
{
	const char *var = "LTTNG_RELAYD_THREAD_LIVE_WORKER_TP_FAIL";

	if (check_env_var(var)) {
		return 1;
	}

	return 0;
}

LTTNG_EXPORT int __testpoint_relayd_thread_live_listener(void);
int __testpoint_relayd_thread_live_listener(void)
{
	const char *var = "LTTNG_RELAYD_THREAD_LIVE_LISTENER_TP_FAIL";

	if (check_env_var(var)) {
		return 1;
	}

	return 0;
}
