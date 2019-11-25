/*
 * Copyright (C) 2012 Christian Babeux <christian.babeux@efficios.com>
 * Copyright (C) 2014 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <urcu.h>

#define STALL_TIME 60

/*
 * Check if the specified environment variable is set.
 * Return 1 if set, otherwise 0.
 */
static
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

static
void do_stall(void)
{
	unsigned int sleep_time = STALL_TIME;

	while (sleep_time > 0) {
		sleep_time = sleep(sleep_time);
	}
}

/* Session daemon */

int __testpoint_sessiond_thread_manage_clients(void);
int __testpoint_sessiond_thread_manage_clients(void)
{
	const char *var = "LTTNG_SESSIOND_THREAD_MANAGE_CLIENTS_STALL";

	if (check_env_var(var)) {
		do_stall();
	}

	return 0;
}

int __testpoint_sessiond_thread_registration_apps(void);
int __testpoint_sessiond_thread_registration_apps(void)
{
	const char *var = "LTTNG_SESSIOND_THREAD_REG_APPS_STALL";

	if (check_env_var(var)) {
		do_stall();
	}

	return 0;
}

int __testpoint_sessiond_thread_manage_apps(void);
int __testpoint_sessiond_thread_manage_apps(void)
{
	const char *var = "LTTNG_SESSIOND_THREAD_MANAGE_APPS_STALL";

	if (check_env_var(var)) {
		do_stall();
	}

	return 0;
}

int __testpoint_sessiond_thread_manage_kernel(void);
int __testpoint_sessiond_thread_manage_kernel(void)
{
	const char *var = "LTTNG_SESSIOND_THREAD_MANAGE_KERNEL_STALL";

	if (check_env_var(var)) {
		do_stall();
	}

	return 0;
}

int __testpoint_sessiond_thread_manage_consumer(void);
int __testpoint_sessiond_thread_manage_consumer(void)
{
	const char *var = "LTTNG_SESSIOND_THREAD_MANAGE_CONSUMER_STALL";

	if (check_env_var(var)) {
		do_stall();
	}

	return 0;
}

int __testpoint_sessiond_thread_ht_cleanup(void);
int __testpoint_sessiond_thread_ht_cleanup(void)
{
	const char *var = "LTTNG_SESSIOND_THREAD_HT_CLEANUP_STALL";

	if (check_env_var(var)) {
		do_stall();
	}

	return 0;
}

int __testpoint_sessiond_thread_app_manage_notify(void);
int __testpoint_sessiond_thread_app_manage_notify(void)
{
	const char *var = "LTTNG_SESSIOND_THREAD_APP_MANAGE_NOTIFY_STALL";

	if (check_env_var(var)) {
		do_stall();
	}

	return 0;
}

int __testpoint_sessiond_thread_app_reg_dispatch(void);
int __testpoint_sessiond_thread_app_reg_dispatch(void)
{
	const char *var = "LTTNG_SESSIOND_THREAD_APP_REG_DISPATCH_STALL";

	if (check_env_var(var)) {
		do_stall();
	}

	return 0;
}

/* Consumer daemon */

int __testpoint_consumerd_thread_channel(void);
int __testpoint_consumerd_thread_channel(void)
{
	const char *var = "LTTNG_CONSUMERD_THREAD_CHANNEL_STALL";

	if (check_env_var(var)) {
		do_stall();
	}

	return 0;
}

int __testpoint_consumerd_thread_metadata(void);
int __testpoint_consumerd_thread_metadata(void)
{
	const char *var = "LTTNG_CONSUMERD_THREAD_METADATA_STALL";

	if (check_env_var(var)) {
		do_stall();
	}

	return 0;
}

int __testpoint_consumerd_thread_data(void);
int __testpoint_consumerd_thread_data(void)
{
	const char *var = "LTTNG_CONSUMERD_THREAD_DATA_STALL";

	if (check_env_var(var)) {
		do_stall();
	}

	return 0;
}

int __testpoint_consumerd_thread_sessiond(void);
int __testpoint_consumerd_thread_sessiond(void)
{
	const char *var = "LTTNG_CONSUMERD_THREAD_SESSIOND_STALL";

	if (check_env_var(var)) {
		do_stall();
	}

	return 0;
}

int __testpoint_consumerd_thread_metadata_timer(void);
int __testpoint_consumerd_thread_metadata_timer(void)
{
	const char *var = "LTTNG_CONSUMERD_THREAD_METADATA_TIMER_STALL";

	if (check_env_var(var)) {
		do_stall();
	}

	return 0;
}

/* Relay daemon */

int __testpoint_relayd_thread_dispatcher(void);
int __testpoint_relayd_thread_dispatcher(void)
{
	const char *var = "LTTNG_RELAYD_THREAD_DISPATCHER_STALL";

	if (check_env_var(var)) {
		do_stall();
	}

	return 0;
}

int __testpoint_relayd_thread_worker(void);
int __testpoint_relayd_thread_worker(void)
{
	const char *var = "LTTNG_RELAYD_THREAD_WORKER_STALL";

	if (check_env_var(var)) {
		do_stall();
	}

	return 0;
}

int __testpoint_relayd_thread_listener(void);
int __testpoint_relayd_thread_listener(void)
{
	const char *var = "LTTNG_RELAYD_THREAD_LISTENER_STALL";

	if (check_env_var(var)) {
		do_stall();
	}

	return 0;
}

int __testpoint_relayd_thread_live_dispatcher(void);
int __testpoint_relayd_thread_live_dispatcher(void)
{
	const char *var = "LTTNG_RELAYD_THREAD_LIVE_DISPATCHER_STALL";

	if (check_env_var(var)) {
		do_stall();
	}

	return 0;
}

int __testpoint_relayd_thread_live_worker(void);
int __testpoint_relayd_thread_live_worker(void)
{
	const char *var = "LTTNG_RELAYD_THREAD_LIVE_WORKER_STALL";

	if (check_env_var(var)) {
		do_stall();
	}

	return 0;
}

int __testpoint_relayd_thread_live_listener(void);
int __testpoint_relayd_thread_live_listener(void)
{
	const char *var = "LTTNG_RELAYD_THREAD_LIVE_LISTENER_STALL";

	if (check_env_var(var)) {
		do_stall();
	}

	return 0;
}
