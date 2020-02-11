/*
 * Copyright (C) 2011 David Goulet <david.goulet@polymtl.ca>
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright (C) 2013 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "lttng-sessiond.h"
#include <common/uuid.h>

lttng_uuid sessiond_uuid;

int ust_consumerd64_fd = -1;
int ust_consumerd32_fd = -1;

long page_size;

struct health_app *health_sessiond;

struct notification_thread_handle *notification_thread_handle;

struct lttng_ht *agent_apps_ht_by_sock = NULL;
struct lttng_ht *trigger_agents_ht_by_domain = NULL;

struct lttng_kernel_tracer_version kernel_tracer_version;
struct lttng_kernel_tracer_abi_version kernel_tracer_abi_version;

int kernel_poll_pipe[2] = { -1, -1 };

pid_t ppid;
pid_t child_ppid;

struct sessiond_config config;

struct consumer_data kconsumer_data = {
	.type = LTTNG_CONSUMER_KERNEL,
	.err_sock = -1,
	.cmd_sock = -1,
	.channel_monitor_pipe = -1,
	.pid_mutex = PTHREAD_MUTEX_INITIALIZER,
	.lock = PTHREAD_MUTEX_INITIALIZER,
};

struct consumer_data ustconsumer64_data = {
	.type = LTTNG_CONSUMER64_UST,
	.err_sock = -1,
	.cmd_sock = -1,
	.channel_monitor_pipe = -1,
	.pid_mutex = PTHREAD_MUTEX_INITIALIZER,
	.lock = PTHREAD_MUTEX_INITIALIZER,
};

struct consumer_data ustconsumer32_data = {
	.type = LTTNG_CONSUMER32_UST,
	.err_sock = -1,
	.cmd_sock = -1,
	.channel_monitor_pipe = -1,
	.pid_mutex = PTHREAD_MUTEX_INITIALIZER,
	.lock = PTHREAD_MUTEX_INITIALIZER,
};

enum consumerd_state ust_consumerd_state;
enum consumerd_state kernel_consumerd_state;

static void __attribute__((constructor)) init_sessiond_uuid(void)
{
	if (lttng_uuid_generate(sessiond_uuid)) {
		ERR("Failed to generate a session daemon UUID");
		abort();
	}
}
