/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *                      Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *               2013 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "lttng-sessiond.h"
#include <common/compat/uuid.h>

lttng_uuid sessiond_uuid;

int ust_consumerd64_fd = -1;
int ust_consumerd32_fd = -1;

long page_size;

struct health_app *health_sessiond;

struct notification_thread_handle *notification_thread_handle;

struct lttng_ht *agent_apps_ht_by_sock = NULL;

int kernel_tracer_fd = -1;
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
