/*
 * Copyright (C) 2011 EfficiOS Inc.
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright (C) 2013 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "lttng-sessiond.hpp"

#include <common/uuid.hpp>

lttng_uuid the_sessiond_uuid;

int the_ust_consumerd64_fd = -1;
int the_ust_consumerd32_fd = -1;

long the_page_size;

struct health_app *the_health_sessiond;

struct notification_thread_handle *the_notification_thread_handle;
lttng::sessiond::rotation_thread::uptr the_rotation_thread_handle;

struct lttng_ht *the_agent_apps_ht_by_sock = nullptr;
struct lttng_ht *the_trigger_agents_ht_by_domain = nullptr;

struct lttng_kernel_abi_tracer_version the_kernel_tracer_version;
struct lttng_kernel_abi_tracer_abi_version the_kernel_tracer_abi_version;

int the_kernel_poll_pipe[2] = { -1, -1 };

pid_t the_ppid;
pid_t the_child_ppid;

struct sessiond_config the_config;

consumer_data the_kconsumer_data(LTTNG_CONSUMER_KERNEL);
consumer_data the_ustconsumer64_data(LTTNG_CONSUMER64_UST);
consumer_data the_ustconsumer32_data(LTTNG_CONSUMER32_UST);

enum consumerd_state the_ust_consumerd_state;
enum consumerd_state the_kernel_consumerd_state;

static void __attribute__((constructor)) init_sessiond_uuid()
{
	if (lttng_uuid_generate(the_sessiond_uuid)) {
		ERR("Failed to generate a session daemon UUID");
		abort();
	}
}
