/*
 * Copyright (C) 2017 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
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

#ifndef LTTNG_SESSIOND_CONFIG_H
#define LTTNG_SESSIOND_CONFIG_H

#include <common/macros.h>
#include <stdbool.h>

struct config_string {
	char *value;
	bool should_free;
};

/* Config string takes ownership of value. */
LTTNG_HIDDEN
void config_string_set(struct config_string *string, char *value);

struct sessiond_config {
	int verbose;
	int verbose_consumer;
	/* Agent TCP port for registration. Used by the agent thread. */
	int agent_tcp_port;
	/* Socket timeout for receiving and sending (in seconds). */
	int app_socket_timeout;

	bool quiet;
	bool no_kernel;
	bool background;
	bool daemonize;
	bool sig_parent;

	struct config_string tracing_group_name;

	struct config_string kmod_probes_list;
	struct config_string kmod_extra_probes_list;

	struct config_string rundir;

	/* Global application Unix socket path */
	struct config_string apps_unix_sock_path;
	/* Global client Unix socket path */
	struct config_string client_unix_sock_path;
	/* Global wait shm path for UST */
	struct config_string wait_shm_path;
	/* Global health check unix path */
	struct config_string health_unix_sock_path;
	/*
	 * LTTNG_UST_CLOCK_PLUGIN environment variable to be passed to spawned
	 * consumer daemons.
	 */
	struct config_string lttng_ust_clock_plugin;
	struct config_string pid_file_path;
	struct config_string lock_file_path;
	struct config_string load_session_path;
	struct config_string agent_port_file_path;

	struct config_string consumerd32_path;
	struct config_string consumerd32_bin_path;
	struct config_string consumerd32_lib_dir;
	struct config_string consumerd32_err_unix_sock_path;
	struct config_string consumerd32_cmd_unix_sock_path;

	struct config_string consumerd64_path;
	struct config_string consumerd64_bin_path;
	struct config_string consumerd64_lib_dir;
	struct config_string consumerd64_err_unix_sock_path;
	struct config_string consumerd64_cmd_unix_sock_path;

	struct config_string kconsumerd_path;
	struct config_string kconsumerd_err_unix_sock_path;
	struct config_string kconsumerd_cmd_unix_sock_path;
};

/* Initialize the sessiond_config values to build-defaults. */
LTTNG_HIDDEN
int sessiond_config_init(struct sessiond_config *config);

/* Override sessiond_config values with values specified by the environment. */
LTTNG_HIDDEN
int sessiond_config_apply_env_config(struct sessiond_config *config);

LTTNG_HIDDEN
void sessiond_config_fini(struct sessiond_config *config);

LTTNG_HIDDEN
int sessiond_config_resolve_paths(struct sessiond_config *config);

LTTNG_HIDDEN
void sessiond_config_log(struct sessiond_config *config);

#endif /* LTTNG_SESSIOND_CONFIG_H */
