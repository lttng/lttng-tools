/*
 * SPDX-FileCopyrightText: 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "lttng-ust-ctl.hpp"
#include "sessiond-config.hpp"
#include "version.hpp"

#include <common/compat/errno.hpp>
#include <common/compat/getenv.hpp>
#include <common/defaults.hpp>
#include <common/error.hpp>
#include <common/path.hpp>
#include <common/utils.hpp>

#include <ctype.h>
#include <limits.h>

static struct sessiond_config sessiond_config_build_defaults = {
	.verbose = 0,
	.verbose_consumer = 0,
	.agent_tcp_port = { .begin = DEFAULT_AGENT_TCP_PORT_RANGE_BEGIN,
			    .end = DEFAULT_AGENT_TCP_PORT_RANGE_END },

	.event_notifier_buffer_size_kernel = DEFAULT_EVENT_NOTIFIER_ERROR_COUNT_MAP_SIZE,
	.event_notifier_buffer_size_userspace = DEFAULT_EVENT_NOTIFIER_ERROR_COUNT_MAP_SIZE,
	.app_socket_timeout = DEFAULT_APP_SOCKET_RW_TIMEOUT,

	.quiet = false,

	.no_kernel = false,
	.background = false,
	.daemonize = false,
	.sig_parent = false,

	.default_trace_format = LTTNG_TRACE_FORMAT_CTF_1_8,

	.tracing_group_name = { (char *) DEFAULT_TRACING_GROUP, false },

	.kmod_probes_list = { nullptr, false },
	.kmod_extra_probes_list = { nullptr, false },

	.rundir = { nullptr, false },

	.apps_unix_sock_path = { nullptr, false },
	.client_unix_sock_path = { nullptr, false },
	.wait_shm = { false, { nullptr, false } },
	.health_unix_sock_path = { nullptr, false },
	.lttng_ust_clock_plugin = { nullptr, false },
	.pid_file_path = { nullptr, false },
	.lock_file_path = { nullptr, false },
	.load_session_path = { nullptr, false },
	.agent_port_file_path = { nullptr, false },

	.consumerd32_path = { nullptr, false },
	.consumerd32_bin_path = { nullptr, false },
	.consumerd32_lib_dir = { nullptr, false },
	.consumerd32_err_unix_sock_path = { nullptr, false },
	.consumerd32_cmd_unix_sock_path = { nullptr, false },

	.consumerd64_path = { nullptr, false },
	.consumerd64_bin_path = { nullptr, false },
	.consumerd64_lib_dir = { nullptr, false },
	.consumerd64_err_unix_sock_path = { nullptr, false },
	.consumerd64_cmd_unix_sock_path = { nullptr, false },

	.kconsumerd_path = { nullptr, false },
	.kconsumerd_err_unix_sock_path = { nullptr, false },
	.kconsumerd_cmd_unix_sock_path = { nullptr, false },
};

static void config_string_fini(struct config_string *str)
{
	config_string_set(str, nullptr);
}

static void config_string_set_static(struct config_string *config_str, const char *value)
{
	config_string_set(config_str, (char *) value);
	config_str->should_free = false;
}

/* Only use for dynamically-allocated strings. */
void config_string_set(struct config_string *config_str, char *value)
{
	LTTNG_ASSERT(config_str);
	if (config_str->should_free) {
		free(config_str->value);
		config_str->should_free = false;
	}

	config_str->should_free = !!value;
	config_str->value = value;
}

int sessiond_config_apply_env_config(struct sessiond_config *config)
{
	int ret = 0;
	const char *env_value;

	env_value = getenv(DEFAULT_APP_SOCKET_TIMEOUT_ENV);
	if (env_value) {
		char *endptr;
		long int_val;

		errno = 0;
		int_val = strtoul(env_value, &endptr, 0);
		if (errno != 0 || int_val > INT_MAX || (int_val < 0 && int_val != -1)) {
			ERR("Invalid value \"%s\" used for \"%s\" environment variable",
			    env_value,
			    DEFAULT_APP_SOCKET_TIMEOUT_ENV);
			ret = -1;
			goto end;
		}

		config->app_socket_timeout = int_val;
	}

	env_value = lttng_secure_getenv("LTTNG_CONSUMERD32_BIN");
	if (env_value) {
		config_string_set_static(&config->consumerd32_bin_path, env_value);
	}
	env_value = lttng_secure_getenv("LTTNG_CONSUMERD64_BIN");
	if (env_value) {
		config_string_set_static(&config->consumerd64_bin_path, env_value);
	}

	env_value = lttng_secure_getenv("LTTNG_CONSUMERD32_LIBDIR");
	if (env_value) {
		config_string_set_static(&config->consumerd32_lib_dir, env_value);
	}
	env_value = lttng_secure_getenv("LTTNG_CONSUMERD64_LIBDIR");
	if (env_value) {
		config_string_set_static(&config->consumerd64_lib_dir, env_value);
	}

	env_value = lttng_secure_getenv("LTTNG_UST_CLOCK_PLUGIN");
	if (env_value) {
		config_string_set_static(&config->lttng_ust_clock_plugin, env_value);
	}

	env_value = lttng_secure_getenv(DEFAULT_LTTNG_KMOD_PROBES);
	if (env_value) {
		config_string_set_static(&config->kmod_probes_list, env_value);
	}

	env_value = lttng_secure_getenv(DEFAULT_LTTNG_EXTRA_KMOD_PROBES);
	if (env_value) {
		config_string_set_static(&config->kmod_extra_probes_list, env_value);
	}
end:
	return ret;
}

static int config_set_ust_ctl_paths(struct sessiond_config *config,
				    const char *lttng_ust_ctl_path_override)
{
	char *str;
	int ret;

	ret = asprintf(&str, "%s/%s", lttng_ust_ctl_path_override, LTTNG_UST_SOCK_FILENAME);
	if (ret < 0) {
		ERR("Failed to set default ust_ctl unix socket path");
		return ret;
	}

	config_string_set(&config->apps_unix_sock_path, str);
	str = nullptr;
	ret = asprintf(&str, "%s/%s", lttng_ust_ctl_path_override, LTTNG_UST_WAIT_FILENAME);
	if (ret < 0) {
		ERR("Failed to set default ust_ctl wait shm path");
		return ret;
	}

	config->wait_shm.is_regular_path = true;
	config_string_set(&config->wait_shm.path, str);
	str = nullptr;

	ret = asprintf(
		&str, "%s/%s", lttng_ust_ctl_path_override, DEFAULT_LTTNG_SESSIOND_AGENTPORT_FILE);
	if (ret < 0) {
		ERR("Failed to set ust_ctl agent port file path");
		return ret;
	}

	config_string_set(&config->agent_port_file_path, str);
	str = nullptr;
	return 0;
}

static int config_set_paths(struct sessiond_config *config)
{
	config_string_set(&config->rundir, utils_get_rundir(0));
	if (!config->rundir.value) {
		ERR("Failed to set rundir in session daemon's configuration");
		return -1;
	}

	{
		char *app_sock_path;

		const auto fmt_ret =
			asprintf(&app_sock_path, DEFAULT_APPS_UNIX_SOCK, config->rundir.value);
		if (fmt_ret < 0) {
			ERR("Failed to format apps unix socket path");
			return -1;
		}

		/* Ownership of app_sock_path transfered to config. */
		config_string_set(&config->apps_unix_sock_path, app_sock_path);
	}

	const auto current_uid = getuid();
	if (current_uid == 0) {
		config_string_set_static(&config->wait_shm.path, DEFAULT_GLOBAL_APPS_WAIT_SHM_PATH);
	} else {
		char *home_apps_wait_shm_path;

		const auto fmt_ret = asprintf(
			&home_apps_wait_shm_path, DEFAULT_HOME_APPS_WAIT_SHM_PATH, current_uid);
		if (fmt_ret < 0) {
			ERR("Failed to set default home apps wait shm path");
			return -1;
		}

		/* Ownership of home_apps_wait_shm_path transfered to config. */
		config_string_set(&config->wait_shm.path, home_apps_wait_shm_path);
	}

	{
		char *client_unix_sock_path;

		const auto fmt_ret = asprintf(
			&client_unix_sock_path, DEFAULT_CLIENT_UNIX_SOCK, config->rundir.value);
		if (fmt_ret < 0) {
			ERR("Failed to format client unix sock path");
			return -1;
		}

		config_string_set(&config->client_unix_sock_path, client_unix_sock_path);
	}

	{
		char *health_unix_sock_path;

		const auto fmt_ret = asprintf(
			&health_unix_sock_path, DEFAULT_HEALTH_UNIX_SOCK, config->rundir.value);
		if (fmt_ret < 0) {
			ERR("Failed to format health unix sock path");
			return -1;
		}

		config_string_set(&config->health_unix_sock_path, health_unix_sock_path);
	}

	return 0;
}

int sessiond_config_init(struct sessiond_config *config)
{
	int ret;
	char *str;
	auto lttng_ust_ctl_path_override = lttng::make_unique_wrapper<char, lttng::memory::free>(
		utils_get_lttng_ust_ctl_path_override_dir());

	LTTNG_ASSERT(config);
	memcpy(config, &sessiond_config_build_defaults, sizeof(*config));

	ret = config_set_paths(config);
	if (ret < 0) {
		goto error;
	}

	if (lttng_ust_ctl_path_override) {
		/*
		 * Since a ustctl path override has been specified, re-evaluate the following paths
		 * to take it into account:
		 *   - apps_unix_sock_path
		 *   - wait_shm_path
		 *   - agent_port_file_path
		 */
		ret = config_set_ust_ctl_paths(config, lttng_ust_ctl_path_override.get());
		if (ret < 0) {
			goto error;
		}
	} else {
		ret = asprintf(
			&str, "%s/%s", config->rundir.value, DEFAULT_LTTNG_SESSIOND_AGENTPORT_FILE);
		if (ret < 0) {
			ERR("Failed to set agent port file path");
			goto error;
		}

		config_string_set(&config->agent_port_file_path, str);
		str = nullptr;
	}

	/* 32 bits consumerd path setup */
	ret = asprintf(&str, DEFAULT_USTCONSUMERD32_PATH, config->rundir.value);
	if (ret < 0) {
		ERR("Failed to set 32-bit consumer path");
		goto error;
	}
	config_string_set(&config->consumerd32_path, str);
	str = nullptr;

	ret = asprintf(&str, DEFAULT_USTCONSUMERD32_ERR_SOCK_PATH, config->rundir.value);
	if (ret < 0) {
		ERR("Failed to set 32-bit consumer error socket path");
		goto error;
	}
	config_string_set(&config->consumerd32_err_unix_sock_path, str);
	str = nullptr;

	ret = asprintf(&str, DEFAULT_USTCONSUMERD32_CMD_SOCK_PATH, config->rundir.value);
	if (ret < 0) {
		ERR("Failed to set 32-bit consumer command socket path");
		goto error;
	}
	config_string_set(&config->consumerd32_cmd_unix_sock_path, str);
	str = nullptr;

	/* 64 bits consumerd path setup */
	ret = asprintf(&str, DEFAULT_USTCONSUMERD64_PATH, config->rundir.value);
	if (ret < 0) {
		ERR("Failed to set 64-bit consumer path");
		goto error;
	}
	config_string_set(&config->consumerd64_path, str);
	str = nullptr;

	ret = asprintf(&str, DEFAULT_USTCONSUMERD64_ERR_SOCK_PATH, config->rundir.value);
	if (ret < 0) {
		ERR("Failed to set 64-bit consumer error socket path");
		goto error;
	}
	config_string_set(&config->consumerd64_err_unix_sock_path, str);
	str = nullptr;

	ret = asprintf(&str, DEFAULT_USTCONSUMERD64_CMD_SOCK_PATH, config->rundir.value);
	if (ret < 0) {
		ERR("Failed to set 64-bit consumer command socket path");
		goto error;
	}
	config_string_set(&config->consumerd64_cmd_unix_sock_path, str);
	str = nullptr;

	/* kconsumerd consumerd path setup */
	ret = asprintf(&str, DEFAULT_KCONSUMERD_PATH, config->rundir.value);
	if (ret < 0) {
		ERR("Failed to set kernel consumer path");
		goto error;
	}
	config_string_set(&config->kconsumerd_path, str);
	str = nullptr;

	ret = asprintf(&str, DEFAULT_KCONSUMERD_ERR_SOCK_PATH, config->rundir.value);
	if (ret < 0) {
		ERR("Failed to set kernel consumer error socket path");
		goto error;
	}
	config_string_set(&config->kconsumerd_err_unix_sock_path, str);
	str = nullptr;

	ret = asprintf(&str, DEFAULT_KCONSUMERD_CMD_SOCK_PATH, config->rundir.value);
	if (ret < 0) {
		ERR("Failed to set kernel consumer command socket path");
		goto error;
	}
	config_string_set(&config->kconsumerd_cmd_unix_sock_path, str);
	str = nullptr;

	ret = asprintf(&str, "%s/%s", config->rundir.value, DEFAULT_LTTNG_SESSIOND_PIDFILE);
	if (ret < 0) {
		ERR("Failed to set PID file path");
		goto error;
	}
	config_string_set(&config->pid_file_path, str);
	str = nullptr;

	ret = asprintf(&str, "%s/%s", config->rundir.value, DEFAULT_LTTNG_SESSIOND_LOCKFILE);
	if (ret < 0) {
		ERR("Failed to set lock file path");
		goto error;
	}
	config_string_set(&config->lock_file_path, str);
	str = nullptr;

	/*
	 * Allow INSTALL_BIN_PATH to be used as a target path for the
	 * native architecture size consumer if CONFIG_CONSUMER*_PATH
	 * has not been defined.
	 */
#if (CAA_BITS_PER_LONG == 32)
	config_string_set_static(&config->consumerd32_bin_path,
				 INSTALL_BIN_PATH "/" DEFAULT_CONSUMERD_FILE);
	config_string_set_static(&config->consumerd32_lib_dir, INSTALL_LIB_PATH);
#elif (CAA_BITS_PER_LONG == 64)
	config_string_set_static(&config->consumerd64_bin_path,
				 INSTALL_BIN_PATH "/" DEFAULT_CONSUMERD_FILE);
	config_string_set_static(&config->consumerd64_lib_dir, INSTALL_LIB_PATH);
#else
#error "Unknown bitness"
#endif
	ret = 0;
	return ret;
error:
	sessiond_config_fini(config);
	return ret;
}

void sessiond_config_fini(struct sessiond_config *config)
{
	config_string_fini(&config->tracing_group_name);
	config_string_fini(&config->kmod_probes_list);
	config_string_fini(&config->kmod_extra_probes_list);
	config_string_fini(&config->rundir);
	config_string_fini(&config->apps_unix_sock_path);
	config_string_fini(&config->client_unix_sock_path);
	config_string_fini(&config->wait_shm.path);
	config_string_fini(&config->health_unix_sock_path);
	config_string_fini(&config->lttng_ust_clock_plugin);
	config_string_fini(&config->pid_file_path);
	config_string_fini(&config->lock_file_path);
	config_string_fini(&config->load_session_path);
	config_string_fini(&config->agent_port_file_path);
	config_string_fini(&config->consumerd32_path);
	config_string_fini(&config->consumerd32_bin_path);
	config_string_fini(&config->consumerd32_lib_dir);
	config_string_fini(&config->consumerd32_err_unix_sock_path);
	config_string_fini(&config->consumerd32_cmd_unix_sock_path);
	config_string_fini(&config->consumerd64_path);
	config_string_fini(&config->consumerd64_bin_path);
	config_string_fini(&config->consumerd64_lib_dir);
	config_string_fini(&config->consumerd64_err_unix_sock_path);
	config_string_fini(&config->consumerd64_cmd_unix_sock_path);
	config_string_fini(&config->kconsumerd_path);
	config_string_fini(&config->kconsumerd_err_unix_sock_path);
	config_string_fini(&config->kconsumerd_cmd_unix_sock_path);
}

static int resolve_path(struct config_string *path)
{
	int ret = 0;
	char *absolute_path;

	if (!path->value || path->value[0] == '/') {
		goto end;
	}

	absolute_path = utils_expand_path(path->value);
	if (!absolute_path) {
		ret = -1;
		goto end;
	}

	config_string_set(path, absolute_path);
end:
	return ret;
}

#define RESOLVE_CHECK(path_config_str)     \
	if (resolve_path(path_config_str)) \
	return -1

int sessiond_config_resolve_paths(struct sessiond_config *config)
{
	RESOLVE_CHECK(&config->apps_unix_sock_path);
	RESOLVE_CHECK(&config->client_unix_sock_path);
	RESOLVE_CHECK(&config->wait_shm.path);
	RESOLVE_CHECK(&config->health_unix_sock_path);
	RESOLVE_CHECK(&config->lttng_ust_clock_plugin);
	RESOLVE_CHECK(&config->pid_file_path);
	RESOLVE_CHECK(&config->lock_file_path);
	RESOLVE_CHECK(&config->load_session_path);
	RESOLVE_CHECK(&config->agent_port_file_path);
	RESOLVE_CHECK(&config->consumerd32_path);
	RESOLVE_CHECK(&config->consumerd32_bin_path);
	RESOLVE_CHECK(&config->consumerd32_lib_dir);
	RESOLVE_CHECK(&config->consumerd32_err_unix_sock_path);
	RESOLVE_CHECK(&config->consumerd32_cmd_unix_sock_path);
	RESOLVE_CHECK(&config->consumerd64_path);
	RESOLVE_CHECK(&config->consumerd64_bin_path);
	RESOLVE_CHECK(&config->consumerd64_lib_dir);
	RESOLVE_CHECK(&config->consumerd64_err_unix_sock_path);
	RESOLVE_CHECK(&config->consumerd64_cmd_unix_sock_path);
	RESOLVE_CHECK(&config->kconsumerd_path);
	RESOLVE_CHECK(&config->kconsumerd_err_unix_sock_path);
	RESOLVE_CHECK(&config->kconsumerd_cmd_unix_sock_path);
	return 0;
}

void sessiond_config_log(struct sessiond_config *config)
{
	DBG_NO_LOC("[sessiond configuration]");
	DBG_NO_LOC("\tversion                        %s", VERSION);
	if (GIT_VERSION[0] != '\0') {
		DBG_NO_LOC("\tgit version                    %s", GIT_VERSION);
	}
	if (EXTRA_VERSION_NAME[0] != '\0') {
		DBG_NO_LOC("\textra version name             %s", EXTRA_VERSION_NAME);
	}
	if (EXTRA_VERSION_DESCRIPTION[0] != '\0') {
		DBG_NO_LOC("\textra version description:\n\t%s", EXTRA_VERSION_DESCRIPTION);
	}
	if (EXTRA_VERSION_PATCHES[0] != '\0') {
		DBG_NO_LOC("\textra version patches:\n\t%s", EXTRA_VERSION_PATCHES);
	}
	DBG_NO_LOC("\tverbose:                       %i", config->verbose);
	DBG_NO_LOC("\tverbose consumer:              %i", config->verbose_consumer);
	DBG_NO_LOC("\tquiet mode:                    %s", config->quiet ? "True" : "False");
	if (config->agent_tcp_port.begin == config->agent_tcp_port.end) {
		DBG_NO_LOC("\tagent_tcp_port:                %i", config->agent_tcp_port.begin);
	} else {
		DBG_NO_LOC("\tagent_tcp_port:                [%i, %i]",
			   config->agent_tcp_port.begin,
			   config->agent_tcp_port.end);
	}
	DBG_NO_LOC("\tapplication socket timeout:    %i", config->app_socket_timeout);
	DBG_NO_LOC("\tno-kernel:                     %s", config->no_kernel ? "True" : "False");
	DBG_NO_LOC("\tbackground:                    %s", config->background ? "True" : "False");
	DBG_NO_LOC("\tdaemonize:                     %s", config->daemonize ? "True" : "False");
	DBG_NO_LOC("\tsignal parent on start:        %s", config->sig_parent ? "True" : "False");
	DBG_NO_LOC("\ttracing group name:            %s",
		   config->tracing_group_name.value ?: "Unknown");
	DBG_NO_LOC("\tkmod_probe_list:               %s", config->kmod_probes_list.value ?: "None");
	DBG_NO_LOC("\tkmod_extra_probe_list:         %s",
		   config->kmod_extra_probes_list.value ?: "None");
	DBG_NO_LOC("\trundir:                        %s", config->rundir.value ?: "Unknown");
	DBG_NO_LOC("\tapplication socket path:       %s",
		   config->apps_unix_sock_path.value ?: "Unknown");
	DBG_NO_LOC("\tclient socket path:            %s",
		   config->client_unix_sock_path.value ?: "Unknown");
	DBG_NO_LOC("\twait shm path:                 %s", config->wait_shm.path.value ?: "Unknown");
	DBG_NO_LOC("\thealth socket path:            %s",
		   config->health_unix_sock_path.value ?: "Unknown");
	DBG_NO_LOC("\tLTTNG_UST_CLOCK_PLUGIN:        %s",
		   config->lttng_ust_clock_plugin.value ?: "None");
	DBG_NO_LOC("\tpid file path:                 %s", config->pid_file_path.value ?: "Unknown");
	DBG_NO_LOC("\tlock file path:                %s",
		   config->lock_file_path.value ?: "Unknown");
	DBG_NO_LOC("\tsession load path:             %s",
		   config->load_session_path.value ?: "None");
	DBG_NO_LOC("\tagent port file path:          %s",
		   config->agent_port_file_path.value ?: "Unknown");
	DBG_NO_LOC("\tconsumerd32 path:              %s",
		   config->consumerd32_path.value ?: "Unknown");
	DBG_NO_LOC("\tconsumerd32 bin path:          %s",
		   config->consumerd32_bin_path.value ?: "Unknown");
	DBG_NO_LOC("\tconsumerd32 lib dir:           %s",
		   config->consumerd32_lib_dir.value ?: "Unknown");
	DBG_NO_LOC("\tconsumerd32 err unix sock path:%s",
		   config->consumerd32_err_unix_sock_path.value ?: "Unknown");
	DBG_NO_LOC("\tconsumerd32 cmd unix sock path:%s",
		   config->consumerd32_cmd_unix_sock_path.value ?: "Unknown");
	DBG_NO_LOC("\tconsumerd64 path:              %s",
		   config->consumerd64_path.value ?: "Unknown");
	DBG_NO_LOC("\tconsumerd64 bin path:          %s",
		   config->consumerd64_bin_path.value ?: "Unknown");
	DBG_NO_LOC("\tconsumerd64 lib dir:           %s",
		   config->consumerd64_lib_dir.value ?: "Unknown");
	DBG_NO_LOC("\tconsumerd64 err unix sock path:%s",
		   config->consumerd64_err_unix_sock_path.value ?: "Unknown");
	DBG_NO_LOC("\tconsumerd64 cmd unix sock path:%s",
		   config->consumerd64_cmd_unix_sock_path.value ?: "Unknown");
	DBG_NO_LOC("\tkconsumerd path:               %s",
		   config->kconsumerd_path.value ?: "Unknown");
	DBG_NO_LOC("\tkconsumerd err unix sock path: %s",
		   config->kconsumerd_err_unix_sock_path.value ?: "Unknown");
	DBG_NO_LOC("\tkconsumerd cmd unix sock path: %s",
		   config->kconsumerd_cmd_unix_sock_path.value ?: "Unknown");
}
