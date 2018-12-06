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

#define _LGPL_SOURCE
#include <getopt.h>
#include <grp.h>
#include <limits.h>
#include <paths.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <urcu/uatomic.h>
#include <unistd.h>
#include <ctype.h>

#include <common/common.h>
#include <common/compat/socket.h>
#include <common/compat/getenv.h>
#include <common/defaults.h>
#include <common/kernel-consumer/kernel-consumer.h>
#include <common/futex.h>
#include <common/relayd/relayd.h>
#include <common/utils.h>
#include <common/daemonize.h>
#include <common/config/session-config.h>
#include <common/dynamic-buffer.h>
#include <lttng/event-internal.h>

#include "lttng-sessiond.h"
#include "buffer-registry.h"
#include "channel.h"
#include "cmd.h"
#include "consumer.h"
#include "context.h"
#include "event.h"
#include "kernel.h"
#include "kernel-consumer.h"
#include "modprobe.h"
#include "shm.h"
#include "ust-ctl.h"
#include "ust-consumer.h"
#include "utils.h"
#include "fd-limit.h"
#include "health-sessiond.h"
#include "testpoint.h"
#include "notify-apps.h"
#include "agent-thread.h"
#include "save.h"
#include "notification-thread.h"
#include "notification-thread-commands.h"
#include "rotation-thread.h"
#include "lttng-syscall.h"
#include "agent.h"
#include "ht-cleanup.h"
#include "sessiond-config.h"
#include "timer.h"
#include "thread.h"
#include "client.h"
#include "dispatch.h"
#include "register.h"
#include "manage-apps.h"
#include "manage-kernel.h"

static const char *help_msg =
#ifdef LTTNG_EMBED_HELP
#include <lttng-sessiond.8.h>
#else
NULL
#endif
;

const char *progname;
static int lockfile_fd = -1;

/* Set to 1 when a SIGUSR1 signal is received. */
static int recv_child_signal;

/* Command line options */
static const struct option long_options[] = {
	{ "client-sock", required_argument, 0, 'c' },
	{ "apps-sock", required_argument, 0, 'a' },
	{ "kconsumerd-cmd-sock", required_argument, 0, '\0' },
	{ "kconsumerd-err-sock", required_argument, 0, '\0' },
	{ "ustconsumerd32-cmd-sock", required_argument, 0, '\0' },
	{ "ustconsumerd32-err-sock", required_argument, 0, '\0' },
	{ "ustconsumerd64-cmd-sock", required_argument, 0, '\0' },
	{ "ustconsumerd64-err-sock", required_argument, 0, '\0' },
	{ "consumerd32-path", required_argument, 0, '\0' },
	{ "consumerd32-libdir", required_argument, 0, '\0' },
	{ "consumerd64-path", required_argument, 0, '\0' },
	{ "consumerd64-libdir", required_argument, 0, '\0' },
	{ "daemonize", no_argument, 0, 'd' },
	{ "background", no_argument, 0, 'b' },
	{ "sig-parent", no_argument, 0, 'S' },
	{ "help", no_argument, 0, 'h' },
	{ "group", required_argument, 0, 'g' },
	{ "version", no_argument, 0, 'V' },
	{ "quiet", no_argument, 0, 'q' },
	{ "verbose", no_argument, 0, 'v' },
	{ "verbose-consumer", no_argument, 0, '\0' },
	{ "no-kernel", no_argument, 0, '\0' },
	{ "pidfile", required_argument, 0, 'p' },
	{ "agent-tcp-port", required_argument, 0, '\0' },
	{ "config", required_argument, 0, 'f' },
	{ "load", required_argument, 0, 'l' },
	{ "kmod-probes", required_argument, 0, '\0' },
	{ "extra-kmod-probes", required_argument, 0, '\0' },
	{ NULL, 0, 0, 0 }
};

/* Command line options to ignore from configuration file */
static const char *config_ignore_options[] = { "help", "version", "config" };

/*
 * This pipe is used to inform the thread managing application communication
 * that a command is queued and ready to be processed.
 */
static int apps_cmd_pipe[2] = { -1, -1 };
static int apps_cmd_notify_pipe[2] = { -1, -1 };

/*
 * UST registration command queue. This queue is tied with a futex and uses a N
 * wakers / 1 waiter implemented and detailed in futex.c/.h
 *
 * The thread_registration_apps and thread_dispatch_ust_registration uses this
 * queue along with the wait/wake scheme. The thread_manage_apps receives down
 * the line new application socket and monitors it for any I/O error or clean
 * close that triggers an unregistration of the application.
 */
static struct ust_cmd_queue ust_cmd_queue;

static const char *module_proc_lttng = "/proc/lttng";

/*
 * Section name to look for in the daemon configuration file.
 */
static const char * const config_section_name = "sessiond";

/* Am I root or not. Set to 1 if the daemon is running as root */
static int is_root;

/*
 * Stop all threads by closing the thread quit pipe.
 */
static void stop_threads(void)
{
	int ret;

	/* Stopping all threads */
	DBG("Terminating all threads");
	ret = sessiond_notify_quit_pipe();
	if (ret < 0) {
		ERR("write error on thread quit pipe");
	}
}

/*
 * Close every consumer sockets.
 */
static void close_consumer_sockets(void)
{
	int ret;

	if (kconsumer_data.err_sock >= 0) {
		ret = close(kconsumer_data.err_sock);
		if (ret < 0) {
			PERROR("kernel consumer err_sock close");
		}
	}
	if (ustconsumer32_data.err_sock >= 0) {
		ret = close(ustconsumer32_data.err_sock);
		if (ret < 0) {
			PERROR("UST consumerd32 err_sock close");
		}
	}
	if (ustconsumer64_data.err_sock >= 0) {
		ret = close(ustconsumer64_data.err_sock);
		if (ret < 0) {
			PERROR("UST consumerd64 err_sock close");
		}
	}
	if (kconsumer_data.cmd_sock >= 0) {
		ret = close(kconsumer_data.cmd_sock);
		if (ret < 0) {
			PERROR("kernel consumer cmd_sock close");
		}
	}
	if (ustconsumer32_data.cmd_sock >= 0) {
		ret = close(ustconsumer32_data.cmd_sock);
		if (ret < 0) {
			PERROR("UST consumerd32 cmd_sock close");
		}
	}
	if (ustconsumer64_data.cmd_sock >= 0) {
		ret = close(ustconsumer64_data.cmd_sock);
		if (ret < 0) {
			PERROR("UST consumerd64 cmd_sock close");
		}
	}
	if (kconsumer_data.channel_monitor_pipe >= 0) {
		ret = close(kconsumer_data.channel_monitor_pipe);
		if (ret < 0) {
			PERROR("kernel consumer channel monitor pipe close");
		}
	}
	if (ustconsumer32_data.channel_monitor_pipe >= 0) {
		ret = close(ustconsumer32_data.channel_monitor_pipe);
		if (ret < 0) {
			PERROR("UST consumerd32 channel monitor pipe close");
		}
	}
	if (ustconsumer64_data.channel_monitor_pipe >= 0) {
		ret = close(ustconsumer64_data.channel_monitor_pipe);
		if (ret < 0) {
			PERROR("UST consumerd64 channel monitor pipe close");
		}
	}
}

/*
 * Wait on consumer process termination.
 *
 * Need to be called with the consumer data lock held or from a context
 * ensuring no concurrent access to data (e.g: cleanup).
 */
static void wait_consumer(struct consumer_data *consumer_data)
{
	pid_t ret;
	int status;

	if (consumer_data->pid <= 0) {
		return;
	}

	DBG("Waiting for complete teardown of consumerd (PID: %d)",
			consumer_data->pid);
	ret = waitpid(consumer_data->pid, &status, 0);
	if (ret == -1) {
		PERROR("consumerd waitpid pid: %d", consumer_data->pid)
	} else	if (!WIFEXITED(status)) {
		ERR("consumerd termination with error: %d",
				WEXITSTATUS(ret));
	}
	consumer_data->pid = 0;
}

/*
 * Cleanup the session daemon's data structures.
 */
static void sessiond_cleanup(void)
{
	int ret;
	struct ltt_session_list *session_list = session_get_list();

	DBG("Cleanup sessiond");

	/*
	 * Close the thread quit pipe. It has already done its job,
	 * since we are now called.
	 */
	sessiond_close_quit_pipe();
	utils_close_pipe(apps_cmd_pipe);
	utils_close_pipe(apps_cmd_notify_pipe);
	utils_close_pipe(kernel_poll_pipe);

	ret = remove(config.pid_file_path.value);
	if (ret < 0) {
		PERROR("remove pidfile %s", config.pid_file_path.value);
	}

	DBG("Removing sessiond and consumerd content of directory %s",
		config.rundir.value);

	/* sessiond */
	DBG("Removing %s", config.pid_file_path.value);
	(void) unlink(config.pid_file_path.value);

	DBG("Removing %s", config.agent_port_file_path.value);
	(void) unlink(config.agent_port_file_path.value);

	/* kconsumerd */
	DBG("Removing %s", kconsumer_data.err_unix_sock_path);
	(void) unlink(kconsumer_data.err_unix_sock_path);

	DBG("Removing directory %s", config.kconsumerd_path.value);
	(void) rmdir(config.kconsumerd_path.value);

	/* ust consumerd 32 */
	DBG("Removing %s", config.consumerd32_err_unix_sock_path.value);
	(void) unlink(config.consumerd32_err_unix_sock_path.value);

	DBG("Removing directory %s", config.consumerd32_path.value);
	(void) rmdir(config.consumerd32_path.value);

	/* ust consumerd 64 */
	DBG("Removing %s", config.consumerd64_err_unix_sock_path.value);
	(void) unlink(config.consumerd64_err_unix_sock_path.value);

	DBG("Removing directory %s", config.consumerd64_path.value);
	(void) rmdir(config.consumerd64_path.value);

	pthread_mutex_destroy(&session_list->lock);

	wait_consumer(&kconsumer_data);
	wait_consumer(&ustconsumer64_data);
	wait_consumer(&ustconsumer32_data);

	DBG("Cleaning up all agent apps");
	agent_app_ht_clean();

	DBG("Closing all UST sockets");
	ust_app_clean_list();
	buffer_reg_destroy_registries();

	if (is_root && !config.no_kernel) {
		DBG2("Closing kernel fd");
		if (kernel_tracer_fd >= 0) {
			ret = close(kernel_tracer_fd);
			if (ret) {
				PERROR("close");
			}
		}
		DBG("Unloading kernel modules");
		modprobe_remove_lttng_all();
		free(syscall_table);
	}

	close_consumer_sockets();

	/*
	 * We do NOT rmdir rundir because there are other processes
	 * using it, for instance lttng-relayd, which can start in
	 * parallel with this teardown.
	 */
}

/*
 * Cleanup the daemon's option data structures.
 */
static void sessiond_cleanup_options(void)
{
	DBG("Cleaning up options");

	sessiond_config_fini(&config);

	run_as_destroy_worker();
}

/*
 * Setup necessary data for kernel tracer action.
 */
static int init_kernel_tracer(void)
{
	int ret;

	/* Modprobe lttng kernel modules */
	ret = modprobe_lttng_control();
	if (ret < 0) {
		goto error;
	}

	/* Open debugfs lttng */
	kernel_tracer_fd = open(module_proc_lttng, O_RDWR);
	if (kernel_tracer_fd < 0) {
		DBG("Failed to open %s", module_proc_lttng);
		goto error_open;
	}

	/* Validate kernel version */
	ret = kernel_validate_version(kernel_tracer_fd, &kernel_tracer_version,
			&kernel_tracer_abi_version);
	if (ret < 0) {
		goto error_version;
	}

	ret = modprobe_lttng_data();
	if (ret < 0) {
		goto error_modules;
	}

	ret = kernel_supports_ring_buffer_snapshot_sample_positions(
			kernel_tracer_fd);
	if (ret < 0) {
		goto error_modules;
	}

	if (ret < 1) {
		WARN("Kernel tracer does not support buffer monitoring. "
			"The monitoring timer of channels in the kernel domain "
			"will be set to 0 (disabled).");
	}

	DBG("Kernel tracer fd %d", kernel_tracer_fd);
	return 0;

error_version:
	modprobe_remove_lttng_control();
	ret = close(kernel_tracer_fd);
	if (ret) {
		PERROR("close");
	}
	kernel_tracer_fd = -1;
	return LTTNG_ERR_KERN_VERSION;

error_modules:
	ret = close(kernel_tracer_fd);
	if (ret) {
		PERROR("close");
	}

error_open:
	modprobe_remove_lttng_control();

error:
	WARN("No kernel tracer available");
	kernel_tracer_fd = -1;
	if (!is_root) {
		return LTTNG_ERR_NEED_ROOT_SESSIOND;
	} else {
		return LTTNG_ERR_KERN_NA;
	}
}

static int string_match(const char *str1, const char *str2)
{
	return (str1 && str2) && !strcmp(str1, str2);
}

/*
 * Take an option from the getopt output and set it in the right variable to be
 * used later.
 *
 * Return 0 on success else a negative value.
 */
static int set_option(int opt, const char *arg, const char *optname)
{
	int ret = 0;

	if (string_match(optname, "client-sock") || opt == 'c') {
		if (!arg || *arg == '\0') {
			ret = -EINVAL;
			goto end;
		}
		if (lttng_is_setuid_setgid()) {
			WARN("Getting '%s' argument from setuid/setgid binary refused for security reasons.",
				"-c, --client-sock");
		} else {
			config_string_set(&config.client_unix_sock_path,
					strdup(arg));
			if (!config.client_unix_sock_path.value) {
				ret = -ENOMEM;
				PERROR("strdup");
			}
		}
	} else if (string_match(optname, "apps-sock") || opt == 'a') {
		if (!arg || *arg == '\0') {
			ret = -EINVAL;
			goto end;
		}
		if (lttng_is_setuid_setgid()) {
			WARN("Getting '%s' argument from setuid/setgid binary refused for security reasons.",
				"-a, --apps-sock");
		} else {
			config_string_set(&config.apps_unix_sock_path,
					strdup(arg));
			if (!config.apps_unix_sock_path.value) {
				ret = -ENOMEM;
				PERROR("strdup");
			}
		}
	} else if (string_match(optname, "daemonize") || opt == 'd') {
		config.daemonize = true;
	} else if (string_match(optname, "background") || opt == 'b') {
		config.background = true;
	} else if (string_match(optname, "group") || opt == 'g') {
		if (!arg || *arg == '\0') {
			ret = -EINVAL;
			goto end;
		}
		if (lttng_is_setuid_setgid()) {
			WARN("Getting '%s' argument from setuid/setgid binary refused for security reasons.",
				"-g, --group");
		} else {
			config_string_set(&config.tracing_group_name,
					strdup(arg));
			if (!config.tracing_group_name.value) {
				ret = -ENOMEM;
				PERROR("strdup");
			}
		}
	} else if (string_match(optname, "help") || opt == 'h') {
		ret = utils_show_help(8, "lttng-sessiond", help_msg);
		if (ret) {
			ERR("Cannot show --help for `lttng-sessiond`");
			perror("exec");
		}
		exit(ret ? EXIT_FAILURE : EXIT_SUCCESS);
	} else if (string_match(optname, "version") || opt == 'V') {
		fprintf(stdout, "%s\n", VERSION);
		exit(EXIT_SUCCESS);
	} else if (string_match(optname, "sig-parent") || opt == 'S') {
		config.sig_parent = true;
	} else if (string_match(optname, "kconsumerd-err-sock")) {
		if (!arg || *arg == '\0') {
			ret = -EINVAL;
			goto end;
		}
		if (lttng_is_setuid_setgid()) {
			WARN("Getting '%s' argument from setuid/setgid binary refused for security reasons.",
				"--kconsumerd-err-sock");
		} else {
			config_string_set(&config.kconsumerd_err_unix_sock_path,
					strdup(arg));
			if (!config.kconsumerd_err_unix_sock_path.value) {
				ret = -ENOMEM;
				PERROR("strdup");
			}
		}
	} else if (string_match(optname, "kconsumerd-cmd-sock")) {
		if (!arg || *arg == '\0') {
			ret = -EINVAL;
			goto end;
		}
		if (lttng_is_setuid_setgid()) {
			WARN("Getting '%s' argument from setuid/setgid binary refused for security reasons.",
				"--kconsumerd-cmd-sock");
		} else {
			config_string_set(&config.kconsumerd_cmd_unix_sock_path,
					strdup(arg));
			if (!config.kconsumerd_cmd_unix_sock_path.value) {
				ret = -ENOMEM;
				PERROR("strdup");
			}
		}
	} else if (string_match(optname, "ustconsumerd64-err-sock")) {
		if (!arg || *arg == '\0') {
			ret = -EINVAL;
			goto end;
		}
		if (lttng_is_setuid_setgid()) {
			WARN("Getting '%s' argument from setuid/setgid binary refused for security reasons.",
				"--ustconsumerd64-err-sock");
		} else {
			config_string_set(&config.consumerd64_err_unix_sock_path,
					strdup(arg));
			if (!config.consumerd64_err_unix_sock_path.value) {
				ret = -ENOMEM;
				PERROR("strdup");
			}
		}
	} else if (string_match(optname, "ustconsumerd64-cmd-sock")) {
		if (!arg || *arg == '\0') {
			ret = -EINVAL;
			goto end;
		}
		if (lttng_is_setuid_setgid()) {
			WARN("Getting '%s' argument from setuid/setgid binary refused for security reasons.",
				"--ustconsumerd64-cmd-sock");
		} else {
			config_string_set(&config.consumerd64_cmd_unix_sock_path,
					strdup(arg));
			if (!config.consumerd64_cmd_unix_sock_path.value) {
				ret = -ENOMEM;
				PERROR("strdup");
			}
		}
	} else if (string_match(optname, "ustconsumerd32-err-sock")) {
		if (!arg || *arg == '\0') {
			ret = -EINVAL;
			goto end;
		}
		if (lttng_is_setuid_setgid()) {
			WARN("Getting '%s' argument from setuid/setgid binary refused for security reasons.",
				"--ustconsumerd32-err-sock");
		} else {
			config_string_set(&config.consumerd32_err_unix_sock_path,
					strdup(arg));
			if (!config.consumerd32_err_unix_sock_path.value) {
				ret = -ENOMEM;
				PERROR("strdup");
			}
		}
	} else if (string_match(optname, "ustconsumerd32-cmd-sock")) {
		if (!arg || *arg == '\0') {
			ret = -EINVAL;
			goto end;
		}
		if (lttng_is_setuid_setgid()) {
			WARN("Getting '%s' argument from setuid/setgid binary refused for security reasons.",
				"--ustconsumerd32-cmd-sock");
		} else {
			config_string_set(&config.consumerd32_cmd_unix_sock_path,
					strdup(arg));
			if (!config.consumerd32_cmd_unix_sock_path.value) {
				ret = -ENOMEM;
				PERROR("strdup");
			}
		}
	} else if (string_match(optname, "no-kernel")) {
		config.no_kernel = true;
	} else if (string_match(optname, "quiet") || opt == 'q') {
		config.quiet = true;
	} else if (string_match(optname, "verbose") || opt == 'v') {
		/* Verbose level can increase using multiple -v */
		if (arg) {
			/* Value obtained from config file */
			config.verbose = config_parse_value(arg);
		} else {
			/* -v used on command line */
			config.verbose++;
		}
		/* Clamp value to [0, 3] */
		config.verbose = config.verbose < 0 ? 0 :
			(config.verbose <= 3 ? config.verbose : 3);
	} else if (string_match(optname, "verbose-consumer")) {
		if (arg) {
			config.verbose_consumer = config_parse_value(arg);
		} else {
			config.verbose_consumer++;
		}
	} else if (string_match(optname, "consumerd32-path")) {
		if (!arg || *arg == '\0') {
			ret = -EINVAL;
			goto end;
		}
		if (lttng_is_setuid_setgid()) {
			WARN("Getting '%s' argument from setuid/setgid binary refused for security reasons.",
				"--consumerd32-path");
		} else {
			config_string_set(&config.consumerd32_bin_path,
					strdup(arg));
			if (!config.consumerd32_bin_path.value) {
				PERROR("strdup");
				ret = -ENOMEM;
			}
		}
	} else if (string_match(optname, "consumerd32-libdir")) {
		if (!arg || *arg == '\0') {
			ret = -EINVAL;
			goto end;
		}
		if (lttng_is_setuid_setgid()) {
			WARN("Getting '%s' argument from setuid/setgid binary refused for security reasons.",
				"--consumerd32-libdir");
		} else {
			config_string_set(&config.consumerd32_lib_dir,
					strdup(arg));
			if (!config.consumerd32_lib_dir.value) {
				PERROR("strdup");
				ret = -ENOMEM;
			}
		}
	} else if (string_match(optname, "consumerd64-path")) {
		if (!arg || *arg == '\0') {
			ret = -EINVAL;
			goto end;
		}
		if (lttng_is_setuid_setgid()) {
			WARN("Getting '%s' argument from setuid/setgid binary refused for security reasons.",
				"--consumerd64-path");
		} else {
			config_string_set(&config.consumerd64_bin_path,
					strdup(arg));
			if (!config.consumerd64_bin_path.value) {
				PERROR("strdup");
				ret = -ENOMEM;
			}
		}
	} else if (string_match(optname, "consumerd64-libdir")) {
		if (!arg || *arg == '\0') {
			ret = -EINVAL;
			goto end;
		}
		if (lttng_is_setuid_setgid()) {
			WARN("Getting '%s' argument from setuid/setgid binary refused for security reasons.",
				"--consumerd64-libdir");
		} else {
			config_string_set(&config.consumerd64_lib_dir,
					strdup(arg));
			if (!config.consumerd64_lib_dir.value) {
				PERROR("strdup");
				ret = -ENOMEM;
			}
		}
	} else if (string_match(optname, "pidfile") || opt == 'p') {
		if (!arg || *arg == '\0') {
			ret = -EINVAL;
			goto end;
		}
		if (lttng_is_setuid_setgid()) {
			WARN("Getting '%s' argument from setuid/setgid binary refused for security reasons.",
				"-p, --pidfile");
		} else {
			config_string_set(&config.pid_file_path, strdup(arg));
			if (!config.pid_file_path.value) {
				PERROR("strdup");
				ret = -ENOMEM;
			}
		}
	} else if (string_match(optname, "agent-tcp-port")) {
		if (!arg || *arg == '\0') {
			ret = -EINVAL;
			goto end;
		}
		if (lttng_is_setuid_setgid()) {
			WARN("Getting '%s' argument from setuid/setgid binary refused for security reasons.",
				"--agent-tcp-port");
		} else {
			unsigned long v;

			errno = 0;
			v = strtoul(arg, NULL, 0);
			if (errno != 0 || !isdigit(arg[0])) {
				ERR("Wrong value in --agent-tcp-port parameter: %s", arg);
				return -1;
			}
			if (v == 0 || v >= 65535) {
				ERR("Port overflow in --agent-tcp-port parameter: %s", arg);
				return -1;
			}
			config.agent_tcp_port.begin = config.agent_tcp_port.end = (int) v;
			DBG3("Agent TCP port set to non default: %i", (int) v);
		}
	} else if (string_match(optname, "load") || opt == 'l') {
		if (!arg || *arg == '\0') {
			ret = -EINVAL;
			goto end;
		}
		if (lttng_is_setuid_setgid()) {
			WARN("Getting '%s' argument from setuid/setgid binary refused for security reasons.",
				"-l, --load");
		} else {
		        config_string_set(&config.load_session_path, strdup(arg));
			if (!config.load_session_path.value) {
				PERROR("strdup");
				ret = -ENOMEM;
			}
		}
	} else if (string_match(optname, "kmod-probes")) {
		if (!arg || *arg == '\0') {
			ret = -EINVAL;
			goto end;
		}
		if (lttng_is_setuid_setgid()) {
			WARN("Getting '%s' argument from setuid/setgid binary refused for security reasons.",
				"--kmod-probes");
		} else {
			config_string_set(&config.kmod_probes_list, strdup(arg));
			if (!config.kmod_probes_list.value) {
				PERROR("strdup");
				ret = -ENOMEM;
			}
		}
	} else if (string_match(optname, "extra-kmod-probes")) {
		if (!arg || *arg == '\0') {
			ret = -EINVAL;
			goto end;
		}
		if (lttng_is_setuid_setgid()) {
			WARN("Getting '%s' argument from setuid/setgid binary refused for security reasons.",
				"--extra-kmod-probes");
		} else {
			config_string_set(&config.kmod_extra_probes_list,
					strdup(arg));
			if (!config.kmod_extra_probes_list.value) {
				PERROR("strdup");
				ret = -ENOMEM;
			}
		}
	} else if (string_match(optname, "config") || opt == 'f') {
		/* This is handled in set_options() thus silent skip. */
		goto end;
	} else {
		/* Unknown option or other error.
		 * Error is printed by getopt, just return */
		ret = -1;
	}

end:
	if (ret == -EINVAL) {
		const char *opt_name = "unknown";
		int i;

		for (i = 0; i < sizeof(long_options) / sizeof(struct option);
			i++) {
			if (opt == long_options[i].val) {
				opt_name = long_options[i].name;
				break;
			}
		}

		WARN("Invalid argument provided for option \"%s\", using default value.",
			opt_name);
	}

	return ret;
}

/*
 * config_entry_handler_cb used to handle options read from a config file.
 * See config_entry_handler_cb comment in common/config/session-config.h for the
 * return value conventions.
 */
static int config_entry_handler(const struct config_entry *entry, void *unused)
{
	int ret = 0, i;

	if (!entry || !entry->name || !entry->value) {
		ret = -EINVAL;
		goto end;
	}

	/* Check if the option is to be ignored */
	for (i = 0; i < sizeof(config_ignore_options) / sizeof(char *); i++) {
		if (!strcmp(entry->name, config_ignore_options[i])) {
			goto end;
		}
	}

	for (i = 0; i < (sizeof(long_options) / sizeof(struct option)) - 1;
		i++) {

		/* Ignore if not fully matched. */
		if (strcmp(entry->name, long_options[i].name)) {
			continue;
		}

		/*
		 * If the option takes no argument on the command line, we have to
		 * check if the value is "true". We support non-zero numeric values,
		 * true, on and yes.
		 */
		if (!long_options[i].has_arg) {
			ret = config_parse_value(entry->value);
			if (ret <= 0) {
				if (ret) {
					WARN("Invalid configuration value \"%s\" for option %s",
							entry->value, entry->name);
				}
				/* False, skip boolean config option. */
				goto end;
			}
		}

		ret = set_option(long_options[i].val, entry->value, entry->name);
		goto end;
	}

	WARN("Unrecognized option \"%s\" in daemon configuration file.", entry->name);

end:
	return ret;
}

/*
 * daemon configuration loading and argument parsing
 */
static int set_options(int argc, char **argv)
{
	int ret = 0, c = 0, option_index = 0;
	int orig_optopt = optopt, orig_optind = optind;
	char *optstring;
	const char *config_path = NULL;

	optstring = utils_generate_optstring(long_options,
			sizeof(long_options) / sizeof(struct option));
	if (!optstring) {
		ret = -ENOMEM;
		goto end;
	}

	/* Check for the --config option */
	while ((c = getopt_long(argc, argv, optstring, long_options,
					&option_index)) != -1) {
		if (c == '?') {
			ret = -EINVAL;
			goto end;
		} else if (c != 'f') {
			/* if not equal to --config option. */
			continue;
		}

		if (lttng_is_setuid_setgid()) {
			WARN("Getting '%s' argument from setuid/setgid binary refused for security reasons.",
				"-f, --config");
		} else {
			config_path = utils_expand_path(optarg);
			if (!config_path) {
				ERR("Failed to resolve path: %s", optarg);
			}
		}
	}

	ret = config_get_section_entries(config_path, config_section_name,
			config_entry_handler, NULL);
	if (ret) {
		if (ret > 0) {
			ERR("Invalid configuration option at line %i", ret);
			ret = -1;
		}
		goto end;
	}

	/* Reset getopt's global state */
	optopt = orig_optopt;
	optind = orig_optind;
	while (1) {
		option_index = -1;
		/*
		 * getopt_long() will not set option_index if it encounters a
		 * short option.
		 */
		c = getopt_long(argc, argv, optstring, long_options,
				&option_index);
		if (c == -1) {
			break;
		}

		/*
		 * Pass NULL as the long option name if popt left the index
		 * unset.
		 */
		ret = set_option(c, optarg,
				option_index < 0 ? NULL :
				long_options[option_index].name);
		if (ret < 0) {
			break;
		}
	}

end:
	free(optstring);
	return ret;
}

/*
 * Create lockfile using the rundir and return its fd.
 */
static int create_lockfile(void)
{
        return utils_create_lock_file(config.lock_file_path.value);
}

/*
 * Check if the global socket is available, and if a daemon is answering at the
 * other side. If yes, error is returned.
 *
 * Also attempts to create and hold the lock file.
 */
static int check_existing_daemon(void)
{
	int ret = 0;

	/* Is there anybody out there ? */
	if (lttng_session_daemon_alive()) {
		ret = -EEXIST;
		goto end;
	}

	lockfile_fd = create_lockfile();
	if (lockfile_fd < 0) {
		ret = -EEXIST;
		goto end;
	}
end:
	return ret;
}

static void sessiond_cleanup_lock_file(void)
{
	int ret;

	/*
	 * Cleanup lock file by deleting it and finaly closing it which will
	 * release the file system lock.
	 */
	if (lockfile_fd >= 0) {
		ret = remove(config.lock_file_path.value);
		if (ret < 0) {
			PERROR("remove lock file");
		}
		ret = close(lockfile_fd);
		if (ret < 0) {
			PERROR("close lock file");
		}
	}
}

/*
 * Set the tracing group gid onto the client socket.
 *
 * Race window between mkdir and chown is OK because we are going from more
 * permissive (root.root) to less permissive (root.tracing).
 */
static int set_permissions(char *rundir)
{
	int ret;
	gid_t gid;

	gid = utils_get_group_id(config.tracing_group_name.value);

	/* Set lttng run dir */
	ret = chown(rundir, 0, gid);
	if (ret < 0) {
		ERR("Unable to set group on %s", rundir);
		PERROR("chown");
	}

	/*
	 * Ensure all applications and tracing group can search the run
	 * dir. Allow everyone to read the directory, since it does not
	 * buy us anything to hide its content.
	 */
	ret = chmod(rundir, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
	if (ret < 0) {
		ERR("Unable to set permissions on %s", rundir);
		PERROR("chmod");
	}

	/* lttng client socket path */
	ret = chown(config.client_unix_sock_path.value, 0, gid);
	if (ret < 0) {
		ERR("Unable to set group on %s", config.client_unix_sock_path.value);
		PERROR("chown");
	}

	/* kconsumer error socket path */
	ret = chown(kconsumer_data.err_unix_sock_path, 0, 0);
	if (ret < 0) {
		ERR("Unable to set group on %s", kconsumer_data.err_unix_sock_path);
		PERROR("chown");
	}

	/* 64-bit ustconsumer error socket path */
	ret = chown(ustconsumer64_data.err_unix_sock_path, 0, 0);
	if (ret < 0) {
		ERR("Unable to set group on %s", ustconsumer64_data.err_unix_sock_path);
		PERROR("chown");
	}

	/* 32-bit ustconsumer compat32 error socket path */
	ret = chown(ustconsumer32_data.err_unix_sock_path, 0, 0);
	if (ret < 0) {
		ERR("Unable to set group on %s", ustconsumer32_data.err_unix_sock_path);
		PERROR("chown");
	}

	DBG("All permissions are set");

	return ret;
}

/*
 * Create the lttng run directory needed for all global sockets and pipe.
 */
static int create_lttng_rundir(void)
{
	int ret;

	DBG3("Creating LTTng run directory: %s", config.rundir.value);

	ret = mkdir(config.rundir.value, S_IRWXU);
	if (ret < 0) {
		if (errno != EEXIST) {
			ERR("Unable to create %s", config.rundir.value);
			goto error;
		} else {
			ret = 0;
		}
	}

error:
	return ret;
}

/*
 * Setup sockets and directory needed by the consumerds' communication with the
 * session daemon.
 */
static int set_consumer_sockets(struct consumer_data *consumer_data)
{
	int ret;
	char *path = NULL;

	switch (consumer_data->type) {
	case LTTNG_CONSUMER_KERNEL:
		path = config.kconsumerd_path.value;
		break;
	case LTTNG_CONSUMER64_UST:
		path = config.consumerd64_path.value;
		break;
	case LTTNG_CONSUMER32_UST:
		path = config.consumerd32_path.value;
		break;
	default:
		ERR("Consumer type unknown");
		ret = -EINVAL;
		goto error;
	}
	assert(path);

	DBG2("Creating consumer directory: %s", path);

	ret = mkdir(path, S_IRWXU | S_IRGRP | S_IXGRP);
	if (ret < 0 && errno != EEXIST) {
		PERROR("mkdir");
		ERR("Failed to create %s", path);
		goto error;
	}
	if (is_root) {
		ret = chown(path, 0, utils_get_group_id(config.tracing_group_name.value));
		if (ret < 0) {
			ERR("Unable to set group on %s", path);
			PERROR("chown");
			goto error;
		}
	}

	/* Create the consumerd error unix socket */
	consumer_data->err_sock =
		lttcomm_create_unix_sock(consumer_data->err_unix_sock_path);
	if (consumer_data->err_sock < 0) {
		ERR("Create unix sock failed: %s", consumer_data->err_unix_sock_path);
		ret = -1;
		goto error;
	}

	/*
	 * Set the CLOEXEC flag. Return code is useless because either way, the
	 * show must go on.
	 */
	ret = utils_set_fd_cloexec(consumer_data->err_sock);
	if (ret < 0) {
		PERROR("utils_set_fd_cloexec");
		/* continue anyway */
	}

	/* File permission MUST be 660 */
	ret = chmod(consumer_data->err_unix_sock_path,
			S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
	if (ret < 0) {
		ERR("Set file permissions failed: %s", consumer_data->err_unix_sock_path);
		PERROR("chmod");
		goto error;
	}

error:
	return ret;
}

/*
 * Signal handler for the daemon
 *
 * Simply stop all worker threads, leaving main() return gracefully after
 * joining all threads and calling cleanup().
 */
static void sighandler(int sig)
{
	switch (sig) {
	case SIGINT:
		DBG("SIGINT caught");
		stop_threads();
		break;
	case SIGTERM:
		DBG("SIGTERM caught");
		stop_threads();
		break;
	case SIGUSR1:
		CMM_STORE_SHARED(recv_child_signal, 1);
		break;
	default:
		break;
	}
}

/*
 * Setup signal handler for :
 *		SIGINT, SIGTERM, SIGPIPE
 */
static int set_signal_handler(void)
{
	int ret = 0;
	struct sigaction sa;
	sigset_t sigset;

	if ((ret = sigemptyset(&sigset)) < 0) {
		PERROR("sigemptyset");
		return ret;
	}

	sa.sa_mask = sigset;
	sa.sa_flags = 0;

	sa.sa_handler = sighandler;
	if ((ret = sigaction(SIGTERM, &sa, NULL)) < 0) {
		PERROR("sigaction");
		return ret;
	}

	if ((ret = sigaction(SIGINT, &sa, NULL)) < 0) {
		PERROR("sigaction");
		return ret;
	}

	if ((ret = sigaction(SIGUSR1, &sa, NULL)) < 0) {
		PERROR("sigaction");
		return ret;
	}

	sa.sa_handler = SIG_IGN;
	if ((ret = sigaction(SIGPIPE, &sa, NULL)) < 0) {
		PERROR("sigaction");
		return ret;
	}

	DBG("Signal handler set for SIGTERM, SIGUSR1, SIGPIPE and SIGINT");

	return ret;
}

/*
 * Set open files limit to unlimited. This daemon can open a large number of
 * file descriptors in order to consume multiple kernel traces.
 */
static void set_ulimit(void)
{
	int ret;
	struct rlimit lim;

	/* The kernel does not allow an infinite limit for open files */
	lim.rlim_cur = 65535;
	lim.rlim_max = 65535;

	ret = setrlimit(RLIMIT_NOFILE, &lim);
	if (ret < 0) {
		PERROR("failed to set open files limit");
	}
}

static int write_pidfile(void)
{
        return utils_create_pid_file(getpid(), config.pid_file_path.value);
}

static int set_clock_plugin_env(void)
{
	int ret = 0;
	char *env_value = NULL;

	if (!config.lttng_ust_clock_plugin.value) {
		goto end;
	}

        ret = asprintf(&env_value, "LTTNG_UST_CLOCK_PLUGIN=%s",
			config.lttng_ust_clock_plugin.value);
	if (ret < 0) {
		PERROR("asprintf");
		goto end;
	}

	ret = putenv(env_value);
	if (ret) {
		free(env_value);
		PERROR("putenv of LTTNG_UST_CLOCK_PLUGIN");
		goto end;
	}

	DBG("Updated LTTNG_UST_CLOCK_PLUGIN environment variable to \"%s\"",
			config.lttng_ust_clock_plugin.value);
end:
	return ret;
}

static void destroy_all_sessions_and_wait(void)
{
	struct ltt_session *session, *tmp;
	struct ltt_session_list *session_list;

	session_list = session_get_list();
	DBG("Initiating destruction of all sessions");

	if (!session_list) {
		return;
	}

	session_lock_list();
	/* Initiate the destruction of all sessions. */
	cds_list_for_each_entry_safe(session, tmp,
			&session_list->head, list) {
		if (!session_get(session)) {
			continue;
		}

		session_lock(session);
		if (session->destroyed) {
			goto unlock_session;
		}
		(void) cmd_stop_trace(session);
		(void) cmd_destroy_session(session,
				notification_thread_handle);
	unlock_session:
		session_unlock(session);
		session_put(session);
	}
	session_unlock_list();

	/* Wait for the destruction of all sessions to complete. */
	DBG("Waiting for the destruction of all sessions to complete");
	session_list_wait_empty();
	DBG("Destruction of all sessions completed");
}

/*
 * main
 */
int main(int argc, char **argv)
{
	int ret = 0, retval = 0;
	const char *env_app_timeout;
	struct lttng_pipe *ust32_channel_monitor_pipe = NULL,
			*ust64_channel_monitor_pipe = NULL,
			*kernel_channel_monitor_pipe = NULL;
	struct lttng_thread *ht_cleanup_thread = NULL;
	struct timer_thread_parameters timer_thread_parameters;
	/* Rotation thread handle. */
	struct rotation_thread_handle *rotation_thread_handle = NULL;
	/* Queue of rotation jobs populated by the sessiond-timer. */
	struct rotation_thread_timer_queue *rotation_timer_queue = NULL;
	struct lttng_thread *client_thread = NULL;
	struct lttng_thread *notification_thread = NULL;

	init_kernel_workarounds();

	rcu_register_thread();

	if (set_signal_handler()) {
		retval = -1;
		goto exit_set_signal_handler;
	}

	if (timer_signal_init()) {
		retval = -1;
		goto exit_set_signal_handler;
	}

	page_size = sysconf(_SC_PAGESIZE);
	if (page_size < 0) {
		PERROR("sysconf _SC_PAGESIZE");
		page_size = LONG_MAX;
		WARN("Fallback page size to %ld", page_size);
	}

	ret = sessiond_config_init(&config);
	if (ret) {
		retval = -1;
		goto exit_set_signal_handler;
	}

	/*
	 * Init config from environment variables.
	 * Command line option override env configuration per-doc. Do env first.
	 */
	sessiond_config_apply_env_config(&config);

	/*
	 * Parse arguments and load the daemon configuration file.
	 *
	 * We have an exit_options exit path to free memory reserved by
	 * set_options. This is needed because the rest of sessiond_cleanup()
	 * depends on ht_cleanup_thread, which depends on lttng_daemonize, which
	 * depends on set_options.
	 */
	progname = argv[0];
	if (set_options(argc, argv)) {
		retval = -1;
		goto exit_options;
	}

	/*
	 * Resolve all paths received as arguments, configuration option, or
	 * through environment variable as absolute paths. This is necessary
	 * since daemonizing causes the sessiond's current working directory
	 * to '/'.
	 */
	ret = sessiond_config_resolve_paths(&config);
	if (ret) {
		goto exit_options;
	}

	/* Apply config. */
	lttng_opt_verbose = config.verbose;
	lttng_opt_quiet = config.quiet;
	kconsumer_data.err_unix_sock_path =
			config.kconsumerd_err_unix_sock_path.value;
	kconsumer_data.cmd_unix_sock_path =
			config.kconsumerd_cmd_unix_sock_path.value;
	ustconsumer32_data.err_unix_sock_path =
			config.consumerd32_err_unix_sock_path.value;
	ustconsumer32_data.cmd_unix_sock_path =
			config.consumerd32_cmd_unix_sock_path.value;
	ustconsumer64_data.err_unix_sock_path =
			config.consumerd64_err_unix_sock_path.value;
	ustconsumer64_data.cmd_unix_sock_path =
			config.consumerd64_cmd_unix_sock_path.value;
	set_clock_plugin_env();

	sessiond_config_log(&config);

	if (create_lttng_rundir()) {
		retval = -1;
		goto exit_options;
	}

	/* Abort launch if a session daemon is already running. */
	if (check_existing_daemon()) {
		ERR("A session daemon is already running.");
		retval = -1;
		goto exit_options;
	}

	/* Daemonize */
	if (config.daemonize || config.background) {
		int i;

		ret = lttng_daemonize(&child_ppid, &recv_child_signal,
			!config.background);
		if (ret < 0) {
			retval = -1;
			goto exit_options;
		}

		/*
		 * We are in the child. Make sure all other file descriptors are
		 * closed, in case we are called with more opened file
		 * descriptors than the standard ones and the lock file.
		 */
		for (i = 3; i < sysconf(_SC_OPEN_MAX); i++) {
			if (i == lockfile_fd) {
				continue;
			}
			(void) close(i);
		}
	}

	if (run_as_create_worker(argv[0]) < 0) {
		goto exit_create_run_as_worker_cleanup;
	}

	/*
	 * Starting from here, we can create threads. This needs to be after
	 * lttng_daemonize due to RCU.
	 */

	/*
	 * Initialize the health check subsystem. This call should set the
	 * appropriate time values.
	 */
	health_sessiond = health_app_create(NR_HEALTH_SESSIOND_TYPES);
	if (!health_sessiond) {
		PERROR("health_app_create error");
		retval = -1;
		goto exit_health_sessiond_cleanup;
	}

	/* Create thread to clean up RCU hash tables */
	ht_cleanup_thread = launch_ht_cleanup_thread();
	if (!ht_cleanup_thread) {
		retval = -1;
		goto exit_ht_cleanup;
	}

	/* Create thread quit pipe */
	if (sessiond_init_thread_quit_pipe()) {
		retval = -1;
		goto exit_init_data;
	}

	/* Check if daemon is UID = 0 */
	is_root = !getuid();
	if (is_root) {
		/* Create global run dir with root access */

		kernel_channel_monitor_pipe = lttng_pipe_open(0);
		if (!kernel_channel_monitor_pipe) {
			ERR("Failed to create kernel consumer channel monitor pipe");
			retval = -1;
			goto exit_init_data;
		}
		kconsumer_data.channel_monitor_pipe =
				lttng_pipe_release_writefd(
					kernel_channel_monitor_pipe);
		if (kconsumer_data.channel_monitor_pipe < 0) {
			retval = -1;
			goto exit_init_data;
		}
	}

	/* Set consumer initial state */
	kernel_consumerd_state = CONSUMER_STOPPED;
	ust_consumerd_state = CONSUMER_STOPPED;

	ust32_channel_monitor_pipe = lttng_pipe_open(0);
	if (!ust32_channel_monitor_pipe) {
		ERR("Failed to create 32-bit user space consumer channel monitor pipe");
		retval = -1;
		goto exit_init_data;
	}
	ustconsumer32_data.channel_monitor_pipe = lttng_pipe_release_writefd(
			ust32_channel_monitor_pipe);
	if (ustconsumer32_data.channel_monitor_pipe < 0) {
		retval = -1;
		goto exit_init_data;
	}

	/*
	 * The rotation_thread_timer_queue structure is shared between the
	 * sessiond timer thread and the rotation thread. The main thread keeps
	 * its ownership and destroys it when both threads have been joined.
	 */
	rotation_timer_queue = rotation_thread_timer_queue_create();
	if (!rotation_timer_queue) {
		retval = -1;
		goto exit_init_data;
	}
	timer_thread_parameters.rotation_thread_job_queue =
			rotation_timer_queue;

	ust64_channel_monitor_pipe = lttng_pipe_open(0);
	if (!ust64_channel_monitor_pipe) {
		ERR("Failed to create 64-bit user space consumer channel monitor pipe");
		retval = -1;
		goto exit_init_data;
	}
	ustconsumer64_data.channel_monitor_pipe = lttng_pipe_release_writefd(
			ust64_channel_monitor_pipe);
	if (ustconsumer64_data.channel_monitor_pipe < 0) {
		retval = -1;
		goto exit_init_data;
	}

	/*
	 * Init UST app hash table. Alloc hash table before this point since
	 * cleanup() can get called after that point.
	 */
	if (ust_app_ht_alloc()) {
		ERR("Failed to allocate UST app hash table");
		retval = -1;
		goto exit_init_data;
	}

	/*
	 * Initialize agent app hash table. We allocate the hash table here
	 * since cleanup() can get called after this point.
	 */
	if (agent_app_ht_alloc()) {
		ERR("Failed to allocate Agent app hash table");
		retval = -1;
		goto exit_init_data;
	}

	/*
	 * These actions must be executed as root. We do that *after* setting up
	 * the sockets path because we MUST make the check for another daemon using
	 * those paths *before* trying to set the kernel consumer sockets and init
	 * kernel tracer.
	 */
	if (is_root) {
		if (set_consumer_sockets(&kconsumer_data)) {
			retval = -1;
			goto exit_init_data;
		}

		/* Setup kernel tracer */
		if (!config.no_kernel) {
			init_kernel_tracer();
			if (kernel_tracer_fd >= 0) {
				ret = syscall_init_table();
				if (ret < 0) {
					ERR("Unable to populate syscall table. "
						"Syscall tracing won't work "
						"for this session daemon.");
				}
			}
		}

		/* Set ulimit for open files */
		set_ulimit();
	}
	/* init lttng_fd tracking must be done after set_ulimit. */
	lttng_fd_init();

	if (set_consumer_sockets(&ustconsumer64_data)) {
		retval = -1;
		goto exit_init_data;
	}

	if (set_consumer_sockets(&ustconsumer32_data)) {
		retval = -1;
		goto exit_init_data;
	}

	/* Set credentials to socket */
	if (is_root && set_permissions(config.rundir.value)) {
		retval = -1;
		goto exit_init_data;
	}

	/* Get parent pid if -S, --sig-parent is specified. */
	if (config.sig_parent) {
		ppid = getppid();
	}

	/* Setup the kernel pipe for waking up the kernel thread */
	if (is_root && !config.no_kernel) {
		if (utils_create_pipe_cloexec(kernel_poll_pipe)) {
			retval = -1;
			goto exit_init_data;
		}
	}

	/* Setup the thread apps communication pipe. */
	if (utils_create_pipe_cloexec(apps_cmd_pipe)) {
		retval = -1;
		goto exit_init_data;
	}

	/* Setup the thread apps notify communication pipe. */
	if (utils_create_pipe_cloexec(apps_cmd_notify_pipe)) {
		retval = -1;
		goto exit_init_data;
	}

	/* Initialize global buffer per UID and PID registry. */
	buffer_reg_init_uid_registry();
	buffer_reg_init_pid_registry();

	/* Init UST command queue. */
	cds_wfcq_init(&ust_cmd_queue.head, &ust_cmd_queue.tail);

	cmd_init();

	/* Check for the application socket timeout env variable. */
	env_app_timeout = getenv(DEFAULT_APP_SOCKET_TIMEOUT_ENV);
	if (env_app_timeout) {
		config.app_socket_timeout = atoi(env_app_timeout);
	} else {
		config.app_socket_timeout = DEFAULT_APP_SOCKET_RW_TIMEOUT;
	}

	ret = write_pidfile();
	if (ret) {
		ERR("Error in write_pidfile");
		retval = -1;
		goto exit_init_data;
	}

	/* Initialize communication library */
	lttcomm_init();
	/* Initialize TCP timeout values */
	lttcomm_inet_init();

	/* Create health-check thread. */
	if (!launch_health_management_thread()) {
		retval = -1;
		goto exit_health;
	}

	/* notification_thread_data acquires the pipes' read side. */
	notification_thread_handle = notification_thread_handle_create(
			ust32_channel_monitor_pipe,
			ust64_channel_monitor_pipe,
			kernel_channel_monitor_pipe);
	if (!notification_thread_handle) {
		retval = -1;
		ERR("Failed to create notification thread shared data");
		goto exit_notification;
	}

	/* Create notification thread. */
	notification_thread = launch_notification_thread(
			notification_thread_handle);
	if (!notification_thread) {
		retval = -1;
		goto exit_notification;
	}

	/* Create timer thread. */
	if (!launch_timer_thread(&timer_thread_parameters)) {
		retval = -1;
		goto exit_notification;
	}

	/* rotation_thread_data acquires the pipes' read side. */
	rotation_thread_handle = rotation_thread_handle_create(
			rotation_timer_queue,
			notification_thread_handle);
	if (!rotation_thread_handle) {
		retval = -1;
		ERR("Failed to create rotation thread shared data");
		stop_threads();
		goto exit_rotation;
	}

	/* Create rotation thread. */
	if (!launch_rotation_thread(rotation_thread_handle)) {
		retval = -1;
		goto exit_rotation;
	}

	/* Create thread to manage the client socket */
	client_thread = launch_client_thread();
	if (!client_thread) {
		retval = -1;
		goto exit_client;
	}

	if (!launch_ust_dispatch_thread(&ust_cmd_queue, apps_cmd_pipe[1],
			apps_cmd_notify_pipe[1])) {
		retval = -1;
		goto exit_dispatch;
	}

	/* Create thread to manage application registration. */
	if (!launch_application_registration_thread(&ust_cmd_queue)) {
		retval = -1;
		goto exit_reg_apps;
	}

	/* Create thread to manage application socket */
	if (!launch_application_management_thread(apps_cmd_pipe[0])) {
		retval = -1;
		goto exit_apps;
	}

	/* Create thread to manage application notify socket */
	if (!launch_application_notification_thread(apps_cmd_notify_pipe[0])) {
		retval = -1;
		goto exit_apps_notify;
	}

	/* Create agent management thread. */
	if (!launch_agent_management_thread()) {
		retval = -1;
		goto exit_agent_reg;
	}

	/* Don't start this thread if kernel tracing is not requested nor root */
	if (is_root && !config.no_kernel) {
		/* Create kernel thread to manage kernel event */
		if (!launch_kernel_management_thread(kernel_poll_pipe[0])) {
			retval = -1;
			goto exit_kernel;
		}
	}

	/* Load sessions. */
	ret = config_load_session(config.load_session_path.value,
			NULL, 1, 1, NULL);
	if (ret) {
		ERR("Session load failed: %s", error_get_str(ret));
		retval = -1;
		goto exit_load_session;
	}

	/* Initialization completed. */
	sessiond_signal_parents();

	/*
	 * This is where we start awaiting program completion (e.g. through
	 * signal that asks threads to teardown).
	 */

	/* Initiate teardown once activity occurs on the quit pipe. */
	sessiond_wait_for_quit_pipe(-1U);

	/*
	 * Ensure that the client thread is no longer accepting new commands,
	 * which could cause new sessions to be created.
	 */
	if (!lttng_thread_shutdown(client_thread)) {
		ERR("Failed to shutdown the client thread, continuing teardown");
		lttng_thread_put(client_thread);
		client_thread = NULL;
	}

	destroy_all_sessions_and_wait();
exit_load_session:
exit_kernel:
exit_agent_reg:
exit_apps_notify:
exit_apps:
exit_reg_apps:
exit_dispatch:
exit_client:
exit_rotation:
exit_notification:
	lttng_thread_list_shutdown_orphans();
exit_health:
exit_init_data:
	if (client_thread) {
		lttng_thread_put(client_thread);
	}

	/*
	 * Wait for all pending call_rcu work to complete before tearing
	 * down data structures. call_rcu worker may be trying to
	 * perform lookups in those structures.
	 */
	rcu_barrier();
	/*
	 * sessiond_cleanup() is called when no other thread is running, except
	 * the ht_cleanup thread, which is needed to destroy the hash tables.
	 */
	rcu_thread_online();
	sessiond_cleanup();

	if (notification_thread) {
		lttng_thread_shutdown(notification_thread);
		lttng_thread_put(notification_thread);
	}

	/*
	 * Ensure all prior call_rcu are done. call_rcu callbacks may push
	 * hash tables to the ht_cleanup thread. Therefore, we ensure that
	 * the queue is empty before shutting down the clean-up thread.
	 */
	rcu_barrier();

	if (ht_cleanup_thread) {
		lttng_thread_shutdown(ht_cleanup_thread);
		lttng_thread_put(ht_cleanup_thread);
	}

	rcu_thread_offline();
	rcu_unregister_thread();

	if (rotation_thread_handle) {
		rotation_thread_handle_destroy(rotation_thread_handle);
	}

	/*
	 * After the rotation and timer thread have quit, we can safely destroy
	 * the rotation_timer_queue.
	 */
	rotation_thread_timer_queue_destroy(rotation_timer_queue);
	/*
	 * The teardown of the notification system is performed after the
	 * session daemon's teardown in order to allow it to be notified
	 * of the active session and channels at the moment of the teardown.
	 */
	if (notification_thread_handle) {
		notification_thread_handle_destroy(notification_thread_handle);
	}
	lttng_pipe_destroy(ust32_channel_monitor_pipe);
	lttng_pipe_destroy(ust64_channel_monitor_pipe);
	lttng_pipe_destroy(kernel_channel_monitor_pipe);
exit_ht_cleanup:

	health_app_destroy(health_sessiond);
exit_health_sessiond_cleanup:
exit_create_run_as_worker_cleanup:

exit_options:
	sessiond_cleanup_lock_file();
	sessiond_cleanup_options();

exit_set_signal_handler:
	if (!retval) {
		exit(EXIT_SUCCESS);
	} else {
		exit(EXIT_FAILURE);
	}
}
