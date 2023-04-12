/*
 * Copyright (C) 2011 EfficiOS Inc.
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright (C) 2013 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include "agent-thread.hpp"
#include "agent.hpp"
#include "buffer-registry.hpp"
#include "channel.hpp"
#include "client.hpp"
#include "cmd.hpp"
#include "consumer.hpp"
#include "context.hpp"
#include "dispatch.hpp"
#include "event-notifier-error-accounting.hpp"
#include "event.hpp"
#include "fd-limit.hpp"
#include "health-sessiond.hpp"
#include "kernel-consumer.hpp"
#include "kernel.hpp"
#include "lttng-sessiond.hpp"
#include "lttng-ust-ctl.hpp"
#include "manage-apps.hpp"
#include "manage-kernel.hpp"
#include "modprobe.hpp"
#include "notification-thread-commands.hpp"
#include "notification-thread.hpp"
#include "notify-apps.hpp"
#include "register.hpp"
#include "rotation-thread.hpp"
#include "save.hpp"
#include "sessiond-config.hpp"
#include "testpoint.hpp"
#include "thread.hpp"
#include "timer.hpp"
#include "ust-consumer.hpp"
#include "ust-sigbus.hpp"
#include "utils.hpp"

#include <common/common.hpp>
#include <common/compat/getenv.hpp>
#include <common/compat/socket.hpp>
#include <common/config/session-config.hpp>
#include <common/daemonize.hpp>
#include <common/defaults.hpp>
#include <common/dynamic-buffer.hpp>
#include <common/futex.hpp>
#include <common/ini-config/ini-config.hpp>
#include <common/kernel-consumer/kernel-consumer.hpp>
#include <common/logging-utils.hpp>
#include <common/path.hpp>
#include <common/relayd/relayd.hpp>
#include <common/utils.hpp>

#include <lttng/event-internal.hpp>

#include <ctype.h>
#include <getopt.h>
#include <grp.h>
#include <inttypes.h>
#include <limits.h>
#include <paths.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <urcu/uatomic.h>

static const char *help_msg =
#ifdef LTTNG_EMBED_HELP
#include <lttng-sessiond.8.h>
#else
	nullptr
#endif
	;

#define EVENT_NOTIFIER_ERROR_COUNTER_NUMBER_OF_BUCKET_MAX 65535
#define EVENT_NOTIFIER_ERROR_BUFFER_SIZE_BASE_OPTION_STR  "event-notifier-error-buffer-size"
#define EVENT_NOTIFIER_ERROR_BUFFER_SIZE_KERNEL_OPTION_STR \
	EVENT_NOTIFIER_ERROR_BUFFER_SIZE_BASE_OPTION_STR "-kernel"
#define EVENT_NOTIFIER_ERROR_BUFFER_SIZE_USERSPACE_OPTION_STR \
	EVENT_NOTIFIER_ERROR_BUFFER_SIZE_BASE_OPTION_STR "-userspace"

const char *progname;
static int lockfile_fd = -1;
static int opt_print_version;

/* Set to 1 when a SIGUSR1 signal is received. */
static int recv_child_signal;

/* Command line options */
static const struct option long_options[] = {
	{ "client-sock", required_argument, nullptr, 'c' },
	{ "apps-sock", required_argument, nullptr, 'a' },
	{ "kconsumerd-cmd-sock", required_argument, nullptr, '\0' },
	{ "kconsumerd-err-sock", required_argument, nullptr, '\0' },
	{ "ustconsumerd32-cmd-sock", required_argument, nullptr, '\0' },
	{ "ustconsumerd32-err-sock", required_argument, nullptr, '\0' },
	{ "ustconsumerd64-cmd-sock", required_argument, nullptr, '\0' },
	{ "ustconsumerd64-err-sock", required_argument, nullptr, '\0' },
	{ "consumerd32-path", required_argument, nullptr, '\0' },
	{ "consumerd32-libdir", required_argument, nullptr, '\0' },
	{ "consumerd64-path", required_argument, nullptr, '\0' },
	{ "consumerd64-libdir", required_argument, nullptr, '\0' },
	{ "daemonize", no_argument, nullptr, 'd' },
	{ "background", no_argument, nullptr, 'b' },
	{ "sig-parent", no_argument, nullptr, 'S' },
	{ "help", no_argument, nullptr, 'h' },
	{ "group", required_argument, nullptr, 'g' },
	{ "version", no_argument, nullptr, 'V' },
	{ "quiet", no_argument, nullptr, 'q' },
	{ "verbose", no_argument, nullptr, 'v' },
	{ "verbose-consumer", no_argument, nullptr, '\0' },
	{ "no-kernel", no_argument, nullptr, '\0' },
	{ "pidfile", required_argument, nullptr, 'p' },
	{ "agent-tcp-port", required_argument, nullptr, '\0' },
	{ "config", required_argument, nullptr, 'f' },
	{ "load", required_argument, nullptr, 'l' },
	{ "kmod-probes", required_argument, nullptr, '\0' },
	{ "extra-kmod-probes", required_argument, nullptr, '\0' },
	{ EVENT_NOTIFIER_ERROR_BUFFER_SIZE_KERNEL_OPTION_STR, required_argument, nullptr, '\0' },
	{ EVENT_NOTIFIER_ERROR_BUFFER_SIZE_USERSPACE_OPTION_STR, required_argument, nullptr, '\0' },
	{ nullptr, 0, nullptr, 0 }
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

/*
 * Section name to look for in the daemon configuration file.
 */
static const char *const config_section_name = "sessiond";

/* Am I root or not. Set to 1 if the daemon is running as root */
static int is_root;

/*
 * Notify the main thread to initiate the teardown of the worker threads by
 * writing to the main quit pipe.
 */
static void notify_main_quit_pipe()
{
	int ret;

	/* Stopping all threads */
	DBG("Notify the main thread to terminate all worker threads");
	ret = sessiond_notify_main_quit_pipe();
	if (ret < 0) {
		ERR("write error on main quit pipe");
	}
}

/*
 * Close every consumer sockets.
 */
static void close_consumer_sockets()
{
	int ret;

	if (the_kconsumer_data.err_sock >= 0) {
		ret = close(the_kconsumer_data.err_sock);
		if (ret < 0) {
			PERROR("kernel consumer err_sock close");
		}
	}
	if (the_ustconsumer32_data.err_sock >= 0) {
		ret = close(the_ustconsumer32_data.err_sock);
		if (ret < 0) {
			PERROR("UST consumerd32 err_sock close");
		}
	}
	if (the_ustconsumer64_data.err_sock >= 0) {
		ret = close(the_ustconsumer64_data.err_sock);
		if (ret < 0) {
			PERROR("UST consumerd64 err_sock close");
		}
	}
	if (the_kconsumer_data.cmd_sock >= 0) {
		ret = close(the_kconsumer_data.cmd_sock);
		if (ret < 0) {
			PERROR("kernel consumer cmd_sock close");
		}
	}
	if (the_ustconsumer32_data.cmd_sock >= 0) {
		ret = close(the_ustconsumer32_data.cmd_sock);
		if (ret < 0) {
			PERROR("UST consumerd32 cmd_sock close");
		}
	}
	if (the_ustconsumer64_data.cmd_sock >= 0) {
		ret = close(the_ustconsumer64_data.cmd_sock);
		if (ret < 0) {
			PERROR("UST consumerd64 cmd_sock close");
		}
	}
	if (the_kconsumer_data.channel_monitor_pipe >= 0) {
		ret = close(the_kconsumer_data.channel_monitor_pipe);
		if (ret < 0) {
			PERROR("kernel consumer channel monitor pipe close");
		}
	}
	if (the_ustconsumer32_data.channel_monitor_pipe >= 0) {
		ret = close(the_ustconsumer32_data.channel_monitor_pipe);
		if (ret < 0) {
			PERROR("UST consumerd32 channel monitor pipe close");
		}
	}
	if (the_ustconsumer64_data.channel_monitor_pipe >= 0) {
		ret = close(the_ustconsumer64_data.channel_monitor_pipe);
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

	DBG("Waiting for complete teardown of consumerd (PID: %d)", consumer_data->pid);
	ret = waitpid(consumer_data->pid, &status, 0);
	if (ret == -1) {
		PERROR("consumerd waitpid pid: %d", consumer_data->pid)
	} else if (!WIFEXITED(status)) {
		ERR("consumerd termination with error: %d", WEXITSTATUS(ret));
	}
	consumer_data->pid = 0;
}

/*
 * Cleanup the session daemon's data structures.
 */
static void sessiond_cleanup()
{
	int ret;
	struct ltt_session_list *session_list = session_get_list();

	DBG("Cleanup sessiond");

	/*
	 * Close the main quit pipe. It has already done its job, since we are
	 * now cleaning up.
	 */
	sessiond_close_main_quit_pipe();

	/* Close all other pipes. */
	utils_close_pipe(apps_cmd_pipe);
	utils_close_pipe(apps_cmd_notify_pipe);
	utils_close_pipe(the_kernel_poll_pipe);

	ret = remove(the_config.pid_file_path.value);
	if (ret < 0) {
		PERROR("remove pidfile %s", the_config.pid_file_path.value);
	}

	DBG("Removing sessiond and consumerd content of directory %s", the_config.rundir.value);

	/* sessiond */
	DBG("Removing %s", the_config.pid_file_path.value);
	(void) unlink(the_config.pid_file_path.value);

	DBG("Removing %s", the_config.agent_port_file_path.value);
	(void) unlink(the_config.agent_port_file_path.value);

	/* kconsumerd */
	DBG("Removing %s", the_kconsumer_data.err_unix_sock_path);
	(void) unlink(the_kconsumer_data.err_unix_sock_path);

	DBG("Removing directory %s", the_config.kconsumerd_path.value);
	(void) rmdir(the_config.kconsumerd_path.value);

	/* ust consumerd 32 */
	DBG("Removing %s", the_config.consumerd32_err_unix_sock_path.value);
	(void) unlink(the_config.consumerd32_err_unix_sock_path.value);

	DBG("Removing directory %s", the_config.consumerd32_path.value);
	(void) rmdir(the_config.consumerd32_path.value);

	/* ust consumerd 64 */
	DBG("Removing %s", the_config.consumerd64_err_unix_sock_path.value);
	(void) unlink(the_config.consumerd64_err_unix_sock_path.value);

	DBG("Removing directory %s", the_config.consumerd64_path.value);
	(void) rmdir(the_config.consumerd64_path.value);

	pthread_mutex_destroy(&session_list->lock);

	DBG("Cleaning up all per-event notifier domain agents");
	agent_by_event_notifier_domain_ht_destroy();

	DBG("Cleaning up all agent apps");
	agent_app_ht_clean();
	DBG("Closing all UST sockets");
	ust_app_clean_list();
	buffer_reg_destroy_registries();

	close_consumer_sockets();

	wait_consumer(&the_kconsumer_data);
	wait_consumer(&the_ustconsumer64_data);
	wait_consumer(&the_ustconsumer32_data);

	if (is_root && !the_config.no_kernel) {
		cleanup_kernel_tracer();
	}

	/*
	 * We do NOT rmdir rundir because there are other processes
	 * using it, for instance lttng-relayd, which can start in
	 * parallel with this teardown.
	 */
}

/*
 * Cleanup the daemon's option data structures.
 */
static void sessiond_cleanup_options()
{
	DBG("Cleaning up options");

	sessiond_config_fini(&the_config);

	run_as_destroy_worker();
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
			config_string_set(&the_config.client_unix_sock_path, strdup(arg));
			if (!the_config.client_unix_sock_path.value) {
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
			config_string_set(&the_config.apps_unix_sock_path, strdup(arg));
			if (!the_config.apps_unix_sock_path.value) {
				ret = -ENOMEM;
				PERROR("strdup");
			}
		}
	} else if (string_match(optname, "daemonize") || opt == 'd') {
		the_config.daemonize = true;
	} else if (string_match(optname, "background") || opt == 'b') {
		the_config.background = true;
	} else if (string_match(optname, "group") || opt == 'g') {
		if (!arg || *arg == '\0') {
			ret = -EINVAL;
			goto end;
		}
		if (lttng_is_setuid_setgid()) {
			WARN("Getting '%s' argument from setuid/setgid binary refused for security reasons.",
			     "-g, --group");
		} else {
			config_string_set(&the_config.tracing_group_name, strdup(arg));
			if (!the_config.tracing_group_name.value) {
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
		opt_print_version = 1;
	} else if (string_match(optname, "sig-parent") || opt == 'S') {
		the_config.sig_parent = true;
	} else if (string_match(optname, "kconsumerd-err-sock")) {
		if (!arg || *arg == '\0') {
			ret = -EINVAL;
			goto end;
		}
		if (lttng_is_setuid_setgid()) {
			WARN("Getting '%s' argument from setuid/setgid binary refused for security reasons.",
			     "--kconsumerd-err-sock");
		} else {
			config_string_set(&the_config.kconsumerd_err_unix_sock_path, strdup(arg));
			if (!the_config.kconsumerd_err_unix_sock_path.value) {
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
			config_string_set(&the_config.kconsumerd_cmd_unix_sock_path, strdup(arg));
			if (!the_config.kconsumerd_cmd_unix_sock_path.value) {
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
			config_string_set(&the_config.consumerd64_err_unix_sock_path, strdup(arg));
			if (!the_config.consumerd64_err_unix_sock_path.value) {
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
			config_string_set(&the_config.consumerd64_cmd_unix_sock_path, strdup(arg));
			if (!the_config.consumerd64_cmd_unix_sock_path.value) {
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
			config_string_set(&the_config.consumerd32_err_unix_sock_path, strdup(arg));
			if (!the_config.consumerd32_err_unix_sock_path.value) {
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
			config_string_set(&the_config.consumerd32_cmd_unix_sock_path, strdup(arg));
			if (!the_config.consumerd32_cmd_unix_sock_path.value) {
				ret = -ENOMEM;
				PERROR("strdup");
			}
		}
	} else if (string_match(optname, "no-kernel")) {
		the_config.no_kernel = true;
	} else if (string_match(optname, "quiet") || opt == 'q') {
		the_config.quiet = true;
	} else if (string_match(optname, "verbose") || opt == 'v') {
		/* Verbose level can increase using multiple -v */
		if (arg) {
			/* Value obtained from config file */
			the_config.verbose = config_parse_value(arg);
		} else {
			/* -v used on command line */
			the_config.verbose++;
		}
		/* Clamp value to [0, 3] */
		the_config.verbose = the_config.verbose < 0 ?
			0 :
			(the_config.verbose <= 3 ? the_config.verbose : 3);
	} else if (string_match(optname, "verbose-consumer")) {
		if (arg) {
			the_config.verbose_consumer = config_parse_value(arg);
		} else {
			the_config.verbose_consumer++;
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
			config_string_set(&the_config.consumerd32_bin_path, strdup(arg));
			if (!the_config.consumerd32_bin_path.value) {
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
			config_string_set(&the_config.consumerd32_lib_dir, strdup(arg));
			if (!the_config.consumerd32_lib_dir.value) {
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
			config_string_set(&the_config.consumerd64_bin_path, strdup(arg));
			if (!the_config.consumerd64_bin_path.value) {
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
			config_string_set(&the_config.consumerd64_lib_dir, strdup(arg));
			if (!the_config.consumerd64_lib_dir.value) {
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
			config_string_set(&the_config.pid_file_path, strdup(arg));
			if (!the_config.pid_file_path.value) {
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
			v = strtoul(arg, nullptr, 0);
			if (errno != 0 || !isdigit(arg[0])) {
				ERR("Wrong value in --agent-tcp-port parameter: %s", arg);
				return -1;
			}
			if (v == 0 || v >= 65535) {
				ERR("Port overflow in --agent-tcp-port parameter: %s", arg);
				return -1;
			}
			the_config.agent_tcp_port.begin = the_config.agent_tcp_port.end = (int) v;
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
			config_string_set(&the_config.load_session_path, strdup(arg));
			if (!the_config.load_session_path.value) {
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
			config_string_set(&the_config.kmod_probes_list, strdup(arg));
			if (!the_config.kmod_probes_list.value) {
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
			config_string_set(&the_config.kmod_extra_probes_list, strdup(arg));
			if (!the_config.kmod_extra_probes_list.value) {
				PERROR("strdup");
				ret = -ENOMEM;
			}
		}
	} else if (string_match(optname, EVENT_NOTIFIER_ERROR_BUFFER_SIZE_KERNEL_OPTION_STR)) {
		unsigned long v;

		errno = 0;
		v = strtoul(arg, nullptr, 0);
		if (errno != 0 || !isdigit(arg[0])) {
			ERR("Wrong value in --%s parameter: %s",
			    EVENT_NOTIFIER_ERROR_BUFFER_SIZE_KERNEL_OPTION_STR,
			    arg);
			return -1;
		}
		if (v == 0 || v >= EVENT_NOTIFIER_ERROR_COUNTER_NUMBER_OF_BUCKET_MAX) {
			ERR("Value out of range for --%s parameter: %s",
			    EVENT_NOTIFIER_ERROR_BUFFER_SIZE_KERNEL_OPTION_STR,
			    arg);
			return -1;
		}
		the_config.event_notifier_buffer_size_kernel = (int) v;
		DBG3("Number of event notifier error buffer kernel size to non default: %i",
		     the_config.event_notifier_buffer_size_kernel);
		goto end;
	} else if (string_match(optname, EVENT_NOTIFIER_ERROR_BUFFER_SIZE_USERSPACE_OPTION_STR)) {
		unsigned long v;

		errno = 0;
		v = strtoul(arg, nullptr, 0);
		if (errno != 0 || !isdigit(arg[0])) {
			ERR("Wrong value in --%s parameter: %s",
			    EVENT_NOTIFIER_ERROR_BUFFER_SIZE_USERSPACE_OPTION_STR,
			    arg);
			return -1;
		}
		if (v == 0 || v >= EVENT_NOTIFIER_ERROR_COUNTER_NUMBER_OF_BUCKET_MAX) {
			ERR("Value out of range for --%s parameter: %s",
			    EVENT_NOTIFIER_ERROR_BUFFER_SIZE_USERSPACE_OPTION_STR,
			    arg);
			return -1;
		}
		the_config.event_notifier_buffer_size_userspace = (int) v;
		DBG3("Number of event notifier error buffer userspace size to non default: %i",
		     the_config.event_notifier_buffer_size_userspace);
		goto end;
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

		for (i = 0; i < sizeof(long_options) / sizeof(struct option); i++) {
			if (opt == long_options[i].val) {
				opt_name = long_options[i].name;
				break;
			}
		}

		WARN("Invalid argument provided for option \"%s\", using default value.", opt_name);
	}

	return ret;
}

/*
 * config_entry_handler_cb used to handle options read from a config file.
 * See config_entry_handler_cb comment in common/config/session-config.h for the
 * return value conventions.
 */
static int config_entry_handler(const struct config_entry *entry,
				void *unused __attribute__((unused)))
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

	for (i = 0; i < (sizeof(long_options) / sizeof(struct option)) - 1; i++) {
		/* Ignore if not fully matched. */
		if (strcmp(entry->name, long_options[i].name) != 0) {
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
					     entry->value,
					     entry->name);
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

static void print_version()
{
	fprintf(stdout, "%s\n", VERSION);
}

/*
 * daemon configuration loading and argument parsing
 */
static int set_options(int argc, char **argv)
{
	int ret = 0, c = 0, option_index = 0;
	int orig_optopt = optopt, orig_optind = optind;
	char *optstring;
	char *config_path = nullptr;

	optstring = utils_generate_optstring(long_options,
					     sizeof(long_options) / sizeof(struct option));
	if (!optstring) {
		ret = -ENOMEM;
		goto end;
	}

	/* Check for the --config option */
	while ((c = getopt_long(argc, argv, optstring, long_options, &option_index)) != -1) {
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
			free(config_path);
			config_path = utils_expand_path(optarg);
			if (!config_path) {
				ERR("Failed to resolve path: %s", optarg);
			}
		}
	}

	ret = config_get_section_entries(
		config_path, config_section_name, config_entry_handler, nullptr);
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
	while (true) {
		option_index = -1;
		/*
		 * getopt_long() will not set option_index if it encounters a
		 * short option.
		 */
		c = getopt_long(argc, argv, optstring, long_options, &option_index);
		if (c == -1) {
			break;
		}

		/*
		 * Pass NULL as the long option name if popt left the index
		 * unset.
		 */
		ret = set_option(
			c, optarg, option_index < 0 ? nullptr : long_options[option_index].name);
		if (ret < 0) {
			break;
		}
	}

end:
	free(config_path);
	free(optstring);
	return ret;
}

/*
 * Create lockfile using the rundir and return its fd.
 */
static int create_lockfile()
{
	return utils_create_lock_file(the_config.lock_file_path.value);
}

/*
 * Check if the global socket is available, and if a daemon is answering at the
 * other side. If yes, error is returned.
 *
 * Also attempts to create and hold the lock file.
 */
static int check_existing_daemon()
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

static void sessiond_cleanup_lock_file()
{
	int ret;

	/*
	 * Cleanup lock file by deleting it and finaly closing it which will
	 * release the file system lock.
	 */
	if (lockfile_fd >= 0) {
		ret = remove(the_config.lock_file_path.value);
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

	ret = utils_get_group_id(the_config.tracing_group_name.value, true, &gid);
	if (ret) {
		/* Default to root group. */
		gid = 0;
	}

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
	ret = chown(the_config.client_unix_sock_path.value, 0, gid);
	if (ret < 0) {
		ERR("Unable to set group on %s", the_config.client_unix_sock_path.value);
		PERROR("chown");
	}

	/* kconsumer error socket path */
	ret = chown(the_kconsumer_data.err_unix_sock_path, 0, 0);
	if (ret < 0) {
		ERR("Unable to set group on %s", the_kconsumer_data.err_unix_sock_path);
		PERROR("chown");
	}

	/* 64-bit ustconsumer error socket path */
	ret = chown(the_ustconsumer64_data.err_unix_sock_path, 0, 0);
	if (ret < 0) {
		ERR("Unable to set group on %s", the_ustconsumer64_data.err_unix_sock_path);
		PERROR("chown");
	}

	/* 32-bit ustconsumer compat32 error socket path */
	ret = chown(the_ustconsumer32_data.err_unix_sock_path, 0, 0);
	if (ret < 0) {
		ERR("Unable to set group on %s", the_ustconsumer32_data.err_unix_sock_path);
		PERROR("chown");
	}

	DBG("All permissions are set");

	return ret;
}

/*
 * Create the lttng run directory needed for all global sockets and pipe.
 */
static int create_lttng_rundir()
{
	int ret;

	DBG3("Creating LTTng run directory: %s", the_config.rundir.value);

	ret = mkdir(the_config.rundir.value, S_IRWXU);
	if (ret < 0) {
		if (errno != EEXIST) {
			ERR("Unable to create %s", the_config.rundir.value);
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
	char *path = nullptr;

	switch (consumer_data->type) {
	case LTTNG_CONSUMER_KERNEL:
		path = the_config.kconsumerd_path.value;
		break;
	case LTTNG_CONSUMER64_UST:
		path = the_config.consumerd64_path.value;
		break;
	case LTTNG_CONSUMER32_UST:
		path = the_config.consumerd32_path.value;
		break;
	default:
		ERR("Consumer type unknown");
		ret = -EINVAL;
		goto error;
	}
	LTTNG_ASSERT(path);

	DBG2("Creating consumer directory: %s", path);

	ret = mkdir(path, S_IRWXU | S_IRGRP | S_IXGRP);
	if (ret < 0 && errno != EEXIST) {
		PERROR("mkdir");
		ERR("Failed to create %s", path);
		goto error;
	}
	if (is_root) {
		gid_t gid;

		ret = utils_get_group_id(the_config.tracing_group_name.value, true, &gid);
		if (ret) {
			/* Default to root group. */
			gid = 0;
		}

		ret = chown(path, 0, gid);
		if (ret < 0) {
			ERR("Unable to set group on %s", path);
			PERROR("chown");
			goto error;
		}
	}

	/* Create the consumerd error unix socket */
	consumer_data->err_sock = lttcomm_create_unix_sock(consumer_data->err_unix_sock_path);
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
	ret = chmod(consumer_data->err_unix_sock_path, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
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
static void sighandler(int sig, siginfo_t *siginfo, void *arg __attribute__((unused)))
{
	switch (sig) {
	case SIGINT:
		DBG("SIGINT caught");
		notify_main_quit_pipe();
		break;
	case SIGTERM:
		DBG("SIGTERM caught");
		notify_main_quit_pipe();
		break;
	case SIGUSR1:
		CMM_STORE_SHARED(recv_child_signal, 1);
		break;
	case SIGBUS:
	{
		int write_ret;
		const char msg[] = "Received SIGBUS, aborting program.\n";

		lttng_ust_handle_sigbus(siginfo->si_addr);
		/*
		 * If ustctl did not catch this signal (triggering a
		 * siglongjmp), abort the program. Otherwise, the execution
		 * will resume from the ust-ctl call which caused this error.
		 *
		 * The return value is ignored since the program aborts anyhow.
		 */
		write_ret = write(STDERR_FILENO, msg, sizeof(msg));
		(void) write_ret;
		abort();
	}
	default:
		break;
	}
}

/*
 * Setup signal handler for :
 *		SIGINT, SIGTERM, SIGPIPE
 */
static int set_signal_handler()
{
	int ret = 0;
	struct sigaction sa;
	sigset_t sigset;

	if ((ret = sigemptyset(&sigset)) < 0) {
		PERROR("sigemptyset");
		return ret;
	}

	sa.sa_mask = sigset;
	sa.sa_flags = SA_SIGINFO;

	sa.sa_sigaction = sighandler;
	if ((ret = sigaction(SIGTERM, &sa, nullptr)) < 0) {
		PERROR("sigaction");
		return ret;
	}

	if ((ret = sigaction(SIGINT, &sa, nullptr)) < 0) {
		PERROR("sigaction");
		return ret;
	}

	if ((ret = sigaction(SIGUSR1, &sa, nullptr)) < 0) {
		PERROR("sigaction");
		return ret;
	}

	if ((ret = sigaction(SIGBUS, &sa, nullptr)) < 0) {
		PERROR("sigaction");
		return ret;
	}

	sa.sa_flags = 0;
	sa.sa_handler = SIG_IGN;
	if ((ret = sigaction(SIGPIPE, &sa, nullptr)) < 0) {
		PERROR("sigaction");
		return ret;
	}

	DBG("Signal handler set for SIGTERM, SIGUSR1, SIGPIPE, SIGINT, and SIGBUS");

	return ret;
}

/*
 * Set open files limit to unlimited. This daemon can open a large number of
 * file descriptors in order to consume multiple kernel traces.
 */
static void set_ulimit()
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

static int write_pidfile()
{
	return utils_create_pid_file(getpid(), the_config.pid_file_path.value);
}

static int set_clock_plugin_env()
{
	int ret = 0;
	char *env_value = nullptr;

	if (!the_config.lttng_ust_clock_plugin.value) {
		goto end;
	}

	ret = asprintf(
		&env_value, "LTTNG_UST_CLOCK_PLUGIN=%s", the_config.lttng_ust_clock_plugin.value);
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
	    the_config.lttng_ust_clock_plugin.value);
end:
	return ret;
}

static void destroy_all_sessions_and_wait()
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
	cds_list_for_each_entry_safe (session, tmp, &session_list->head, list) {
		if (!session_get(session)) {
			continue;
		}

		session_lock(session);
		if (session->destroyed) {
			goto unlock_session;
		}
		(void) cmd_stop_trace(session);
		(void) cmd_destroy_session(session, nullptr);
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

static void unregister_all_triggers()
{
	enum lttng_error_code ret_code;
	enum lttng_trigger_status trigger_status;
	struct lttng_triggers *triggers = nullptr;
	unsigned int trigger_count, i;
	const struct lttng_credentials creds = {
		.uid = LTTNG_OPTIONAL_INIT_VALUE(0),
		.gid = LTTNG_OPTIONAL_INIT_UNSET,
	};

	DBG("Unregistering all triggers");

	/*
	 * List all triggers as "root" since we wish to unregister all triggers.
	 */
	ret_code = notification_thread_command_list_triggers(
		the_notification_thread_handle, creds.uid.value, &triggers);
	if (ret_code != LTTNG_OK) {
		ERR("Failed to list triggers while unregistering all triggers");
		goto end;
	}

	trigger_status = lttng_triggers_get_count(triggers, &trigger_count);
	LTTNG_ASSERT(trigger_status == LTTNG_TRIGGER_STATUS_OK);

	for (i = 0; i < trigger_count; i++) {
		uid_t trigger_owner;
		const char *trigger_name;
		const struct lttng_trigger *trigger = lttng_triggers_get_at_index(triggers, i);

		LTTNG_ASSERT(trigger);

		trigger_status = lttng_trigger_get_owner_uid(trigger, &trigger_owner);
		LTTNG_ASSERT(trigger_status == LTTNG_TRIGGER_STATUS_OK);

		trigger_status = lttng_trigger_get_name(trigger, &trigger_name);
		trigger_name = trigger_status == LTTNG_TRIGGER_STATUS_OK ? trigger_name :
									   "(anonymous)";

		DBG("Unregistering trigger: trigger owner uid = %d, trigger name = '%s'",
		    (int) trigger_owner,
		    trigger_name);

		ret_code = cmd_unregister_trigger(&creds, trigger, the_notification_thread_handle);
		if (ret_code != LTTNG_OK) {
			ERR("Failed to unregister trigger: trigger owner uid = %d, trigger name = '%s', error: '%s'",
			    (int) trigger_owner,
			    trigger_name,
			    lttng_strerror(-ret_code));
			/* Continue to unregister the remaining triggers. */
		}
	}
end:
	lttng_triggers_destroy(triggers);
}

static int run_as_worker_post_fork_cleanup(void *data)
{
	struct sessiond_config *sessiond_config = (struct sessiond_config *) data;

	sessiond_config_fini(sessiond_config);
	return 0;
}

static int launch_run_as_worker(const char *procname)
{
	/*
	 * Clean-up before forking the run-as worker. Any dynamically
	 * allocated memory of which the worker is not aware will
	 * be leaked as the process forks a run-as worker (and performs
	 * no exec*()). The same would apply to any opened fd.
	 */
	return run_as_create_worker(procname, run_as_worker_post_fork_cleanup, &the_config);
}

static void sessiond_uuid_log()
{
	char uuid_str[LTTNG_UUID_STR_LEN];

	lttng_uuid_to_str(the_sessiond_uuid, uuid_str);
	DBG("Starting lttng-sessiond {%s}", uuid_str);
}

/*
 * main
 */
int main(int argc, char **argv)
{
	int ret = 0, retval = 0;
	const char *env_app_timeout;
	struct lttng_pipe *ust32_channel_monitor_pipe = nullptr,
			  *ust64_channel_monitor_pipe = nullptr,
			  *kernel_channel_monitor_pipe = nullptr;
	struct timer_thread_parameters timer_thread_parameters;
	/* Queue of rotation jobs populated by the sessiond-timer. */
	lttng::sessiond::rotation_thread_timer_queue *rotation_timer_queue = nullptr;
	struct lttng_thread *client_thread = nullptr;
	struct lttng_thread *notification_thread = nullptr;
	struct lttng_thread *register_apps_thread = nullptr;
	enum event_notifier_error_accounting_status event_notifier_error_accounting_status;

	logger_set_thread_name("Main", false);
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

	the_page_size = sysconf(_SC_PAGE_SIZE);
	if (the_page_size < 0) {
		PERROR("sysconf _SC_PAGE_SIZE");
		the_page_size = LONG_MAX;
		WARN("Fallback page size to %ld", the_page_size);
	}

	ret = sessiond_config_init(&the_config);
	if (ret) {
		retval = -1;
		goto exit_set_signal_handler;
	}

	/*
	 * Init config from environment variables.
	 * Command line option override env configuration per-doc. Do env first.
	 */
	sessiond_config_apply_env_config(&the_config);

	/*
	 * Parse arguments and load the daemon configuration file.
	 *
	 * We have an exit_options exit path to free memory reserved by
	 * set_options.
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
	ret = sessiond_config_resolve_paths(&the_config);
	if (ret) {
		goto exit_options;
	}

	/* Apply config. */
	lttng_opt_verbose = the_config.verbose;
	lttng_opt_quiet = the_config.quiet;
	the_kconsumer_data.err_unix_sock_path = the_config.kconsumerd_err_unix_sock_path.value;
	the_kconsumer_data.cmd_unix_sock_path = the_config.kconsumerd_cmd_unix_sock_path.value;
	the_ustconsumer32_data.err_unix_sock_path = the_config.consumerd32_err_unix_sock_path.value;
	the_ustconsumer32_data.cmd_unix_sock_path = the_config.consumerd32_cmd_unix_sock_path.value;
	the_ustconsumer64_data.err_unix_sock_path = the_config.consumerd64_err_unix_sock_path.value;
	the_ustconsumer64_data.cmd_unix_sock_path = the_config.consumerd64_cmd_unix_sock_path.value;
	set_clock_plugin_env();

	sessiond_config_log(&the_config);
	sessiond_uuid_log();
	lttng::logging::log_system_information(PRINT_DBG);

	if (opt_print_version) {
		print_version();
		retval = 0;
		goto exit_options;
	}

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
	if (the_config.daemonize || the_config.background) {
		int i;

		ret = lttng_daemonize(&the_child_ppid, &recv_child_signal, !the_config.background);
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

	if (launch_run_as_worker(argv[0]) < 0) {
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
	the_health_sessiond = health_app_create(NR_HEALTH_SESSIOND_TYPES);
	if (!the_health_sessiond) {
		PERROR("health_app_create error");
		retval = -1;
		goto stop_threads;
	}

	/* Create main quit pipe */
	if (sessiond_init_main_quit_pipe()) {
		retval = -1;
		goto stop_threads;
	}

	/* Check if daemon is UID = 0 */
	is_root = !getuid();
	if (is_root) {
		/* Create global run dir with root access */

		kernel_channel_monitor_pipe = lttng_pipe_open(0);
		if (!kernel_channel_monitor_pipe) {
			ERR("Failed to create kernel consumer channel monitor pipe");
			retval = -1;
			goto stop_threads;
		}
		the_kconsumer_data.channel_monitor_pipe =
			lttng_pipe_release_writefd(kernel_channel_monitor_pipe);
		if (the_kconsumer_data.channel_monitor_pipe < 0) {
			retval = -1;
			goto stop_threads;
		}
	}

	/* Set consumer initial state */
	the_kernel_consumerd_state = CONSUMER_STOPPED;
	the_ust_consumerd_state = CONSUMER_STOPPED;

	ust32_channel_monitor_pipe = lttng_pipe_open(0);
	if (!ust32_channel_monitor_pipe) {
		ERR("Failed to create 32-bit user space consumer channel monitor pipe");
		retval = -1;
		goto stop_threads;
	}
	the_ustconsumer32_data.channel_monitor_pipe =
		lttng_pipe_release_writefd(ust32_channel_monitor_pipe);
	if (the_ustconsumer32_data.channel_monitor_pipe < 0) {
		retval = -1;
		goto stop_threads;
	}

	/*
	 * The rotation_thread_timer_queue structure is shared between the
	 * sessiond timer thread and the rotation thread. The main thread keeps
	 * its ownership and destroys it when both threads have been joined.
	 */
	rotation_timer_queue = lttng::sessiond::rotation_thread_timer_queue_create();
	if (!rotation_timer_queue) {
		retval = -1;
		goto stop_threads;
	}
	timer_thread_parameters.rotation_thread_job_queue = rotation_timer_queue;

	ust64_channel_monitor_pipe = lttng_pipe_open(0);
	if (!ust64_channel_monitor_pipe) {
		ERR("Failed to create 64-bit user space consumer channel monitor pipe");
		retval = -1;
		goto stop_threads;
	}
	the_ustconsumer64_data.channel_monitor_pipe =
		lttng_pipe_release_writefd(ust64_channel_monitor_pipe);
	if (the_ustconsumer64_data.channel_monitor_pipe < 0) {
		retval = -1;
		goto stop_threads;
	}

	/*
	 * Init UST app hash table. Alloc hash table before this point since
	 * cleanup() can get called after that point.
	 */
	if (ust_app_ht_alloc()) {
		ERR("Failed to allocate UST app hash table");
		retval = -1;
		goto stop_threads;
	}

	event_notifier_error_accounting_status = event_notifier_error_accounting_init(
		the_config.event_notifier_buffer_size_kernel,
		the_config.event_notifier_buffer_size_userspace);
	if (event_notifier_error_accounting_status != EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK) {
		ERR("Failed to initialize event notifier error accounting system");
		retval = -1;
		goto stop_threads;
	}

	/*
	 * Initialize agent app hash table. We allocate the hash table here
	 * since cleanup() can get called after this point.
	 */
	if (agent_app_ht_alloc()) {
		ERR("Failed to allocate Agent app hash table");
		retval = -1;
		goto stop_threads;
	}

	if (agent_by_event_notifier_domain_ht_create()) {
		ERR("Failed to allocate per-event notifier domain agent hash table");
		retval = -1;
		goto stop_threads;
	}
	/*
	 * These actions must be executed as root. We do that *after* setting up
	 * the sockets path because we MUST make the check for another daemon using
	 * those paths *before* trying to set the kernel consumer sockets and init
	 * kernel tracer.
	 */
	if (is_root) {
		if (set_consumer_sockets(&the_kconsumer_data)) {
			retval = -1;
			goto stop_threads;
		}

		/* Setup kernel tracer */
		if (!the_config.no_kernel) {
			init_kernel_tracer();
		}

		/* Set ulimit for open files */
		set_ulimit();
	}
	/* init lttng_fd tracking must be done after set_ulimit. */
	lttng_fd_init();

	if (set_consumer_sockets(&the_ustconsumer64_data)) {
		retval = -1;
		goto stop_threads;
	}

	if (set_consumer_sockets(&the_ustconsumer32_data)) {
		retval = -1;
		goto stop_threads;
	}

	/* Get parent pid if -S, --sig-parent is specified. */
	if (the_config.sig_parent) {
		the_ppid = getppid();
	}

	/* Setup the kernel pipe for waking up the kernel thread */
	if (is_root && !the_config.no_kernel) {
		if (utils_create_pipe_cloexec(the_kernel_poll_pipe)) {
			retval = -1;
			goto stop_threads;
		}
	}

	/* Setup the thread apps communication pipe. */
	if (utils_create_pipe_cloexec(apps_cmd_pipe)) {
		retval = -1;
		goto stop_threads;
	}

	/* Setup the thread apps notify communication pipe. */
	if (utils_create_pipe_cloexec(apps_cmd_notify_pipe)) {
		retval = -1;
		goto stop_threads;
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
		the_config.app_socket_timeout = atoi(env_app_timeout);
	} else {
		the_config.app_socket_timeout = DEFAULT_APP_SOCKET_RW_TIMEOUT;
	}

	ret = write_pidfile();
	if (ret) {
		ERR("Error in write_pidfile");
		retval = -1;
		goto stop_threads;
	}

	/* Initialize communication library */
	lttcomm_init();
	/* Initialize TCP timeout values */
	lttcomm_inet_init();

	/* Create health-check thread. */
	if (!launch_health_management_thread()) {
		retval = -1;
		goto stop_threads;
	}

	/* notification_thread_data acquires the pipes' read side. */
	the_notification_thread_handle =
		notification_thread_handle_create(ust32_channel_monitor_pipe,
						  ust64_channel_monitor_pipe,
						  kernel_channel_monitor_pipe);
	if (!the_notification_thread_handle) {
		retval = -1;
		ERR("Failed to create notification thread shared data");
		goto stop_threads;
	}

	/* Create notification thread. */
	notification_thread = launch_notification_thread(the_notification_thread_handle);
	if (!notification_thread) {
		retval = -1;
		goto stop_threads;
	}

	/* Create timer thread. */
	if (!launch_timer_thread(&timer_thread_parameters)) {
		retval = -1;
		goto stop_threads;
	}

	try {
		the_rotation_thread_handle = lttng::make_unique<lttng::sessiond::rotation_thread>(
			*rotation_timer_queue, *the_notification_thread_handle);
	} catch (const std::exception& e) {
		retval = -1;
		ERR("Failed to create rotation thread: %s", e.what());
		goto stop_threads;
	}

	try {
		the_rotation_thread_handle->launch_thread();
	} catch (const std::exception& e) {
		retval = -1;
		ERR("Failed to launch rotation thread: %s", e.what());
		goto stop_threads;
	}

	/* Create thread to manage the client socket */
	client_thread = launch_client_thread();
	if (!client_thread) {
		retval = -1;
		goto stop_threads;
	}

	/* Set credentials of the client socket and rundir */
	if (is_root && set_permissions(the_config.rundir.value)) {
		retval = -1;
		goto stop_threads;
	}

	if (!launch_ust_dispatch_thread(&ust_cmd_queue, apps_cmd_pipe[1], apps_cmd_notify_pipe[1])) {
		retval = -1;
		goto stop_threads;
	}

	/* Create thread to manage application registration. */
	register_apps_thread = launch_application_registration_thread(&ust_cmd_queue);
	if (!register_apps_thread) {
		retval = -1;
		goto stop_threads;
	}

	/* Create thread to manage application socket */
	if (!launch_application_management_thread(apps_cmd_pipe[0])) {
		retval = -1;
		goto stop_threads;
	}

	/* Create thread to manage application notify socket */
	if (!launch_application_notification_thread(apps_cmd_notify_pipe[0])) {
		retval = -1;
		goto stop_threads;
	}

	/* Create agent management thread. */
	if (!launch_agent_management_thread()) {
		retval = -1;
		goto stop_threads;
	}

	/* Don't start this thread if kernel tracing is not requested nor root */
	if (is_root && !the_config.no_kernel) {
		/* Create kernel thread to manage kernel event */
		if (!launch_kernel_management_thread(the_kernel_poll_pipe[0])) {
			retval = -1;
			goto stop_threads;
		}

		if (kernel_get_notification_fd() >= 0) {
			ret = notification_thread_command_add_tracer_event_source(
				the_notification_thread_handle,
				kernel_get_notification_fd(),
				LTTNG_DOMAIN_KERNEL);
			if (ret != LTTNG_OK) {
				ERR("Failed to add kernel trigger event source to notification thread");
				retval = -1;
				goto stop_threads;
			}
		}
	}

	/* Load sessions. */
	ret = config_load_session(the_config.load_session_path.value, nullptr, 1, 1, nullptr);
	if (ret) {
		ERR("Session load failed: %s", error_get_str(ret));
		retval = -1;
		goto stop_threads;
	}

	/* Initialization completed. */
	sessiond_signal_parents();

	/*
	 * This is where we start awaiting program completion (e.g. through
	 * signal that asks threads to teardown).
	 */

	/* Initiate teardown once activity occurs on the main quit pipe. */
	sessiond_wait_for_main_quit_pipe(-1);

stop_threads:

	DBG("Terminating all threads");

	/*
	 * Ensure that the client thread is no longer accepting new commands,
	 * which could cause new sessions to be created.
	 */
	if (client_thread) {
		lttng_thread_shutdown(client_thread);
		lttng_thread_put(client_thread);
	}

	destroy_all_sessions_and_wait();

	/*
	 * At this point no new trigger can be registered (no sessions are
	 * running/rotating) and clients can't connect to the session daemon
	 * anymore. Unregister all triggers.
	 */
	unregister_all_triggers();

	if (register_apps_thread) {
		lttng_thread_shutdown(register_apps_thread);
		lttng_thread_put(register_apps_thread);
	}
	lttng_thread_list_shutdown_orphans();

	/*
	 * Wait for all pending call_rcu work to complete before tearing
	 * down data structures. call_rcu worker may be trying to
	 * perform lookups in those structures.
	 */
	rcu_barrier();

	rcu_thread_online();
	sessiond_cleanup();

	/*
	 * Wait for all pending call_rcu work to complete before shutting down
	 * the notification thread. This call_rcu work includes shutting down
	 * UST apps and event notifier pipes.
	 */
	rcu_barrier();

	if (notification_thread) {
		lttng_thread_shutdown(notification_thread);
		lttng_thread_put(notification_thread);
	}

	/*
	 * Error accounting teardown has to be done after the teardown of all
	 * event notifier pipes to ensure that no tracer may try to use the
	 * error accounting facilities.
	 */
	event_notifier_error_accounting_fini();

	/*
	 * Unloading the kernel modules needs to be done after all kernel
	 * ressources have been released. In our case, this includes the
	 * notification fd, the event notifier group fd, error accounting fd,
	 * all event and event notifier fds, etc.
	 *
	 * In short, at this point, we need to have called close() on all fds
	 * received from the kernel tracer.
	 */
	if (is_root && !the_config.no_kernel) {
		DBG("Unloading kernel modules");
		modprobe_remove_lttng_all();
	}

	rcu_thread_offline();
	rcu_unregister_thread();

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
	if (the_notification_thread_handle) {
		notification_thread_handle_destroy(the_notification_thread_handle);
	}
	lttng_pipe_destroy(ust32_channel_monitor_pipe);
	lttng_pipe_destroy(ust64_channel_monitor_pipe);
	lttng_pipe_destroy(kernel_channel_monitor_pipe);

	if (the_health_sessiond) {
		health_app_destroy(the_health_sessiond);
	}
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
