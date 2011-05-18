/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#define _GNU_SOURCE
#include <fcntl.h>
#include <getopt.h>
#include <grp.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <urcu/list.h>		/* URCU list library (-lurcu) */
#include <ust/ustctl.h>		/* UST control lib (-lust) */
#include <lttng/lttng.h>

#include "liblttsessiondcomm.h"
#include "ltt-sessiond.h"
#include "lttngerr.h"
#include "session.h"
#include "trace.h"
#include "traceable-app.h"

/*
 * TODO:
 * teardown: signal SIGTERM handler -> write into pipe. Threads waits
 * with epoll on pipe and on other pipes/sockets for commands.  Main
 * simply waits on pthread join.
 */

/* Const values */
const char default_home_dir[] = DEFAULT_HOME_DIR;
const char default_tracing_group[] = DEFAULT_TRACING_GROUP;
const char default_ust_sock_dir[] = DEFAULT_UST_SOCK_DIR;
const char default_global_apps_pipe[] = DEFAULT_GLOBAL_APPS_PIPE;

/* Static functions */
static int check_existing_daemon(void);
static int ust_connect_app(pid_t pid);
static int init_daemon_socket(void);
static int notify_apps(const char* name);
static int process_client_msg(struct command_ctx *cmd_ctx);
static int send_unix_sock(int sock, void *buf, size_t len);
static int set_signal_handler(void);
static int set_permissions(void);
static int setup_lttng_msg(struct command_ctx *cmd_ctx, size_t size);
static int create_lttng_rundir(void);
static int set_kconsumerd_sockets(void);
static void cleanup(void);
static void sighandler(int sig);
static void clean_command_ctx(struct command_ctx *cmd_ctx);

static void *thread_manage_clients(void *data);
static void *thread_manage_apps(void *data);
static void *thread_manage_kconsumerd(void *data);

/* Variables */
int opt_verbose;
int opt_quiet;
const char *progname;
const char *opt_tracing_group;
static int opt_sig_parent;
static int opt_daemon;
static int is_root;			/* Set to 1 if the daemon is running as root */
static pid_t ppid;

static char apps_unix_sock_path[PATH_MAX];				/* Global application Unix socket path */
static char client_unix_sock_path[PATH_MAX];			/* Global client Unix socket path */
static char kconsumerd_err_unix_sock_path[PATH_MAX];	/* kconsumerd error Unix socket path */
static char kconsumerd_cmd_unix_sock_path[PATH_MAX];	/* kconsumerd command Unix socket path */

static int client_sock;
static int apps_sock;
static int kconsumerd_err_sock;

/*
 *  thread_manage_kconsumerd
 *
 *  This thread manage the kconsumerd error sent
 *  back to the session daemon.
 */
static void *thread_manage_kconsumerd(void *data)
{
	int sock, ret;

	DBG("[thread] Manage kconsumerd started");

	ret = lttcomm_listen_unix_sock(kconsumerd_err_sock);
	if (ret < 0) {
		goto error;
	}

	sock = lttcomm_accept_unix_sock(kconsumerd_err_sock);
	if (sock < 0) {
		goto error;
	}

	while (1) {
		//ret = lttcomm_recv_unix_sock(sock, &lsm, sizeof(lsm));
		if (ret <= 0) {
			/* TODO: Consumerd died? */
			continue;
		}
	}

error:
	return NULL;
}

/*
 * 	thread_manage_apps
 *
 * 	This thread manage the application socket communication
 */
static void *thread_manage_apps(void *data)
{
	int sock, ret;

	/* TODO: Something more elegant is needed but fine for now */
	/* FIXME: change all types to either uint8_t, uint32_t, uint64_t
	 * for 32-bit vs 64-bit compat processes. */
	/* replicate in ust with version number */
	struct {
		int reg;	/* 1:register, 0:unregister */
		pid_t pid;
		uid_t uid;
	} reg_msg;

	DBG("[thread] Manage apps started");

	ret = lttcomm_listen_unix_sock(apps_sock);
	if (ret < 0) {
		goto error;
	}

	/* Notify all applications to register */
	notify_apps(default_global_apps_pipe);

	while (1) {
		DBG("Accepting application registration");
		/* Blocking call, waiting for transmission */
		sock = lttcomm_accept_unix_sock(apps_sock);
		if (sock < 0) {
			goto error;
		}

		/* Basic recv here to handle the very simple data
		 * that the libust send to register (reg_msg).
		 */
		ret = recv(sock, &reg_msg, sizeof(reg_msg), 0);
		if (ret < 0) {
			perror("recv");
			continue;
		}

		/* Add application to the global traceable list */
		if (reg_msg.reg == 1) {
			/* Registering */
			ret = register_traceable_app(reg_msg.pid, reg_msg.uid);
			if (ret < 0) {
				/* register_traceable_app only return an error with
				 * ENOMEM. At this point, we better stop everything.
				 */
				goto error;
			}
		} else {
			/* Unregistering */
			unregister_traceable_app(reg_msg.pid);
		}
	}

error:

	return NULL;
}

/*
 * 	thread_manage_clients
 *
 * 	This thread manage all clients request using the unix
 * 	client socket for communication.
 */
static void *thread_manage_clients(void *data)
{
	int sock, ret;
	struct command_ctx *cmd_ctx;

	DBG("[thread] Manage client started");

	ret = lttcomm_listen_unix_sock(client_sock);
	if (ret < 0) {
		goto error;
	}

	/* Notify parent pid that we are ready
	 * to accept command for client side.
	 */
	if (opt_sig_parent) {
		kill(ppid, SIGCHLD);
	}

	while (1) {
		/* Blocking call, waiting for transmission */
		DBG("Accepting client command ...");
		sock = lttcomm_accept_unix_sock(client_sock);
		if (sock < 0) {
			goto error;
		}

		/* Allocate context command to process the client request */
		cmd_ctx = malloc(sizeof(struct command_ctx));

		/* Allocate data buffer for reception */
		cmd_ctx->lsm = malloc(sizeof(struct lttcomm_session_msg));
		cmd_ctx->llm = NULL;
		cmd_ctx->session = NULL;

		/*
		 * Data is received from the lttng client. The struct
		 * lttcomm_session_msg (lsm) contains the command and data request of
		 * the client.
		 */
		DBG("Receiving data from client ...");
		ret = lttcomm_recv_unix_sock(sock, cmd_ctx->lsm, sizeof(struct lttcomm_session_msg));
		if (ret <= 0) {
			continue;
		}

		/*
		 * This function dispatch the work to the kernel or userspace tracer
		 * libs and fill the lttcomm_lttng_msg data structure of all the needed
		 * informations for the client. The command context struct contains
		 * everything this function may needs.
		 */
		ret = process_client_msg(cmd_ctx);
		if (ret < 0) {
			/* TODO: Inform client somehow of the fatal error. At this point,
			 * ret < 0 means that a malloc failed (ENOMEM). */
			/* Error detected but still accept command */
			clean_command_ctx(cmd_ctx);
			continue;
		}

		DBG("Sending response (size: %d, retcode: %d)",
				cmd_ctx->lttng_msg_size, cmd_ctx->llm->ret_code);
		ret = send_unix_sock(sock, cmd_ctx->llm, cmd_ctx->lttng_msg_size);
		if (ret < 0) {
			ERR("Failed to send data back to client");
		}

		clean_command_ctx(cmd_ctx);
	}

error:
	return NULL;
}

/*
 *  send_unix_sock
 *
 *  Send data on a unix socket using the liblttsessiondcomm API.
 *
 *  Return lttcomm error code.
 */
static int send_unix_sock(int sock, void *buf, size_t len)
{
	/* Check valid length */
	if (len <= 0) {
		return -1;
	}

	return lttcomm_send_unix_sock(sock, buf, len);
}

/*
 *  clean_command_ctx
 *
 *  Free memory of a command context structure.
 */
static void clean_command_ctx(struct command_ctx *cmd_ctx)
{
	DBG("Clean command context structure %p", cmd_ctx);
	if (cmd_ctx) {
		if (cmd_ctx->llm) {
			free(cmd_ctx->llm);
		}
		if (cmd_ctx->lsm) {
			free(cmd_ctx->lsm);
		}
		free(cmd_ctx);
		cmd_ctx = NULL;
	}
}

/*
 * 	ust_connect_app
 *
 * 	Return a socket connected to the libust communication socket
 * 	of the application identified by the pid.
 *
 * 	If the pid is not found in the traceable list,
 * 	return -1 to indicate error.
 */
static int ust_connect_app(pid_t pid)
{
	int sock;
	struct ltt_traceable_app *lta;

	DBG("Connect to application pid %d", pid);

	lta = find_app_by_pid(pid);
	if (lta == NULL) {
		/* App not found */
		DBG("Application pid %d not found", pid);
		return -1;
	}

	sock = ustctl_connect_pid(lta->pid);
	if (sock < 0) {
		ERR("Fail connecting to the PID %d\n", pid);
	}

	return sock;
}

/*
 * 	notify_apps
 *
 *  Notify apps by writing 42 to a named pipe using name.
 * 	Every applications waiting for a ltt-sessiond will be notified
 * 	and re-register automatically to the session daemon.
 *
 * 	Return open or write error value.
 */
static int notify_apps(const char *name)
{
	int fd;
	int ret = -1;

	DBG("Notify the global application pipe");

	/* Try opening the global pipe */
	fd = open(name, O_WRONLY);
	if (fd < 0) {
		goto error;
	}

	/* Notify by writing on the pipe */
	ret = write(fd, "42", 2);
	if (ret < 0) {
		perror("write");
	}

error:
	return ret;
}

/*
 *  setup_lttng_msg
 *
 *  Setup the outgoing data buffer for the response (llm) by allocating the
 *  right amount of memory and copying the original information from the lsm
 *  structure.
 *
 *  Return total size of the buffer pointed by buf.
 */
static int setup_lttng_msg(struct command_ctx *cmd_ctx, size_t size)
{
	int ret, buf_size, trace_name_size;

	/*
	 * Check for the trace_name. If defined, it's part of the payload data of
	 * the llm structure.
	 */
	trace_name_size = strlen(cmd_ctx->lsm->trace_name);
	buf_size = trace_name_size + size;

	cmd_ctx->llm = malloc(sizeof(struct lttcomm_lttng_msg) + buf_size);
	if (cmd_ctx->llm == NULL) {
		perror("malloc");
		ret = -ENOMEM;
		goto error;
	}

	/* Copy common data */
	cmd_ctx->llm->cmd_type = cmd_ctx->lsm->cmd_type;
	cmd_ctx->llm->pid = cmd_ctx->lsm->pid;
	if (!uuid_is_null(cmd_ctx->lsm->session_uuid)) {
		uuid_copy(cmd_ctx->llm->session_uuid, cmd_ctx->lsm->session_uuid);
	}

	cmd_ctx->llm->trace_name_offset = trace_name_size;
	cmd_ctx->llm->data_size = size;
	cmd_ctx->lttng_msg_size = sizeof(struct lttcomm_lttng_msg) + buf_size;

	/* Copy trace name to the llm structure. Begining of the payload. */
	memcpy(cmd_ctx->llm->payload, cmd_ctx->lsm->trace_name, trace_name_size);

	return buf_size;

error:
	return ret;
}

/*
 * 	process_client_msg
 *
 *  Process the command requested by the lttng client within the command
 *  context structure.  This function make sure that the return structure (llm)
 *  is set and ready for transmission before returning.
 *
 * 	Return any error encountered or 0 for success.
 */
static int process_client_msg(struct command_ctx *cmd_ctx)
{
	int ret;

	DBG("Processing client command %d", cmd_ctx->lsm->cmd_type);

	/* Check command that needs a session */
	switch (cmd_ctx->lsm->cmd_type) {
	case LTTNG_CREATE_SESSION:
	case LTTNG_LIST_SESSIONS:
	case UST_LIST_APPS:
		break;
	default:
		cmd_ctx->session = find_session_by_uuid(cmd_ctx->lsm->session_uuid);
		if (cmd_ctx->session == NULL) {
			ret = LTTCOMM_SELECT_SESS;
			goto error;
		}
		break;
	}

	/* Connect to ust apps if available pid */
	if (cmd_ctx->lsm->pid > 0) {
		/* Connect to app using ustctl API */
		cmd_ctx->ust_sock = ust_connect_app(cmd_ctx->lsm->pid);
		if (cmd_ctx->ust_sock < 0) {
			ret = LTTCOMM_NO_TRACEABLE;
			goto error;
		}
	}

	/* Process by command type */
	switch (cmd_ctx->lsm->cmd_type) {
	case KERNEL_ENABLE_EVENT:
	{
		/* Setup lttng message with no payload */
		ret = setup_lttng_msg(cmd_ctx, 0);
		if (ret < 0) {
			goto setup_error;
		}

		DBG("Enabling kernel event %s", cmd_ctx->lsm->u.event.event_name);

		ret = LTTCOMM_OK;
		break;
	}
	case LTTNG_CREATE_SESSION:
	{
		/* Setup lttng message with no payload */
		ret = setup_lttng_msg(cmd_ctx, 0);
		if (ret < 0) {
			goto setup_error;
		}

		ret = create_session(cmd_ctx->lsm->session_name, &cmd_ctx->llm->session_uuid);
		if (ret < 0) {
			if (ret == -1) {
				ret = LTTCOMM_EXIST_SESS;
			} else {
				ret = LTTCOMM_FATAL;
			}
			goto error;
		}

		ret = LTTCOMM_OK;
		break;
	}
	case LTTNG_DESTROY_SESSION:
	{
		/* Setup lttng message with no payload */
		ret = setup_lttng_msg(cmd_ctx, 0);
		if (ret < 0) {
			goto setup_error;
		}

		ret = destroy_session(&cmd_ctx->lsm->session_uuid);
		if (ret < 0) {
			ret = LTTCOMM_NO_SESS;
			goto error;
		}

		ret = LTTCOMM_OK;
		break;
	}
	case LTTNG_LIST_TRACES:
	{
		unsigned int trace_count;

		trace_count = get_trace_count_per_session(cmd_ctx->session);
		if (trace_count == 0) {
			ret = LTTCOMM_NO_TRACE;
			goto error;
		}

		ret = setup_lttng_msg(cmd_ctx, sizeof(struct lttng_trace) * trace_count);
		if (ret < 0) {
			goto setup_error;
		}

		get_traces_per_session(cmd_ctx->session,
				(struct lttng_trace *)(cmd_ctx->llm->payload));

		ret = LTTCOMM_OK;
		break;
	}
	case UST_CREATE_TRACE:
	{
		/* Setup lttng message with no payload */
		ret = setup_lttng_msg(cmd_ctx, 0);
		if (ret < 0) {
			goto setup_error;
		}

		ret = ust_create_trace(cmd_ctx);
		if (ret < 0) {
			goto setup_error;
		}
		break;
	}
	case UST_LIST_APPS:
	{
		unsigned int app_count;

		app_count = get_app_count();
		DBG("Traceable application count : %d", app_count);
		if (app_count == 0) {
			ret = LTTCOMM_NO_APPS;
			goto error;
		}

		ret = setup_lttng_msg(cmd_ctx, sizeof(pid_t) * app_count);
		if (ret < 0) {
			goto setup_error;
		}

		get_app_list_pids((pid_t *)(cmd_ctx->llm->payload));

		ret = LTTCOMM_OK;
		break;
	}
	case UST_START_TRACE:
	{
		/* Setup lttng message with no payload */
		ret = setup_lttng_msg(cmd_ctx, 0);
		if (ret < 0) {
			goto setup_error;
		}

		ret = ust_start_trace(cmd_ctx);
		if (ret < 0) {
			goto setup_error;
		}
		break;
	}
	case UST_STOP_TRACE:
	{
		/* Setup lttng message with no payload */
		ret = setup_lttng_msg(cmd_ctx, 0);
		if (ret < 0) {
			goto setup_error;
		}

		ret = ust_stop_trace(cmd_ctx);
		if (ret < 0) {
			goto setup_error;
		}
		break;
	}
	case LTTNG_LIST_SESSIONS:
	{
		unsigned int session_count;

		session_count = get_session_count();
		if (session_count == 0) {
			ret = LTTCOMM_NO_SESS;
			goto error;
		}

		ret = setup_lttng_msg(cmd_ctx, sizeof(struct lttng_session) * session_count);
		if (ret < 0) {
			goto setup_error;
		}

		get_lttng_session((struct lttng_session *)(cmd_ctx->llm->payload));

		ret = LTTCOMM_OK;
		break;
	}
	default:
		/* Undefined command */
		ret = setup_lttng_msg(cmd_ctx, 0);
		if (ret < 0) {
			goto setup_error;
		}

		ret = LTTCOMM_UND;
		break;
	}

	/* Set return code */
	cmd_ctx->llm->ret_code = ret;

	return ret;

error:
	if (cmd_ctx->llm == NULL) {
		DBG("Missing llm structure. Allocating one.");
		if (setup_lttng_msg(cmd_ctx, 0) < 0) {
			goto setup_error;
		}
	}
	/* Notify client of error */
	cmd_ctx->llm->ret_code = ret;

setup_error:
	return ret;
}

/*
 * usage function on stderr
 */
static void usage(void)
{
	fprintf(stderr, "Usage: %s OPTIONS\n\nOptions:\n", progname);
	fprintf(stderr, "  -h, --help                         Display this usage.\n");
	fprintf(stderr, "  -c, --client-sock PATH             Specify path for the client unix socket\n");
	fprintf(stderr, "  -a, --apps-sock PATH               Specify path for apps unix socket\n");
	fprintf(stderr, "      --kconsumerd-err-sock PATH     Specify path for the kernel consumer error socket\n");
	fprintf(stderr, "      --kconsumerd-cmd-sock PATH     Specify path for the kernel consumer command socket\n");
	fprintf(stderr, "  -d, --daemonize                    Start as a daemon.\n");
	fprintf(stderr, "  -g, --group NAME                   Specify the tracing group name. (default: tracing)\n");
	fprintf(stderr, "  -V, --version                      Show version number.\n");
	fprintf(stderr, "  -S, --sig-parent                   Send SIGCHLD to parent pid to notify readiness.\n");
	fprintf(stderr, "  -q, --quiet                        No output at all.\n");
	fprintf(stderr, "  -v, --verbose                      Verbose mode. Activate DBG() macro.\n");
}

/*
 * daemon argument parsing
 */
static int parse_args(int argc, char **argv)
{
	int c;

	static struct option long_options[] = {
		{ "client-sock", 1, 0, 'c' },
		{ "apps-sock", 1, 0, 'a' },
		{ "kconsumerd-cmd-sock", 1, 0, 0 },
		{ "kconsumerd-err-sock", 1, 0, 0 },
		{ "daemonize", 0, 0, 'd' },
		{ "sig-parent", 0, 0, 'S' },
		{ "help", 0, 0, 'h' },
		{ "group", 1, 0, 'g' },
		{ "version", 0, 0, 'V' },
		{ "quiet", 0, 0, 'q' },
		{ "verbose", 0, 0, 'v' },
		{ NULL, 0, 0, 0 }
	};

	while (1) {
		int option_index = 0;
		c = getopt_long(argc, argv, "dhqvVS" "a:c:g:s:E:C:", long_options, &option_index);
		if (c == -1) {
			break;
		}

		switch (c) {
		case 0:
			fprintf(stderr, "option %s", long_options[option_index].name);
			if (optarg) {
				fprintf(stderr, " with arg %s\n", optarg);
			}
			break;
		case 'c':
			snprintf(client_unix_sock_path, PATH_MAX, "%s", optarg);
			break;
		case 'a':
			snprintf(apps_unix_sock_path, PATH_MAX, "%s", optarg);
			break;
		case 'd':
			opt_daemon = 1;
			break;
		case 'g':
			opt_tracing_group = strdup(optarg);
			break;
		case 'h':
			usage();
			exit(EXIT_FAILURE);
		case 'V':
			fprintf(stdout, "%s\n", VERSION);
			exit(EXIT_SUCCESS);
		case 'S':
			opt_sig_parent = 1;
			break;
		case 'E':
			snprintf(kconsumerd_err_unix_sock_path, PATH_MAX, "%s", optarg);
			break;
		case 'C':
			snprintf(kconsumerd_cmd_unix_sock_path, PATH_MAX, "%s", optarg);
			break;
		case 'q':
			opt_quiet = 1;
			break;
		case 'v':
			opt_verbose = 1;
			break;
		default:
			/* Unknown option or other error.
			 * Error is printed by getopt, just return */
			return -1;
		}
	}

	return 0;
}

/*
 * 	init_daemon_socket
 *
 * 	Creates the two needed socket by the daemon.
 * 	    apps_sock - The communication socket for all UST apps.
 * 	    client_sock - The communication of the cli tool (lttng).
 */
static int init_daemon_socket()
{
	int ret = 0;
	mode_t old_umask;

	old_umask = umask(0);

	/* Create client tool unix socket */
	client_sock = lttcomm_create_unix_sock(client_unix_sock_path);
	if (client_sock < 0) {
		ERR("Create unix sock failed: %s", client_unix_sock_path);
		ret = -1;
		goto end;
	}

	/* File permission MUST be 660 */
	ret = chmod(client_unix_sock_path, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
	if (ret < 0) {
		ERR("Set file permissions failed: %s", client_unix_sock_path);
		perror("chmod");
		goto end;
	}

	/* Create the application unix socket */
	apps_sock = lttcomm_create_unix_sock(apps_unix_sock_path);
	if (apps_sock < 0) {
		ERR("Create unix sock failed: %s", apps_unix_sock_path);
		ret = -1;
		goto end;
	}

	/* File permission MUST be 666 */
	ret = chmod(apps_unix_sock_path, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
	if (ret < 0) {
		ERR("Set file permissions failed: %s", apps_unix_sock_path);
		perror("chmod");
		goto end;
	}

end:
	umask(old_umask);
	return ret;
}

/*
 * 	check_existing_daemon
 *
 * 	Check if the global socket is available.
 *  If yes, error is returned.
 */
static int check_existing_daemon()
{
	int ret;

	ret = access(client_unix_sock_path, F_OK);
	if (ret == 0) {
		ret = access(apps_unix_sock_path, F_OK);
	}

	return ret;
}

/*
 *  get_home_dir
 *
 *  Return pointer to home directory path using
 *  the env variable HOME.
 *
 *  Default : /tmp
 */
static const char *get_home_dir(void)
{
	const char *home_path;

	if ((home_path = (const char *) getenv("HOME")) == NULL) {
		home_path = default_home_dir;
	}

	return home_path;
}

/*
 *  set_permissions
 *
 *  Set the tracing group gid onto the client socket.
 *
 *  Race window between mkdir and chown is OK because we are going from
 *  less permissive (root.root) to more permissive (root.tracing).
 */
static int set_permissions(void)
{
	int ret;
	struct group *grp;

	/* Decide which group name to use */
	(opt_tracing_group != NULL) ?
		(grp = getgrnam(opt_tracing_group)) :
		(grp = getgrnam(default_tracing_group));

	if (grp == NULL) {
		ERR("Missing tracing group. Aborting execution.\n");
		ret = -1;
		goto end;
	}

	/* Set lttng run dir */
	ret = chown(LTTNG_RUNDIR, 0, grp->gr_gid);
	if (ret < 0) {
		ERR("Unable to set group on " LTTNG_RUNDIR);
		perror("chown");
	}

	/* lttng client socket path */
	ret = chown(client_unix_sock_path, 0, grp->gr_gid);
	if (ret < 0) {
		ERR("Unable to set group on %s", client_unix_sock_path);
		perror("chown");
	}

	/* kconsumerd error socket path */
	ret = chown(kconsumerd_err_unix_sock_path, 0, grp->gr_gid);
	if (ret < 0) {
		ERR("Unable to set group on %s", kconsumerd_err_unix_sock_path);
		perror("chown");
	}

	DBG("All permissions are set");

end:
	return ret;
}

/*
 *  create_lttng_rundir
 *
 *  Create the lttng run directory needed for all
 *  global sockets and pipe.
 */
static int create_lttng_rundir(void)
{
	int ret;

	ret = mkdir(LTTNG_RUNDIR, S_IRWXU | S_IRWXG );
	if (ret < 0) {
		ERR("Unable to create " LTTNG_RUNDIR);
		goto error;
	}

error:
	return ret;
}

/*
 *  set_kconsumerd_sockets
 *
 *  Setup sockets and directory needed by the kconsumerd
 *  communication with the session daemon.
 */
static int set_kconsumerd_sockets(void)
{
	int ret;

	if (strlen(kconsumerd_err_unix_sock_path) == 0) {
		snprintf(kconsumerd_err_unix_sock_path, PATH_MAX, KCONSUMERD_ERR_SOCK_PATH);
	}

	if (strlen(kconsumerd_cmd_unix_sock_path) == 0) {
		snprintf(kconsumerd_cmd_unix_sock_path, PATH_MAX, KCONSUMERD_CMD_SOCK_PATH);
	}

	ret = mkdir(KCONSUMERD_PATH, S_IRWXU | S_IRWXG);
	if (ret < 0) {
		ERR("Failed to create " KCONSUMERD_PATH);
		goto error;
	}

	/* Create the kconsumerd error unix socket */
	kconsumerd_err_sock = lttcomm_create_unix_sock(kconsumerd_err_unix_sock_path);
	if (kconsumerd_err_sock < 0) {
		ERR("Create unix sock failed: %s", kconsumerd_err_unix_sock_path);
		ret = -1;
		goto error;
	}

	/* File permission MUST be 660 */
	ret = chmod(kconsumerd_err_unix_sock_path, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
	if (ret < 0) {
		ERR("Set file permissions failed: %s", kconsumerd_err_unix_sock_path);
		perror("chmod");
		goto error;
	}

error:
	return ret;
}

/*
 *  set_signal_handler
 *
 *  Setup signal handler for :
 *		SIGINT, SIGTERM, SIGPIPE
 */
static int set_signal_handler(void)
{
	int ret = 0;
	struct sigaction sa;
	sigset_t sigset;

	if ((ret = sigemptyset(&sigset)) < 0) {
		perror("sigemptyset");
		return ret;
	}

	sa.sa_handler = sighandler;
	sa.sa_mask = sigset;
	sa.sa_flags = 0;
	if ((ret = sigaction(SIGTERM, &sa, NULL)) < 0) {
		perror("sigaction");
		return ret;
	}

	if ((ret = sigaction(SIGINT, &sa, NULL)) < 0) {
		perror("sigaction");
		return ret;
	}

	if ((ret = sigaction(SIGPIPE, &sa, NULL)) < 0) {
		perror("sigaction");
		return ret;
	}

	DBG("Signal handler set for SIGTERM, SIGPIPE and SIGINT");

	return ret;
}

/**
 *  sighandler
 *
 *  Signal handler for the daemon
 */
static void sighandler(int sig)
{
	switch (sig) {
		case SIGPIPE:
			DBG("SIGPIPE catched");
			return;
		case SIGINT:
			DBG("SIGINT catched");
			cleanup();
			break;
		case SIGTERM:
			DBG("SIGTERM catched");
			cleanup();
			break;
		default:
			break;
	}

	exit(EXIT_SUCCESS);
}

/*
 *  cleanup
 *
 *  Cleanup the daemon on exit
 */
static void cleanup()
{
	int ret;
	char *cmd;

	DBG("Cleaning up");

	/* <fun> */
	MSG("\n%c[%d;%dm*** assert failed *** ==> %c[%dm", 27,1,31,27,0);
	MSG("%c[%d;%dmMatthew, BEET driven development works!%c[%dm",27,1,33,27,0);
	/* </fun> */

	unlink(client_unix_sock_path);
	unlink(apps_unix_sock_path);
	unlink(kconsumerd_err_unix_sock_path);

	ret = asprintf(&cmd, "rm -rf " LTTNG_RUNDIR);
	if (ret < 0) {
		ERR("asprintf failed. Something is really wrong!");
	}

	/* Remove lttng run directory */
	ret = system(cmd);
	if (ret < 0) {
		ERR("Unable to clean " LTTNG_RUNDIR);
	}
}

/*
 * main
 */
int main(int argc, char **argv)
{
	int i;
	int ret = 0;
	void *status;
	pthread_t threads[2];

	/* Parse arguments */
	progname = argv[0];
	if ((ret = parse_args(argc, argv) < 0)) {
		goto error;
	}

	/* Daemonize */
	if (opt_daemon) {
		ret = daemon(0, 0);
		if (ret < 0) {
			perror("daemon");
			goto error;
		}
	}

	/* Check if daemon is UID = 0 */
	is_root = !getuid();

	/* Set all sockets path */
	if (is_root) {
		ret = create_lttng_rundir();
		if (ret < 0) {
			goto error;
		}

		if (strlen(apps_unix_sock_path) == 0) {
			snprintf(apps_unix_sock_path, PATH_MAX,
					DEFAULT_GLOBAL_APPS_UNIX_SOCK);
		}

		if (strlen(client_unix_sock_path) == 0) {
			snprintf(client_unix_sock_path, PATH_MAX,
					DEFAULT_GLOBAL_CLIENT_UNIX_SOCK);
		}

		ret = set_kconsumerd_sockets();
		if (ret < 0) {
			goto error;
		}
	} else {
		if (strlen(apps_unix_sock_path) == 0) {
			snprintf(apps_unix_sock_path, PATH_MAX,
					DEFAULT_HOME_APPS_UNIX_SOCK, get_home_dir());
		}

		/* Set the cli tool unix socket path */
		if (strlen(client_unix_sock_path) == 0) {
			snprintf(client_unix_sock_path, PATH_MAX,
					DEFAULT_HOME_CLIENT_UNIX_SOCK, get_home_dir());
		}
	}

	DBG("Client socket path %s", client_unix_sock_path);
	DBG("Application socket path %s", apps_unix_sock_path);

	/* See if daemon already exist. If any of the two
	 * socket needed by the daemon are present, this test fails
	 */
	if ((ret = check_existing_daemon()) == 0) {
		ERR("Already running daemon.\n");
		/* We do not goto error because we must not
		 * cleanup() because a daemon is already running.
		 */
		exit(EXIT_FAILURE);
	}

	if (set_signal_handler() < 0) {
		goto error;
	}

	/* Setup the needed unix socket */
	if (init_daemon_socket() < 0) {
		goto error;
	}

	/* Set credentials to socket */
	if (is_root && (set_permissions() < 0)) {
		goto error;
	}

	/* Get parent pid if -S, --sig-parent is specified. */
	if (opt_sig_parent) {
		ppid = getppid();
	}

	while (1) {
		/* Create thread to manage the client socket */
		ret = pthread_create(&threads[0], NULL, thread_manage_clients, (void *) NULL);
		if (ret != 0) {
			perror("pthread_create");
			goto error;
		}

		/* Create thread to manage application socket */
		ret = pthread_create(&threads[1], NULL, thread_manage_apps, (void *) NULL);
		if (ret != 0) {
			perror("pthread_create");
			goto error;
		}

		for (i = 0; i < 2; i++) {
			ret = pthread_join(threads[i], &status);
			if (ret != 0) {
				perror("pthread_join");
				goto error;
			}
		}
	}

	cleanup();
	exit(EXIT_SUCCESS);

error:
	cleanup();
	exit(EXIT_FAILURE);
}
