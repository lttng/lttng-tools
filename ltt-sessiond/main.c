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

/* Const values */
const char default_home_dir[] = DEFAULT_HOME_DIR;
const char default_tracing_group[] = DEFAULT_TRACING_GROUP;
const char default_ust_sock_dir[] = DEFAULT_UST_SOCK_DIR;
const char default_global_apps_pipe[] = DEFAULT_GLOBAL_APPS_PIPE;

/* Static functions */
static int check_existing_daemon(void);
static int connect_app(pid_t pid);
static int init_daemon_socket(void);
static int notify_apps(const char* name);
static int process_client_msg(int sock, struct lttcomm_session_msg*);
static int send_unix_sock(int sock, void *buf, size_t len);
static int set_signal_handler(void);
static int set_socket_perms(void);
static int setup_data_buffer(char **buf, size_t size, struct lttcomm_lttng_msg *llm);
static void cleanup(void);
static void copy_common_data(struct lttcomm_lttng_msg *llm, struct lttcomm_session_msg *lsm);
static void sighandler(int sig);

static void *thread_manage_clients(void *data);
static void *thread_manage_apps(void *data);

/* Variables */
int opt_verbose;
int opt_quiet;
const char *progname;
const char *opt_tracing_group;
static int opt_sig_parent;
static int opt_daemon;
static int is_root;			/* Set to 1 if the daemon is running as root */
static pid_t ppid;

static char apps_unix_sock_path[PATH_MAX];			/* Global application Unix socket path */
static char client_unix_sock_path[PATH_MAX];		/* Global client Unix socket path */

static int client_socket;
static int apps_socket;

static struct ltt_session *current_session;

/*
 * 	thread_manage_apps
 *
 * 	This thread manage the application socket communication
 */
static void *thread_manage_apps(void *data)
{
	int sock, ret;

	/* TODO: Something more elegant is needed but fine for now */
	struct {
		int reg;	/* 1:register, 0:unregister */
		pid_t pid;
		uid_t uid;
	} reg_msg;

	DBG("[thread] Manage apps started");

	/* Notify all applications to register */
	notify_apps(default_global_apps_pipe);

	ret = lttcomm_listen_unix_sock(apps_socket);
	if (ret < 0) {
		goto error;
	}

	while (1) {
		/* Blocking call, waiting for transmission */
		sock = lttcomm_accept_unix_sock(apps_socket);
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
	struct lttcomm_session_msg lsm;

	DBG("[thread] Manage client started");

	ret = lttcomm_listen_unix_sock(client_socket);
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
		sock = lttcomm_accept_unix_sock(client_socket);
		if (sock < 0) {
			goto error;
		}

		/*
		 * Data is received from the lttng client. The struct
		 * lttcomm_session_msg (lsm) contains the command and data
		 * request of the client.
		 */
		ret = lttcomm_recv_unix_sock(sock, &lsm, sizeof(lsm));
		if (ret <= 0) {
			continue;
		}

		/* This function dispatch the work to the LTTng or UST libs
		 * and then sends back the response to the client. This is needed
		 * because there might be more then one lttcomm_lttng_msg to
		 * send out so process_client_msg do both jobs.
		 */
		ret = process_client_msg(sock, &lsm);
		if (ret < 0) {
			/* Error detected but still accept command */
			continue;
		}
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
 * 	connect_app
 *
 * 	Return a socket connected to the libust communication socket
 * 	of the application identified by the pid.
 *
 * 	If the pid is not found in the traceable list,
 * 	return -1 to indicate error.
 */
static int connect_app(pid_t pid)
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
 *  ust_create_trace
 *
 *  Create an userspace trace using pid.
 *  This trace is then appended to the current session
 *  ust trace list.
 */
static int ust_create_trace(pid_t pid)
{
	int sock, ret;
	struct ltt_ust_trace *trace;

	DBG("Creating trace for pid %d", pid);

	trace = malloc(sizeof(struct ltt_ust_trace));
	if (trace == NULL) {
		perror("malloc");
		ret = -1;
		goto error;
	}

	/* Init */
	trace->pid = pid;
	trace->shmid = 0;
	/* NOTE: to be removed. Trace name will no longer be
	 * required for LTTng userspace tracer. For now, we set it
	 * to 'auto' for API compliance.
	 */
	snprintf(trace->name, 5, "auto");

	/* Connect to app using ustctl API */
	sock = connect_app(pid);
	if (sock < 0) {
		ret = LTTCOMM_NO_TRACEABLE;
		goto error;
	}

	ret = ustctl_create_trace(sock, trace->name);
	if (ret < 0) {
		ret = LTTCOMM_CREATE_FAIL;
		goto error;
	}

	/* Check if current session is valid */
	if (current_session) {
		cds_list_add(&trace->list, &current_session->ust_traces);
		current_session->ust_trace_count++;
	}

error:
	return ret;
}

/*
 *  ust_start_trace
 *
 *  Start a trace. This trace, identified by the pid, must be
 *  in the current session ust_traces list.
 */
static int ust_start_trace(pid_t pid)
{
	int sock, ret;
	struct ltt_ust_trace *trace;

	DBG("Starting trace for pid %d", pid);

	trace = find_session_ust_trace_by_pid(current_session, pid);
	if (trace == NULL) {
		ret = LTTCOMM_NO_TRACE;
		goto error;
	}

	/* Connect to app using ustctl API */
	sock = connect_app(pid);
	if (sock < 0) {
		ret = LTTCOMM_NO_TRACEABLE;
		goto error;
	}

	ret = ustctl_start_trace(sock, "auto");
	if (ret < 0) {
		ret = LTTCOMM_START_FAIL;
		goto error;
	}

error:
	return ret;
}

/*
 *  ust_stop_trace
 *
 *  Stop a trace. This trace, identified by the pid, must be
 *  in the current session ust_traces list.
 */
static int ust_stop_trace(pid_t pid)
{
	int sock, ret;
	struct ltt_ust_trace *trace;

	DBG("Stopping trace for pid %d", pid);

	trace = find_session_ust_trace_by_pid(current_session, pid);
	if (trace == NULL) {
		ret = LTTCOMM_NO_TRACE;
		goto error;
	}

	/* Connect to app using ustctl API */
	sock = connect_app(pid);
	if (sock < 0) {
		ret = LTTCOMM_NO_TRACEABLE;
		goto error;
	}

	ret = ustctl_stop_trace(sock, trace->name);
	if (ret < 0) {
		ret = LTTCOMM_STOP_FAIL;
		goto error;
	}

error:
	return ret;
}

/*
 *  copy_common_data
 *
 *  Copy common data between lttcomm_lttng_msg and lttcomm_session_msg
 */
static void copy_common_data(struct lttcomm_lttng_msg *llm, struct lttcomm_session_msg *lsm)
{
	llm->cmd_type = lsm->cmd_type;
	llm->pid = lsm->pid;

	/* Manage uuid */
	if (!uuid_is_null(lsm->session_id)) {
		uuid_copy(llm->session_id, lsm->session_id);
	}

	strncpy(llm->trace_name, lsm->trace_name, strlen(llm->trace_name));
	llm->trace_name[strlen(llm->trace_name) - 1] = '\0';
}

/*
 *  setup_data_buffer
 *
 *  Setup the outgoing data buffer for the response
 *  data allocating the right amount of memory.
 *
 *  Return total size of the buffer pointed by buf.
 */
static int setup_data_buffer(char **buf, size_t s_data, struct lttcomm_lttng_msg *llm)
{
	int ret = 0;
	size_t buf_size;

	buf_size = sizeof(struct lttcomm_lttng_msg) + s_data;
	*buf = malloc(buf_size);
	if (*buf == NULL) {
		perror("malloc");
		ret = -1;
		goto error;
	}

	/* Setup lttcomm_lttng_msg data and copy
	 * it to the newly allocated buffer.
	 */
	llm->size_payload = s_data;
	memcpy(*buf, llm, sizeof(struct lttcomm_lttng_msg));

	return buf_size;

error:
	return ret;
}

/*
 * 	process_client_msg
 *
 * 	This takes the lttcomm_session_msg struct and process the command requested
 * 	by the client. It then creates response(s) and send it back to the
 * 	given socket (sock).
 *
 * 	Return any error encountered or 0 for success.
 */
static int process_client_msg(int sock, struct lttcomm_session_msg *lsm)
{
	int ret;
	int buf_size;
	size_t header_size;
	char *send_buf = NULL;
	struct lttcomm_lttng_msg llm;

	DBG("Processing client message");

	/* Copy common data to identify the response
	 * on the lttng client side.
	 */
	copy_common_data(&llm, lsm);

	/* Check command that needs a session */
	if (lsm->cmd_type != LTTNG_CREATE_SESSION &&
		lsm->cmd_type != LTTNG_LIST_SESSIONS &&
		lsm->cmd_type != UST_LIST_APPS)
	{
		current_session = find_session_by_uuid(lsm->session_id);
		if (current_session == NULL) {
			ret = LTTCOMM_SELECT_SESS;
			goto end;
		}
	}

	/* Default return code.
	 * In our world, everything is OK... right? ;)
	 */
	llm.ret_code = LTTCOMM_OK;

	header_size = sizeof(struct lttcomm_lttng_msg);

	/* Process by command type */
	switch (lsm->cmd_type) {
		case LTTNG_CREATE_SESSION:
		{
			ret = create_session(lsm->session_name, &llm.session_id);
			if (ret < 0) {
				if (ret == -1) {
					ret = LTTCOMM_EXIST_SESS;
				} else {
					ret = LTTCOMM_FATAL;
				}
				goto end;
			}

			buf_size = setup_data_buffer(&send_buf, 0, &llm);
			if (buf_size < 0) {
				ret = LTTCOMM_FATAL;
				goto end;
			}

			break;
		}
		case LTTNG_DESTROY_SESSION:
		{
			ret = destroy_session(&lsm->session_id);
			if (ret < 0) {
				ret = LTTCOMM_NO_SESS;
			} else {
				ret = LTTCOMM_OK;
			}

			/* No auxiliary data so only send the llm struct. */
			goto end;
		}
		case LTTNG_LIST_TRACES:
		{
			unsigned int trace_count = get_trace_count_per_session(current_session);

			if (trace_count == 0) {
				ret = LTTCOMM_NO_TRACE;
				goto end;
			}

			buf_size = setup_data_buffer(&send_buf,
					sizeof(struct lttng_trace) * trace_count, &llm);
			if (buf_size < 0) {
				ret = LTTCOMM_FATAL;
				goto end;
			}

			get_traces_per_session(current_session, (struct lttng_trace *)(send_buf + header_size));
			break;
		}
		case UST_CREATE_TRACE:
		{
			ret = ust_create_trace(lsm->pid);
			if (ret < 0) {
				/* If -1 is returned from ust_create_trace, malloc
				 * failed so it's pretty much a fatal error.
				 */
				ret = LTTCOMM_FATAL;
				goto end;
			}

			/* No auxiliary data so only send the llm struct. */
			goto end;
		}
		case UST_LIST_APPS:
		{
			unsigned int app_count = get_app_count();
			/* Stop right now if no apps */
			if (app_count == 0) {
				ret = LTTCOMM_NO_APPS;
				goto end;
			}

			/* Setup data buffer and details for transmission */
			buf_size = setup_data_buffer(&send_buf,
					sizeof(pid_t) * app_count, &llm);
			if (buf_size < 0) {
				ret = LTTCOMM_FATAL;
				goto end;
			}

			get_app_list_pids((pid_t *)(send_buf + header_size));

			break;
		}
		case UST_START_TRACE:
		{
			ret = ust_start_trace(lsm->pid);

			/* No auxiliary data so only send the llm struct. */
			goto end;
		}
		case UST_STOP_TRACE:
		{
			ret = ust_stop_trace(lsm->pid);

			/* No auxiliary data so only send the llm struct. */
			goto end;
		}
		case LTTNG_LIST_SESSIONS:
		{
			unsigned int session_count = get_session_count();
			/* Stop right now if no session */
			if (session_count == 0) {
				ret = LTTCOMM_NO_SESS;
				goto end;
			}

			/* Setup data buffer and details for transmission */
			buf_size = setup_data_buffer(&send_buf,
					(sizeof(struct lttng_session) * session_count), &llm);
			if (buf_size < 0) {
				ret = LTTCOMM_FATAL;
				goto end;
			}

			get_lttng_session((struct lttng_session *)(send_buf + header_size));

			break;
		}
		default:
		{
			/* Undefined command */
			ret = LTTCOMM_UND;
			goto end;
		}
	}

	ret = send_unix_sock(sock, send_buf, buf_size);

	if (send_buf != NULL) {
		free(send_buf);
	}

	return ret;

end:
	DBG("Return code to client %d", ret);
	/* Notify client of error */
	llm.ret_code = ret;
	llm.size_payload = 0;
	send_unix_sock(sock, (void*) &llm, sizeof(llm));

	return ret;
}

/*
 * usage function on stderr
 */
static void usage(void)
{
	fprintf(stderr, "Usage: %s OPTIONS\n\nOptions:\n", progname);
	fprintf(stderr, "  -h, --help                Display this usage.\n");
	fprintf(stderr, "  -c, --client-sock PATH    Specify path for the client unix socket\n");
	fprintf(stderr, "  -a, --apps-sock PATH      Specify path for apps unix socket.\n");
	fprintf(stderr, "  -d, --daemonize           Start as a daemon.\n");
	fprintf(stderr, "  -g, --group NAME          Specify the tracing group name. (default: tracing)\n");
	fprintf(stderr, "  -V, --version             Show version number.\n");
	fprintf(stderr, "  -S, --sig-parent          Send SIGCHLD to parent pid to notify readiness.\n");
	fprintf(stderr, "  -q, --quiet               No output at all.\n");
	fprintf(stderr, "  -v, --verbose             Verbose mode. Activate DBG() macro.\n");
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
		c = getopt_long(argc, argv, "dhqvVS" "a:c:g:s:", long_options, &option_index);
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
 * 	    apps_socket - The communication socket for all UST apps.
 * 	    client_socket - The communication of the cli tool (lttng).
 */
static int init_daemon_socket()
{
	int ret = 0;
	mode_t old_umask;

	old_umask = umask(0);

	/* Create client tool unix socket */
	client_socket = lttcomm_create_unix_sock(client_unix_sock_path);
	if (client_socket < 0) {
		ret = -1;
		goto end;
	}

	/* File permission MUST be 660 */
	ret = chmod(client_unix_sock_path, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
	if (ret < 0) {
		perror("chmod");
		goto end;
	}

	/* Create the application unix socket */
	apps_socket = lttcomm_create_unix_sock(apps_unix_sock_path);
	if (apps_socket < 0) {
		ret = -1;
		goto end;
	}

	/* File permission MUST be 660 */
	ret = chmod(apps_unix_sock_path, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
	if (ret < 0) {
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
 *  set_socket_perms
 *
 *	Set the tracing group gid onto the client socket.
 */
static int set_socket_perms(void)
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

	ret = chown(client_unix_sock_path, 0, grp->gr_gid);
	if (ret < 0) {
		perror("chown");
	}

	DBG("Sockets permissions set");

end:
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
	DBG("Cleaning up");

	/* <fun> */
	MSG("\n%c[%d;%dm*** assert failed *** ==> %c[%dm", 27,1,31,27,0);
	MSG("%c[%d;%dmMatthew, BEET driven development works!%c[%dm",27,1,33,27,0);
	/* </fun> */

	unlink(client_unix_sock_path);
	unlink(apps_unix_sock_path);
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
		if (strlen(apps_unix_sock_path) == 0) {
			(snprintf(apps_unix_sock_path, PATH_MAX,
					DEFAULT_GLOBAL_APPS_UNIX_SOCK));
		}

		if (strlen(client_unix_sock_path) == 0) {
			(snprintf(client_unix_sock_path, PATH_MAX,
					DEFAULT_GLOBAL_CLIENT_UNIX_SOCK));
		}
	} else {
		if (strlen(apps_unix_sock_path) == 0) {
			(snprintf(apps_unix_sock_path, PATH_MAX,
					DEFAULT_HOME_APPS_UNIX_SOCK, get_home_dir()));
		}

		/* Set the cli tool unix socket path */
		if (strlen(client_unix_sock_path) == 0) {
			(snprintf(client_unix_sock_path, PATH_MAX,
					DEFAULT_HOME_CLIENT_UNIX_SOCK, get_home_dir()));
		}
	}

	/* See if daemon already exist. If any of the two
	 * socket needed by the daemon are present, this test fails
	 */
	if ((ret = check_existing_daemon()) == 0) {
		ERR("Already running daemon.\n");
		/* We do not goto error because we must not
		 * cleanup() because a daemon is already working.
		 */
		return EXIT_FAILURE;
	}

	if (set_signal_handler() < 0) {
		goto error;
	}

	/* Setup the two needed unix socket */
	if (init_daemon_socket() < 0) {
		goto error;
	}

	/* Set credentials to socket */
	if (is_root && (set_socket_perms() < 0)) {
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
	return 0;

error:
	cleanup();

	return EXIT_FAILURE;
}
