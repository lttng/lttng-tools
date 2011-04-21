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

#include "liblttsessiondcomm.h"
#include "ltt-sessiond.h"

const char default_home_dir[] = DEFAULT_HOME_DIR;
const char default_tracing_group[] = DEFAULT_TRACING_GROUP;
const char default_ust_sock_dir[] = DEFAULT_UST_SOCK_DIR;
const char default_global_apps_pipe[] = DEFAULT_GLOBAL_APPS_PIPE;

/* Static functions */
static int set_signal_handler(void);
static int set_socket_perms(void);
static void sighandler(int);
static void cleanup(void);
static void copy_common_data(struct lttcomm_lttng_msg *llm, struct lttcomm_session_msg *lsm);
static int check_existing_daemon(void);
static int notify_apps(const char*);
static int connect_app(pid_t);
static int init_daemon_socket(void);
static int process_client_msg(int sock, struct lttcomm_session_msg*);
static int send_unix_sock(int sock, void *buf, size_t len);

static void *thread_manage_clients(void *);
static void *thread_manage_apps(void *);

static int create_session(const char*, uuid_t *);
static void destroy_session(uuid_t);

static struct ltt_session *find_session(uuid_t);

/* Variables */
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

/* Number of element for the list below. */
static unsigned int session_count;
static unsigned int traceable_app_count;

/* Init session's list */
static struct ltt_session_list ltt_session_list = {
	.head = CDS_LIST_HEAD_INIT(ltt_session_list.head),
};

/* Init ust traceabl application's list */
static struct ltt_traceable_app_list ltt_traceable_app_list = {
	.head = CDS_LIST_HEAD_INIT(ltt_traceable_app_list.head),
};

/*
 * 	thread_manage_apps
 *
 * 	This thread manage the application socket communication
 */
static void *thread_manage_apps(void *data)
{
	int sock, ret;
	struct ltt_traceable_app *lta;

	/* TODO: Something more elegant is needed but fine for now */
	struct {
		int reg;	/* 1:register, 0:unregister */
		pid_t pid;
		uid_t uid;
	} reg_msg;

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
			lta = malloc(sizeof(struct ltt_traceable_app));
			lta->pid = reg_msg.pid;
			lta->uid = reg_msg.uid;
			cds_list_add(&lta->list, &ltt_traceable_app_list.head);
			traceable_app_count++;
		} else {
			/* Unregistering */
			lta = NULL;
			cds_list_for_each_entry(lta, &ltt_traceable_app_list.head, list) {
				if (lta->pid == reg_msg.pid && lta->uid == reg_msg.uid) {
					cds_list_del(&lta->list);
					/* Check to not overflow here */
					if (traceable_app_count != 0) {
						traceable_app_count--;
					}
					break;
				}
			}

			/* If an item was found, free it from memory */
			if (lta) {
				free(lta);
			}
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
		if (ret < 0) {
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
 */
static int connect_app(pid_t pid)
{
	int sock;

	sock = ustctl_connect_pid(pid);
	if (sock < 0) {
		fprintf(stderr, "Fail connecting to the PID %d\n", pid);
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
 * 	find_session
 *
 * 	Return a ltt_session structure ptr that matches the uuid.
 */
static struct ltt_session *find_session(uuid_t session_id)
{
	struct ltt_session *iter = NULL;

	/* Sanity check for NULL session_id */
	if (uuid_is_null(session_id)) {
		goto end;
	}

	cds_list_for_each_entry(iter, &ltt_session_list.head, list) {
		if (uuid_compare(iter->uuid, session_id)) {
			break;
		}
	}

end:
	return iter;
}

/*
 * 	destroy_session
 *
 *  Delete session from the global session list
 *  and free the memory.
 */
static void destroy_session(uuid_t session_id)
{
	struct ltt_session *iter = NULL;

	cds_list_for_each_entry(iter, &ltt_session_list.head, list) {
		if (uuid_compare(iter->uuid, session_id)) {
			cds_list_del(&iter->list);
			break;
		}
	}

	if (iter) {
		free(iter);
		session_count--;
	}
}

/*
 * 	create_session
 *
 * 	Create a brand new session, 
 */
static int create_session(const char *name, uuid_t *session_id)
{
	struct ltt_session *new_session;

	/* Allocate session data structure */
	new_session = malloc(sizeof(struct ltt_session));
	if (new_session == NULL) {
		perror("malloc");
		goto error;
	}

	if (name != NULL) {
		if (asprintf(&new_session->name, "%s", name) < 0) {
			goto error;
		}
	} else {
		/* Generate session name based on the session count */
		if (asprintf(&new_session->name, "%s%d", "auto", session_count) < 0) {
			goto error;
		}
	}

	/* UUID generation */
	uuid_generate(new_session->uuid);
	uuid_copy(*session_id, new_session->uuid);

	/* Set consumer (identifier) to 0. This means that there is
	 * NO consumer attach to that session yet.
	 */
	new_session->ust_consumer = 0;
	new_session->lttng_consumer = 0;

	/* Init list */
	CDS_INIT_LIST_HEAD(&new_session->ust_traces);
	CDS_INIT_LIST_HEAD(&new_session->lttng_traces);

	/* Add new session to the global session list */
	cds_list_add(&new_session->list, &ltt_session_list.head);

	session_count++;

	return 0;

error:
	return -1;
}

/*
 * 	ust_list_apps
 *
 *  List traceable user-space application and fill an
 *  array of pids.
 *
 *  Return size of the array.
 */
static size_t ust_list_apps(pid_t **pids)
{
	size_t size = 0;
	struct ltt_traceable_app *iter = NULL;
	pid_t *p;

	if (traceable_app_count == 0) {
		/* No dynamic allocation is done */
		goto end;
	}

	p = malloc(sizeof(pid_t) * traceable_app_count);

	/* TODO: Mutex needed to access this list */
	cds_list_for_each_entry(iter, &ltt_traceable_app_list.head, list) {
		p[size] = iter->pid;
		size++;
	}

	*pids = p;

end:
	return size;
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
	if (!uuid_is_null(lsm->session_id)) {
		uuid_copy(llm->session_id, lsm->session_id);
	}
	strncpy(llm->trace_name, lsm->trace_name, sizeof(llm->trace_name));
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
	struct lttcomm_lttng_msg llm;

	/* Copy common data to identify the response
	 * on the lttng client side.
	 */
	copy_common_data(&llm, lsm);

	/* Default return code.
	 * In our world, everything is OK... right? ;)
	 */
	llm.ret_code = LTTCOMM_OK;

	/* Process by command type */
	switch (lsm->cmd_type) {
		case UST_LIST_APPS:
		{
			pid_t *pids;
			llm.num_pckt = ust_list_apps(&pids);
			if (llm.num_pckt == 0) {
				ret = LTTCOMM_NO_APPS;
				goto error;
			}

			/* Send all packets */
			while (llm.num_pckt != 0) {
				llm.u.list_apps.pid = pids[traceable_app_count - llm.num_pckt];
				ret = send_unix_sock(sock, (void*) &llm, sizeof(llm));
				if (ret < 0) {
					goto send_error;
				}
				llm.num_pckt--;
			}
			/* Allocated array by ust_list_apps() */
			free(pids);

			break;
		}
		default:
		{
			/* Undefined command */
			ret = LTTCOMM_UND;
			break;
		}
	}

	return 0;

send_error:
	return ret;

error:
	/* Notify client of error */
	llm.ret_code = ret;
	send_unix_sock(sock, (void*) &llm, sizeof(llm));

	return -1;
}

/*
 * usage function on stderr
 */
static void usage(void)
{
	fprintf(stderr, "Usage:\n%s OPTIONS\n\nOptions:\n"
			"\t-h, --help\t\tDisplay this usage.\n"
			"\t-c, --client-sock PATH\t\tSpecify path for the client unix socket\n"
			"\t-a, --apps-sock PATH\t\tSpecify path for apps unix socket.\n"
			"\t-d, --daemonize\t\tStart as a daemon.\n"
			"\t-g, --group NAME\t\tSpecify the tracing group name. (default: tracing)\n"
			"\t-V, --version\t\tShow version number.\n"
			"\t-S, --sig-parent\t\tSend SIGCHLD to parent pid to notify readiness.\n",
			progname);
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
		{ NULL, 0, 0, 0 }
	};

	while (1) {
		int option_index = 0;
		c = getopt_long(argc, argv, "dhVS" "a:c:g:s:", long_options, &option_index);
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
		case 's':
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
 * 		apps_socket - The communication socket for all UST apps.
 * 		client_socket - The communication of the cli tool (lttng).
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
 * 	If yes, error is returned.
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
 *	get_home_dir
 *
 *	Return pointer to home directory path using
 *	the env variable HOME.
 *
 *	Default : /tmp
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
		fprintf(stderr, "Missing tracing group. Aborting execution.\n");
		ret = -1;
		goto end;
	}

	ret = chown(client_unix_sock_path, 0, grp->gr_gid);
	if (ret < 0) {
		perror("chown");
	}

end:
	return ret;
}

/*
 *	set_signal_handler
 *
 *	Setup signal handler for :
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

	return ret;
}

/**
 *	sighandler
 *
 *	Signal handler for the daemon
 */
static void sighandler(int sig)
{
	switch (sig) {
		case SIGPIPE:
		case SIGINT:
		case SIGTERM:
			cleanup();
			break;
		default:
			break;
	}

	exit(EXIT_SUCCESS);
}

/*
 *	cleanup 
 *
 *	Cleanup the daemon on exit
 */
static void cleanup()
{
	/* <fun> */
	fprintf(stdout, "\n\n%c[%d;%dm*** assert failed *** ==> %c[%dm", 27,1,31,27,0);
	fprintf(stdout, "%c[%d;%dm Matthew, BEET driven development works!%c[%dm\n",27,1,33,27,0);
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
		fprintf(stderr, "Already running daemon.\n");
		goto error;
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
