/*
 * Copyright (c)  2011 David Goulet <david.goulet@polymtl.ca>
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

#define _GNU_SOURCE
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <config.h>
#include <ctype.h>

#include <lttng/lttng.h>
#include <common/error.h>

#include "command.h"

/* Variables */
static char *progname;
static int opt_no_sessiond;
static char *opt_sessiond_path;
static pid_t sessiond_pid;
static volatile int recv_child_signal;

enum {
	OPT_SESSION_PATH,
	OPT_DUMP_OPTIONS,
	OPT_DUMP_COMMANDS,
};

/* Getopt options. No first level command. */
static struct option long_options[] = {
	{"help",             0, NULL, 'h'},
	{"group",            1, NULL, 'g'},
	{"verbose",          0, NULL, 'v'},
	{"quiet",            0, NULL, 'q'},
	{"no-sessiond",      0, NULL, 'n'},
	{"sessiond-path",    1, NULL, OPT_SESSION_PATH},
	{"list-options",     0, NULL, OPT_DUMP_OPTIONS},
	{"list-commands",    0, NULL, OPT_DUMP_COMMANDS},
	{NULL, 0, NULL, 0}
};

/* First level command */
static struct cmd_struct commands[] =  {
	{ "list", cmd_list},
	{ "create", cmd_create},
	{ "destroy", cmd_destroy},
	{ "start", cmd_start},
	{ "stop", cmd_stop},
	{ "enable-event", cmd_enable_events},
	{ "disable-event", cmd_disable_events},
	{ "enable-channel", cmd_enable_channels},
	{ "disable-channel", cmd_disable_channels},
	{ "add-context", cmd_add_context},
	{ "set-session", cmd_set_session},
	{ "version", cmd_version},
	{ "calibrate", cmd_calibrate},
	{ "view", cmd_view},
	{ "enable-consumer", cmd_enable_consumer}, /* OBSELETE */
	{ "disable-consumer", cmd_disable_consumer}, /*OBSELETE */
	{ NULL, NULL}	/* Array closure */
};

static void usage(FILE *ofp)
{
	fprintf(ofp, "LTTng Trace Control " VERSION" - " VERSION_NAME"\n\n");
	fprintf(ofp, "usage: lttng [OPTIONS] <COMMAND> [<ARGS>]\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Options:\n");
	fprintf(ofp, "  -h, --help                 Show this help\n");
	fprintf(ofp, "      --list-options         Simple listing of lttng options\n");
	fprintf(ofp, "      --list-commands        Simple listing of lttng commands\n");
	fprintf(ofp, "  -v, --verbose              Increase verbosity\n");
	fprintf(ofp, "  -q, --quiet                Quiet mode\n");
	fprintf(ofp, "  -g, --group NAME           Unix tracing group name. (default: tracing)\n");
	fprintf(ofp, "  -n, --no-sessiond          Don't spawn a session daemon\n");
	fprintf(ofp, "      --sessiond-path PATH   Session daemon full path\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Commands:\n");
	fprintf(ofp, "    add-context       Add context to event and/or channel\n");
	fprintf(ofp, "    calibrate         Quantify LTTng overhead\n");
	fprintf(ofp, "    create            Create tracing session\n");
	fprintf(ofp, "    destroy           Tear down tracing session\n");
	fprintf(ofp, "    enable-channel    Enable tracing channel\n");
	fprintf(ofp, "    enable-event      Enable tracing event\n");
	fprintf(ofp, "    disable-channel   Disable tracing channel\n");
	fprintf(ofp, "    disable-event     Disable tracing event\n");
	fprintf(ofp, "    list              List possible tracing options\n");
	fprintf(ofp, "    set-session       Set current session name\n");
	fprintf(ofp, "    start             Start tracing\n");
	fprintf(ofp, "    stop              Stop tracing\n");
	fprintf(ofp, "    version           Show version information\n");
	fprintf(ofp, "    view              Start trace viewer\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Each command also has its own -h, --help option.\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Please see the lttng(1) man page for full documentation.\n");
	fprintf(ofp, "See http://lttng.org for updates, bug reports and news.\n");
}

/*
 *  list_options
 *
 *  List options line by line. This is mostly for bash auto completion and to
 *  avoid difficult parsing.
 */
static void list_options(FILE *ofp)
{
	int i = 0;
	struct option *option = NULL;

	option = &long_options[i];
	while (option->name != NULL) {
		fprintf(ofp, "--%s\n", option->name);

		if (isprint(option->val)) {
			fprintf(ofp, "-%c\n", option->val);
		}

		i++;
		option = &long_options[i];
	}
}

/*
 *  list_commands
 *
 *  List commands line by line. This is mostly for bash auto completion and to
 *  avoid difficult parsing.
 */
static void list_commands(FILE *ofp)
{
	int i = 0;
	struct cmd_struct *cmd = NULL;

	cmd = &commands[i];
	while (cmd->name != NULL) {
		fprintf(ofp, "%s\n", cmd->name);
		i++;
		cmd = &commands[i];
	}
}

/*
 * clean_exit
 */
static void clean_exit(int code)
{
	DBG("Clean exit");
	exit(code);
}

/*
 *  sighandler
 *
 *  Signal handler for the daemon
 */
static void sighandler(int sig)
{
	int status;

	switch (sig) {
		case SIGTERM:
			DBG("SIGTERM caught");
			clean_exit(EXIT_FAILURE);
			break;
		case SIGCHLD:
			DBG("SIGCHLD caught");
			waitpid(sessiond_pid, &status, 0);
			recv_child_signal = 1;
			/* Indicate that the session daemon died */
			sessiond_pid = 0;
			ERR("Session daemon died (exit status %d)", WEXITSTATUS(status));
			break;
		case SIGUSR1:
			/* Notify is done */
			recv_child_signal = 1;
			DBG("SIGUSR1 caught");
			break;
		default:
			DBG("Unknown signal %d caught", sig);
			break;
	}

	return;
}

/*
 *  set_signal_handler
 *
 *  Setup signal handler for SIGCHLD and SIGTERM.
 */
static int set_signal_handler(void)
{
	int ret = 0;
	struct sigaction sa;
	sigset_t sigset;

	if ((ret = sigemptyset(&sigset)) < 0) {
		perror("sigemptyset");
		goto end;
	}

	sa.sa_handler = sighandler;
	sa.sa_mask = sigset;
	sa.sa_flags = 0;
	if ((ret = sigaction(SIGUSR1, &sa, NULL)) < 0) {
		perror("sigaction");
		goto end;
	}

	if ((ret = sigaction(SIGTERM, &sa, NULL)) < 0) {
		perror("sigaction");
		goto end;
	}

	if ((ret = sigaction(SIGCHLD, &sa, NULL)) < 0) {
		perror("sigaction");
		goto end;
	}

end:
	return ret;
}

/*
 *  handle_command
 *
 *  Handle the full argv list of a first level command. Will find the command
 *  in the global commands array and call the function callback associated.
 *
 *  If command not found, return -1
 *  else, return function command error code.
 */
static int handle_command(int argc, char **argv)
{
	int i = 0, ret;
	struct cmd_struct *cmd;

	if (*argv == NULL) {
		ret = CMD_SUCCESS;
		goto end;
	}

	cmd = &commands[i];
	while (cmd->func != NULL) {
		/* Find command */
		if (strcmp(argv[0], cmd->name) == 0) {
			ret = cmd->func(argc, (const char**) argv);
			goto end;
		}
		i++;
		cmd = &commands[i];
	}

	/* Command not found */
	ret = CMD_UNDEFINED;

end:
	return ret;
}

/*
 *  spawn_sessiond
 *
 *  Spawn a session daemon by forking and execv.
 */
static int spawn_sessiond(char *pathname)
{
	int ret = 0;
	pid_t pid;

	MSG("Spawning a session daemon");
	recv_child_signal = 0;
	pid = fork();
	if (pid == 0) {
		/*
		 * Spawn session daemon and tell
		 * it to signal us when ready.
		 */
		execlp(pathname, "lttng-sessiond", "--sig-parent", "--quiet", NULL);
		/* execlp only returns if error happened */
		if (errno == ENOENT) {
			ERR("No session daemon found. Use --sessiond-path.");
		} else {
			perror("execlp");
		}
		kill(getppid(), SIGTERM);	/* wake parent */
		exit(EXIT_FAILURE);
	} else if (pid > 0) {
		sessiond_pid = pid;
		/*
		 * Wait for lttng-sessiond to start. We need to use a flag to check if
		 * the signal has been sent to us, because the child can be scheduled
		 * before the parent, and thus send the signal before this check. In
		 * the signal handler, we set the recv_child_signal flag, so anytime we
		 * check it after the fork is fine. Note that sleep() is interrupted
		 * before the 1 second delay as soon as the signal is received, so it
		 * will not cause visible delay for the user.
		 */
		while (!recv_child_signal) {
			sleep(1);
		}
		/*
		 * The signal handler will nullify sessiond_pid on SIGCHLD
		 */
		if (!sessiond_pid) {
			exit(EXIT_FAILURE);
		}
		goto end;
	} else {
		perror("fork");
		ret = -1;
		goto end;
	}

end:
	return ret;
}

/*
 *  check_sessiond
 *
 *  Check if the session daemon is available using
 *  the liblttngctl API for the check. If not, try to
 *  spawn a daemon.
 */
static int check_sessiond(void)
{
	int ret;
	char *pathname = NULL;

	ret = lttng_session_daemon_alive();
	if (ret == 0) {	/* not alive */
		/* Try command line option path */
		pathname = opt_sessiond_path;

		/* Try LTTNG_SESSIOND_PATH env variable */
		if (pathname == NULL) {
			pathname = getenv(DEFAULT_SESSIOND_PATH_ENV);
		}

		/* Try with configured path */
		if (pathname == NULL) {
			if (CONFIG_SESSIOND_BIN[0] != '\0') {
				pathname = CONFIG_SESSIOND_BIN;
			}
		}

		/* Let's rock and roll while trying the default path */
		if (pathname == NULL) {
			pathname = INSTALL_BIN_PATH "/lttng-sessiond";
		}

		DBG("Session daemon at: %s", pathname);

		/* Check existence and permissions */
		ret = access(pathname, F_OK | X_OK);
		if (ret < 0) {
			ERR("No such file or access denied: %s", pathname);
			goto end;
		}

		ret = spawn_sessiond(pathname);
		if (ret < 0) {
			ERR("Problem occurred when starting %s", pathname);
		}
	}
end:
	return ret;
}

/*
 * Check args for specific options that *must* not trigger a session daemon
 * execution.
 *
 * Return 1 if match else 0.
 */
static int check_args_no_sessiond(int argc, char **argv)
{
	int i;

	for (i = 0; i < argc; i++) {
		if ((strncmp(argv[i], "-h", sizeof("-h")) == 0) ||
				strncmp(argv[i], "--h", sizeof("--h")) == 0 ||
				strncmp(argv[i], "--list-options", sizeof("--list-options")) == 0 ||
				strncmp(argv[i], "--list-commands", sizeof("--list-commands")) == 0 ||
				strncmp(argv[i], "version", sizeof("version")) == 0 ||
				strncmp(argv[i], "view", sizeof("view")) == 0) {
			return 1;
		}
	}

	return 0;
}

/*
 * Parse command line arguments.
 *
 * Return 0 if OK, else -1
 */
static int parse_args(int argc, char **argv)
{
	int opt, ret;

	if (argc < 2) {
		usage(stderr);
		clean_exit(EXIT_FAILURE);
	}

	while ((opt = getopt_long(argc, argv, "+hnvqg:", long_options, NULL)) != -1) {
		switch (opt) {
		case 'h':
			usage(stdout);
			ret = 0;
			goto end;
		case 'v':
			lttng_opt_verbose += 1;
			break;
		case 'q':
			lttng_opt_quiet = 1;
			break;
		case 'g':
			lttng_set_tracing_group(optarg);
			break;
		case 'n':
			opt_no_sessiond = 1;
			break;
		case OPT_SESSION_PATH:
			opt_sessiond_path = strdup(optarg);
			break;
		case OPT_DUMP_OPTIONS:
			list_options(stdout);
			ret = 0;
			goto end;
		case OPT_DUMP_COMMANDS:
			list_commands(stdout);
			ret = 0;
			goto end;
		default:
			usage(stderr);
			ret = 1;
			goto error;
		}
	}

	/* If both options are specified, quiet wins */
	if (lttng_opt_verbose && lttng_opt_quiet) {
		lttng_opt_verbose = 0;
	}

	/* Spawn session daemon if needed */
	if (opt_no_sessiond == 0 && check_args_no_sessiond(argc, argv) == 0 &&
			(check_sessiond() < 0)) {
		ret = 1;
		goto error;
	}

	/* No leftovers, print usage and quit */
	if ((argc - optind) == 0) {
		usage(stderr);
		ret = 1;
		goto error;
	}

	/* 
	 * Handle leftovers which is a first level command with the trailing
	 * options.
	 */
	ret = handle_command(argc - optind, argv + optind);
	switch (ret) {
	case CMD_WARNING:
		WARN("Some command(s) went wrong");
		break;
	case CMD_ERROR:
		ERR("Command error");
		break;
	case CMD_UNDEFINED:
		ERR("Undefined command");
		break;
	case CMD_FATAL:
		ERR("Fatal error");
		break;
	case CMD_UNSUPPORTED:
		ERR("Unsupported command");
		break;
	case -1:
		usage(stderr);
		ret = 1;
		break;
	case 0:
		break;
	default:
		if (ret < 0) {
			ret = -ret;
		}
		break;
	}

end:
error:
	return ret;
}


/*
 *  main
 */
int main(int argc, char *argv[])
{
	int ret;
	char *user;

	progname = argv[0] ? argv[0] : "lttng";

	/* For Mathieu Desnoyers a.k.a. Dr. Tracing */
	user = getenv("USER");
	if (user != NULL && ((strncmp(progname, "drtrace", 7) == 0 ||
				strncmp("compudj", user, 7) == 0))) {
		MSG("%c[%d;%dmWelcome back Dr Tracing!%c[%dm\n", 27,1,33,27,0);
	}
	/* Thanks Mathieu */

	ret = set_signal_handler();
	if (ret < 0) {
		clean_exit(ret);
	}

	ret = parse_args(argc, argv);
	if (ret != 0) {
		clean_exit(ret);
	}

	return 0;
}
