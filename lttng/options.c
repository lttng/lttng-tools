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

#include <popt.h>
#include <stdlib.h>

#include "options.h"

/* Option variables */
char *opt_event_list;
char *opt_tracing_group;
char *opt_sessiond_path;
char *opt_session_name;
char *opt_trace_name;
int opt_destroy_trace;
int opt_create_session;
int opt_destroy_session;
int opt_trace_kernel;
int opt_quiet;
int opt_verbose;
int opt_list_apps;
int opt_list_events;
int opt_no_sessiond;
int opt_list_session;
int opt_list_traces;
int opt_create_trace;
int opt_start_trace;
int opt_stop_trace;
int opt_enable_event;
int opt_enable_all_event;
int opt_disable_event;
int opt_kern_create_channel;
pid_t opt_trace_pid;

enum {
	OPT_HELP = 1,
	OPT_ENABLE_EVENT,
	OPT_DISABLE_EVENT,
	OPT_CREATE_SESSION,
	OPT_CREATE_TRACE,
	OPT_DESTROY_SESSION,
	OPT_DESTROY_TRACE,
	OPT_START_TRACE,
	OPT_STOP_TRACE,
};

static struct poptOption long_options[] = {
	/* longName, shortName, argInfo, argPtr, value, descrip, argDesc */
	{"create-session",  'c',	POPT_ARG_STRING,	0, OPT_CREATE_SESSION, 0, 0},
	{"create-trace",    'C',    POPT_ARG_STRING | POPT_ARGFLAG_OPTIONAL, 0, OPT_CREATE_TRACE, 0, 0},
	{"destroy-trace",   'D',    POPT_ARG_STRING | POPT_ARGFLAG_OPTIONAL, 0, OPT_DESTROY_TRACE, 0, 0},
	{"destroy-session", 'd',	POPT_ARG_STRING,	0, OPT_DESTROY_SESSION, 0, 0},
	{"disable-event",	0,		POPT_ARG_STRING,	0, OPT_DISABLE_EVENT, 0, 0},
	{"enable-event",	'e',	POPT_ARG_STRING,	0, OPT_ENABLE_EVENT, 0, 0},
	{"enable-all-event",'a',	POPT_ARG_VAL,		&opt_enable_all_event, 1, 0, 0},
	{"group",			0,		POPT_ARG_STRING,	&opt_tracing_group, 0, 0, 0},
	{"help",			'h',	POPT_ARG_NONE,		0, OPT_HELP, 0, 0},
	{"kernel",			'k',	POPT_ARG_VAL,		&opt_trace_kernel, 1, 0, 0},
	{"kern-create-channel",0,   POPT_ARG_VAL,		&opt_kern_create_channel, 1, 0, 0},
	{"list-apps",		'L',	POPT_ARG_VAL,		&opt_list_apps, 1, 0, 0},
	{"list-events",		0,		POPT_ARG_VAL,		&opt_list_events, 1, 0, 0},
	{"list-sessions",	'l',	POPT_ARG_VAL,		&opt_list_session, 1, 0, 0},
	{"list-traces",		't',	POPT_ARG_VAL,		&opt_list_traces, 1, 0, 0},
	{"no-kernel",		0,		POPT_ARG_VAL,		&opt_trace_kernel, 0, 0, 0},
	{"no-sessiond",		0,		POPT_ARG_VAL,		&opt_no_sessiond, 1, 0, 0},
	{"pid",				'p',	POPT_ARG_INT,		&opt_trace_pid, 0, 0, 0},
	{"quiet",			'q',	POPT_ARG_VAL,		&opt_quiet, 1, 0, 0},
	{"session",			's',	POPT_ARG_STRING,	&opt_session_name, 0, 0, 0},
	{"sessiond-path",	0,		POPT_ARG_STRING,	&opt_sessiond_path, 0, 0, 0},
	{"start",			0,		POPT_ARG_STRING | POPT_ARGFLAG_OPTIONAL, 0, OPT_START_TRACE, 0, 0},
	{"stop",			0,		POPT_ARG_STRING | POPT_ARGFLAG_OPTIONAL, 0, OPT_STOP_TRACE, 0, 0},
	{"verbose",			'v',	POPT_ARG_VAL,		&opt_verbose, 1, 0, 0},
	{0, 0, 0, 0, 0, 0, 0}
};


/*
 * 	usage
 */
static void usage(FILE *ofp)
{
	fprintf(ofp, "LTTng Trace Control " VERSION"\n\n");
	fprintf(ofp, "usage : lttng [OPTION]\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Options:\n");
	fprintf(ofp, "  -v, --verbose                Verbose mode\n");
	fprintf(ofp, "  -q, --quiet                  Quiet mode\n");
	fprintf(ofp, "      --help                   Show help\n");
	fprintf(ofp, "      --group NAME             Unix tracing group name. (default: tracing)\n");
	fprintf(ofp, "      --no-sessiond            Don't spawn a session daemon\n");
	fprintf(ofp, "      --sessiond-path          Session daemon full path\n");
	fprintf(ofp, "  -L, --list-apps              List traceable user-space applications\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Session options:\n");
	fprintf(ofp, "  -c, --create-session NAME    Create a new session\n");
	fprintf(ofp, "  -l, --list-sessions          List all available sessions by name\n");
	fprintf(ofp, "  -s, --session UUID           Specify tracing session using UUID\n");
	fprintf(ofp, "  -d, --destroy-session NAME   Destroy the session specified by NAME\n");
	fprintf(ofp, "  -t, --list-traces            List session's traces. Use -s to specify the session\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Tracing options:\n");
	fprintf(ofp, "  -p, --pid PID                Specify action on user-space tracer for PID\n");
	fprintf(ofp, "  -k, --kernel                 Specify action on kernel tracer\n");
	fprintf(ofp, "      --list-events            List all available tracing events\n");
	fprintf(ofp, "  -e, --enable-event LIST      Enable tracing event (support marker and tracepoint)\n");
	fprintf(ofp, "  -a, --enable-all-event       Enable all tracing event\n");
	fprintf(ofp, "      --disable-event LIST     Disable tracing event (support marker and tracepoint)\n");
	fprintf(ofp, "  -C, --create-trace           Create a trace. Allocate and setup a trace\n");
	fprintf(ofp, "  -D, --destroy-trace [NAME]   Destroy a trace. Use NAME to identify user-space trace\n");
	fprintf(ofp, "      --start [NAME]           Start tracing. Use NAME to identify user-space trace\n");
	fprintf(ofp, "      --stop [NAME]            Stop tracing. Use NAME to identify user-space trace\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Kernel tracing options:\n");
	fprintf(ofp, "      --kern-create-channel    Create a kernel channel\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "User-space tracing options:\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Please see the lttng(1) man page for full documentation.\n");
	fprintf(ofp, "See http://lttng.org for updates, bug reports and news.\n");
}

/*
 *  parse_args
 *
 *  Parse command line arguments.
 *  Return 0 if OK, else -1
 */
int parse_args(int argc, const char **argv)
{
	static poptContext pc;
	int opt;

	/* If no options, fail */
	if (argc < 2) {
		return -1;
	}

	pc = poptGetContext(NULL, argc, argv, long_options, 0);
	poptReadDefaultConfig(pc, 0);

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case OPT_HELP:
			usage(stderr);
			clean_exit(EXIT_SUCCESS);
			break;
		case OPT_CREATE_SESSION:
			opt_create_session = 1;
			opt_session_name = poptGetOptArg(pc);
			break;
		case OPT_DESTROY_SESSION:
			opt_destroy_session = 1;
			opt_session_name = poptGetOptArg(pc);
			break;
		case OPT_ENABLE_EVENT:
			opt_enable_event = 1;
			opt_event_list = poptGetOptArg(pc);
			break;
		case OPT_DESTROY_TRACE:
			opt_destroy_trace = 1;
			opt_trace_name = poptGetOptArg(pc);
			break;
		case OPT_START_TRACE:
			opt_start_trace = 1;
			opt_trace_name = poptGetOptArg(pc);
			break;
		case OPT_STOP_TRACE:
			opt_stop_trace = 1;
			opt_trace_name = poptGetOptArg(pc);
			break;
		case OPT_CREATE_TRACE:
			opt_create_trace = 1;
			opt_trace_name = poptGetOptArg(pc);
			break;
		default:
			usage(stderr);
			clean_exit(EXIT_FAILURE);
			break;
		}
	}

	if (pc) {
		poptFreeContext(pc);
	}

	return 0;
}
