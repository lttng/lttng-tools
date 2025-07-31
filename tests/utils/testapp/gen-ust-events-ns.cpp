/*
 * SPDX-FileCopyrightText: 2019 Michael Jeanson <mjeanson@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "signal-helper.hpp"
#include "utils.h"

#include <common/compat/tid.hpp>
#include <common/macros.hpp>

#include <inttypes.h>
#include <popt.h>
#include <sched.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define TRACEPOINT_DEFINE
#include "gen-ust-events-ns-tp.h"

#define LTTNG_PROC_NS_PATH_MAX 40

/*
 * The runner of this test validates that the kernel supports the
 * namespace for which it is invoked. However, these defines are added
 * to allow tests to run on systems that support a given namespace,
 * but that use a libc that doesn't define its associated clone flag.
 */
#ifndef CLONE_NEWNS
#define CLONE_NEWNS 0x00020000
#endif
#ifndef CLONE_NEWCGROUP
#define CLONE_NEWCGROUP 0x02000000
#endif
#ifndef CLONE_NEWUTS
#define CLONE_NEWUTS 0x04000000
#endif
#ifndef CLONE_NEWIPC
#define CLONE_NEWIPC 0x08000000
#endif
#ifndef CLONE_NEWUSER
#define CLONE_NEWUSER 0x10000000
#endif
#ifndef CLONE_NEWPID
#define CLONE_NEWPID 0x20000000
#endif
#ifndef CLONE_NEWNET
#define CLONE_NEWNET 0x40000000
#endif
#ifndef CLONE_NEWTIME
#define CLONE_NEWTIME 0x00000080
#endif

const char *cmd_name = nullptr;
static int nr_iter = 100;
static char *ns_opt = nullptr;
static char *after_unshare_touch_file_path = nullptr;
static char *before_last_event_file_path = nullptr;
static char *before_exit_touch_file_path = nullptr;

static struct poptOption opts[] = {
	/* longName, shortName, argInfo, argPtr, value, descrip, argDesc */
	{ "ns", 'n', POPT_ARG_STRING, &ns_opt, 0, "Namespace short identifier", nullptr },
	{ "iter", 'i', POPT_ARG_INT, &nr_iter, 0, "Number of tracepoint iterations", nullptr },
	{ "sync-after-unshare-touch",
	  'a',
	  POPT_ARG_STRING,
	  &after_unshare_touch_file_path,
	  0,
	  "Path to a file that will be created after unshare",
	  nullptr },
	{ "sync-before-last-event",
	  'b',
	  POPT_ARG_STRING,
	  &before_last_event_file_path,
	  0,
	  "Path to a file to wait on before the last group of events",
	  nullptr },
	{ "sync-before-exit-touch",
	  'g',
	  POPT_ARG_STRING,
	  &before_exit_touch_file_path,
	  0,
	  "Path to a file that will be created before exiting",
	  nullptr },
	POPT_AUTOHELP{ nullptr, 0, 0, nullptr, 0 }
};

static int get_ns_inum(const char *ns, ino_t *ns_inum)
{
	int ret = -1;
	struct stat sb;
	char proc_ns_path[LTTNG_PROC_NS_PATH_MAX];

	/*
	 * /proc/thread-self was introduced in kernel v3.17
	 */
	if (snprintf(proc_ns_path, LTTNG_PROC_NS_PATH_MAX, "/proc/thread-self/ns/%s", ns) >= 0) {
		if (stat(proc_ns_path, &sb) == 0) {
			*ns_inum = sb.st_ino;
			ret = 0;
		}
		goto end;
	}

	if (snprintf(proc_ns_path,
		     LTTNG_PROC_NS_PATH_MAX,
		     "/proc/self/task/%d/%s/net",
		     lttng_gettid(),
		     ns) >= 0) {
		if (stat(proc_ns_path, &sb) == 0) {
			*ns_inum = sb.st_ino;
			ret = 0;
		}
		goto end;
	}
end:
	return ret;
}

static int unshare_and_emit_events(int ns_flag, const char *ns_str)
{
	int ret = 0, i;
	ino_t ns1, ns2;

	ret = get_ns_inum(ns_str, &ns1);
	if (ret) {
		fprintf(stderr,
			"%s: Failed to get ns inode number for namespace %s",
			cmd_name,
			ns_str);
		ret = -1;
		goto end;
	}
	fprintf(stderr,
		"%s: Initial %s ns inode number:      %" PRIuMAX "\n",
		cmd_name,
		ns_str,
		(uintmax_t) ns1);

	for (i = 0; nr_iter < 0 || i < nr_iter; i++) {
		tracepoint(tp, tptest, ns1);
		if (should_quit) {
			break;
		}
	}

	ret = unshare(ns_flag);
	if (ret == -1) {
		perror("Failed to unshare namespace");
		goto end;
	}

	ret = get_ns_inum(ns_str, &ns2);
	if (ret) {
		fprintf(stderr,
			"%s: Failed to get ns inode number for namespace %s",
			cmd_name,
			ns_str);
		ret = -1;
		goto end;
	}
	fprintf(stderr,
		"%s: Post unshare %s ns inode number: %" PRIuMAX "\n",
		cmd_name,
		ns_str,
		(uintmax_t) ns2);

	/*
	 * Signal that we emited the first event group and that the
	 * unshare call is completed.
	 */
	if (after_unshare_touch_file_path) {
		fprintf(stderr,
			"%s: sync-after-unshare-touch: create %s\n",
			cmd_name,
			after_unshare_touch_file_path);
		ret = create_file(after_unshare_touch_file_path);
		if (ret != 0) {
			goto end;
		}
	}

	/* Wait on synchronization before writing last event group. */
	if (before_last_event_file_path) {
		fprintf(stderr,
			"%s: sync-before-last-event: wait %s\n",
			cmd_name,
			before_last_event_file_path);
		ret = wait_on_file(before_last_event_file_path);
		if (ret != 0) {
			goto end;
		}
	}

	for (i = 0; nr_iter < 0 || i < nr_iter; i++) {
		tracepoint(tp, tptest, ns2);
		if (should_quit) {
			break;
		}
	}

	if (before_exit_touch_file_path) {
		fprintf(stderr,
			"%s: sync-before-exit-touch: create %s\n",
			cmd_name,
			before_exit_touch_file_path);
		ret = create_file(before_exit_touch_file_path);
		if (ret != 0) {
			goto end;
		}
	}

end:
	return ret;
}

/*
 * Send X events, change NS, wait for file to sync with test script, send X
 * events in new NS
 */
int main(int argc, const char **argv)
{
	int opt;
	int ret = EXIT_SUCCESS;
	poptContext pc;

	cmd_name = (argc > 0) ? basename(argv[0]) : "COMMAND";

	pc = poptGetContext(nullptr, argc, argv, opts, 0);
	poptReadDefaultConfig(pc, 0);

	if (argc < 2) {
		poptPrintHelp(pc, stderr, 0);
		ret = EXIT_FAILURE;
		goto end;
	}

	while ((opt = poptGetNextOpt(pc)) >= 0) {
		switch (opt) {
		default:
			poptPrintUsage(pc, stderr, 0);
			ret = EXIT_FAILURE;
			goto end;
		}
	}

	if (opt < -1) {
		/* An error occurred during option processing. */
		poptPrintUsage(pc, stderr, 0);
		fprintf(stderr,
			"%s: %s\n",
			poptBadOption(pc, POPT_BADOPTION_NOALIAS),
			poptStrerror(opt));
		ret = EXIT_FAILURE;
		goto end;
	}

	if (ns_opt == nullptr) {
		poptPrintUsage(pc, stderr, 0);
		ret = EXIT_FAILURE;
		goto end;
	}

	if (set_signal_handler()) {
		ret = EXIT_FAILURE;
		goto end;
	}

	if (strncmp(ns_opt, "cgroup", 6) == 0) {
		ret = unshare_and_emit_events(CLONE_NEWCGROUP, "cgroup");
	} else if (strncmp(ns_opt, "ipc", 3) == 0) {
		ret = unshare_and_emit_events(CLONE_NEWIPC, "ipc");
	} else if (strncmp(ns_opt, "mnt", 3) == 0) {
		ret = unshare_and_emit_events(CLONE_NEWNS, "mnt");
	} else if (strncmp(ns_opt, "net", 3) == 0) {
		ret = unshare_and_emit_events(CLONE_NEWNET, "net");
	} else if (strncmp(ns_opt, "pid", 3) == 0) {
		ret = unshare_and_emit_events(CLONE_NEWPID, "pid");
	} else if (strncmp(ns_opt, "time", 4) == 0) {
		ret = unshare_and_emit_events(CLONE_NEWTIME, "time");
	} else if (strncmp(ns_opt, "user", 4) == 0) {
		/*
		 * Will always fail, requires a single threaded application,
		 * which can't happen with UST.
		 */
		ret = unshare_and_emit_events(CLONE_NEWUSER, "user");
	} else if (strncmp(ns_opt, "uts", 3) == 0) {
		ret = unshare_and_emit_events(CLONE_NEWUTS, "uts");
	} else {
		fprintf(stderr, "%s: invalid ns id\n", cmd_name);
		ret = EXIT_FAILURE;
		goto end;
	}
	ret = ret ? EXIT_FAILURE : EXIT_SUCCESS;
end:
	poptFreeContext(pc);
	return ret;
}
