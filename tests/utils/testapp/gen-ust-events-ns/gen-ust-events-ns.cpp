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
#include "tp.h"

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

static int nr_iter = 100;
static int debug = 0;
static char *ns_opt = nullptr;
static char *after_unshare_file_path = nullptr;
static char *before_second_event_file_path = nullptr;

static struct poptOption opts[] = {
	/* longName, shortName, argInfo, argPtr, value, descrip, argDesc */
	{ "debug", 'd', POPT_ARG_NONE, &debug, 0, "Enable debug output", nullptr },
	{ "ns", 'n', POPT_ARG_STRING, &ns_opt, 0, "Namespace short identifier", nullptr },
	{ "iter", 'i', POPT_ARG_INT, &nr_iter, 0, "Number of tracepoint iterations", nullptr },
	{ "after",
	  'a',
	  POPT_ARG_STRING,
	  &after_unshare_file_path,
	  0,
	  "after_unshare_file_path,",
	  nullptr },
	{ "before",
	  'b',
	  POPT_ARG_STRING,
	  &before_second_event_file_path,
	  0,
	  "before_second_event_file_path,",
	  nullptr },
	POPT_AUTOHELP{ nullptr, 0, 0, nullptr, 0 }
};

static ATTR_FORMAT_PRINTF(1, 2) void debug_printf(const char *format, ...)
{
	va_list args;
	va_start(args, format);

	if (debug) {
		vfprintf(stderr, format, args);
	}

	va_end(args);
}

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

static int do_the_needful(int ns_flag, const char *ns_str)
{
	int ret = 0, i;
	ino_t ns1, ns2;

	ret = get_ns_inum(ns_str, &ns1);
	if (ret) {
		debug_printf("Failed to get ns inode number for namespace %s", ns_str);
		ret = -1;
		goto end;
	}
	debug_printf("Initial %s ns inode number:      %" PRIuMAX "\n", ns_str, (uintmax_t) ns1);

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
		debug_printf("Failed to get ns inode number for namespace %s", ns_str);
		ret = -1;
		goto end;
	}
	debug_printf("Post unshare %s ns inode number: %" PRIuMAX "\n", ns_str, (uintmax_t) ns2);

	/*
	 * Signal that we emited the first event group and that the
	 * unshare call is completed.
	 */
	if (after_unshare_file_path) {
		ret = create_file(after_unshare_file_path);
		if (ret != 0) {
			goto end;
		}
	}

	/* Wait on synchronization before writing second event group. */
	if (before_second_event_file_path) {
		ret = wait_on_file(before_second_event_file_path);
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
		ret = do_the_needful(CLONE_NEWCGROUP, "cgroup");
	} else if (strncmp(ns_opt, "ipc", 3) == 0) {
		ret = do_the_needful(CLONE_NEWIPC, "ipc");
	} else if (strncmp(ns_opt, "mnt", 3) == 0) {
		ret = do_the_needful(CLONE_NEWNS, "mnt");
	} else if (strncmp(ns_opt, "net", 3) == 0) {
		ret = do_the_needful(CLONE_NEWNET, "net");
	} else if (strncmp(ns_opt, "pid", 3) == 0) {
		ret = do_the_needful(CLONE_NEWPID, "pid");
	} else if (strncmp(ns_opt, "time", 4) == 0) {
		ret = do_the_needful(CLONE_NEWTIME, "time");
	} else if (strncmp(ns_opt, "user", 4) == 0) {
		/*
		 * Will always fail, requires a single threaded application,
		 * which can't happen with UST.
		 */
		ret = do_the_needful(CLONE_NEWUSER, "user");
	} else if (strncmp(ns_opt, "uts", 3) == 0) {
		ret = do_the_needful(CLONE_NEWUTS, "uts");
	} else {
		printf("invalid ns id\n");
		ret = EXIT_FAILURE;
		goto end;
	}
	ret = ret ? EXIT_FAILURE : EXIT_SUCCESS;
end:
	poptFreeContext(pc);
	return ret;
}
