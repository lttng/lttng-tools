/*
 * Copyright (C) 2017 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

/*
 * The order of inclusion is important here: including sdt.h _before_ the probe
 * declarations ensures that semaphore-protected SDT probes (which we don't support) are not
 * generated. See SYSTEMTAP(2) for more details.
 */
/* clang-format off */
#include <sys/sdt.h>
#include "foobar_provider.h"
/* clang-format on */

#include "libfoo.h"
#include "sema.h"

#include <dlfcn.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>

int main(int argc, char *argv[])
{
	void *handle;
	void (*bar_function)();

	FOOBAR_TP1();
	FOOBAR_TP2();
	/*
	 * This SDT tracepoint has an argument. Argument extraction is not supported
	 * at the moment, but tracing of the tracepoint should work.
	 */
	FOOBAR_TP_WITH_ARG(42);

	/* Call a function containing an SDT tracepoint in shared object. */
	foo_function();

	/*
	 * Load a shared object and call a function containing an SDT
	 * tracepoint
	 */
	handle = dlopen("libbar.so", RTLD_LAZY);
	if (!handle) {
		fprintf(stderr, "Can't dlopen libbar.so");
		return -1;
	}
	bar_function = (void (*)()) dlsym(handle, "bar_function");
	bar_function();
	dlclose(handle);

	/* This tracepoint has 2 call sites in this binary. */
	FOOBAR_TP2();

	/*
	 * This function is defined in libfoo and in libzzz. For a test, libzzz is
	 * LD_PRELOADed and should override this function.
	 */
	overridable_function();

	/*
	 * This function is calling a SDT tracepoint that is guarded by a
	 * semaphore.
	 */
	sema_function();
	return 0;
}
