/*
 * Copyright (C) 2017  Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <dlfcn.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <sys/sdt.h>

#include "foobar_provider.h"
#include "libfoo.h"
#include "sema.h"

int main(int argc, char *argv[])
{
	void *handle;
	void (*bar_function)();

	FOOBAR_TP1();
	FOOBAR_TP2();
	/*
	 * This SDT tracepoint has an argument. Argument extraction is not support
	 * at the moment but tracing of the tracepoint should work.
	 */
	FOOBAR_TP_WITH_ARG(42);

	/* Call function containing an SDT tracepoint in shared object */
	foo_function();

	/*
	 * Load a show shared object and call a function containing an SDT
	 * tracepoint
	 */
	handle = dlopen("libbar.so", RTLD_LAZY);
	if (!handle) {
		fprintf(stderr, "Can't dlopen libbar.so");
		return -1;
	}
	bar_function = (void (*)())dlsym(handle, "bar_function");
	bar_function();
	dlclose(handle);

	/* This tracepoint has 2 callsites in this binary */
	FOOBAR_TP2();

	/*
	 * This function is defined in libfoo AND in libzzz. For a test, libzzz is
	 * LD_PRELOADed and should override this function
	 */
	overridable_function();

	/*
	 * This function is calling a SDT tracepoint that is guarded by a
	 * semaphore.
	 */
	sema_function();
	return 0;
}

