/*
 * Copyright (C) 2023 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include "obj.h"
#include "tp-so.h"
#include "tp-so_c.h"
#include "tp.h"

/* Use tracepoints defined and provided by shared libraries. */
void test_constructor_so() __attribute__((constructor));
void test_constructor_so()
{
	tracepoint(tp_so_c, constructor_c_provider_shared_library);
}

void test_destructor_so() __attribute__((destructor));
void test_destructor_so()
{
	tracepoint(tp_so_c, destructor_c_provider_shared_library);
}

Objso g_objso_shared_library("global - shared library define and provider");

int main()
{
	const Obj l_obj("main() local");
	const Objso l_objso("main() local - shared library define and provider");

	tracepoint(tp, main);
	return 0;
}
