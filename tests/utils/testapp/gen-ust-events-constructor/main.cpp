/*
 * Copyright (C) 2023 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include "obj.h"
#include "tp-a.h"
#include "tp-so.h"
#include "tp.h"

/* Use tracepoints defined and provided by shared libraries. */
void test_constructor_so(void) __attribute__((constructor));
void test_constructor_so(void)
{
	tracepoint(tp_so, constructor_c_provider_shared_library);
}

void test_destructor_so(void) __attribute__((destructor));
void test_destructor_so(void)
{
	tracepoint(tp_so, destructor_c_provider_shared_library);
}

Objso g_objso_shared_library("global - shared library define and provider");

/* Use tracepoints defined and provided by static archive. */
void test_constructor_a(void) __attribute__((constructor));
void test_constructor_a(void)
{
	tracepoint(tp_a, constructor_c_provider_static_archive);
}

void test_destructor_a(void) __attribute__((destructor));
void test_destructor_a(void)
{
	tracepoint(tp_a, destructor_c_provider_static_archive);
}

Obja g_obja_static_archive("global - static archive define and provider");

int main(void)
{
	Obj l_obj("main() local");
	Objso l_objso("main() local - shared library define and provider");
	Obja l_obja("main() local - static archive define and provider");

	tracepoint(tp, main);
	return 0;
}
