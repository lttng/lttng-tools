/*
 * Copyright (C) 2024 Kienan Stewart <kstewart@efficios.com>
 *
 * SPDX-License-Identifier: LPGL-2.1-only
 */

#include "obj-a.h"
#include "tp-a.h"
extern "C" {
#include "tp-a_c.h"
}
#include "tp.h"

/* Use tracepoints defined and provided by static archive. */
void test_constructor_a() __attribute__((constructor));
void test_constructor_a()
{
	tracepoint(tp_a_c, constructor_c_provider_static_archive);
}

void test_destructor_a() __attribute__((destructor));
void test_destructor_a()
{
	tracepoint(tp_a_c, destructor_c_provider_static_archive);
}

Obja g_obja_static_archive("global - static archive define and provider");

int main()
{
	const Obj l_obj("main() local");
	const Obja l_obja("main() local - static archive define and provider");

	tracepoint(tp, main);
	return 0;
}
