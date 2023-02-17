/*
 * Copyright (C) 2023 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include "obj.h"
#include "tp.h"

void test_constructor3(void) __attribute__((constructor));
void test_constructor3(void)
{
	tracepoint(tp, constructor_c_across_units_after_define);
}

void test_destructor3(void) __attribute__((destructor));
void test_destructor3(void)
{
	tracepoint(tp, destructor_c_across_units_after_define);
}

Obj g_obj_across_units_after_define("global - across units after define");
