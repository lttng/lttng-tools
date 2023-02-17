/*
 * Copyright (C) 2023 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include "obj.h"

static void fct_constructor2(void);
static void fct_destructor2(void);

void test_constructor2_same_unit_before(void) __attribute__((constructor));
void test_constructor2_same_unit_before(void)
{
	fct_constructor2();
}

void test_destructor2_same_unit_before(void) __attribute__((destructor));
void test_destructor2_same_unit_before(void)
{
	fct_destructor2();
}

Obj g_obj_same_unit_before_define("global - same unit before define");

#define TRACEPOINT_DEFINE
#include "tp.h"

Obj g_obj_same_unit_after_define("global - same unit after define");

static void fct_constructor2(void)
{
	tracepoint(tp, constructor_c_same_unit_before_define);
}

static void fct_destructor2(void)
{
	tracepoint(tp, destructor_c_same_unit_before_define);
}

void test_constructor2_same_unit_after(void) __attribute__((constructor));
void test_constructor2_same_unit_after(void)
{
	tracepoint(tp, constructor_c_same_unit_after_define);
}

void test_destructor2_same_unit_after(void) __attribute__((destructor));
void test_destructor2_same_unit_after(void)
{
	tracepoint(tp, destructor_c_same_unit_after_define);
}
