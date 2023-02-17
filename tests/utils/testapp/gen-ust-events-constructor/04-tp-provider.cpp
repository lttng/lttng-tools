/*
 * Copyright (C) 2023 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include "obj.h"

static void fct_constructor4(void);
static void fct_destructor4(void);

void test_constructor4_same_unit_before(void) __attribute__((constructor));
void test_constructor4_same_unit_before(void)
{
	fct_constructor4();
}

void test_destructor4_same_unit_before(void) __attribute__((destructor));
void test_destructor4_same_unit_before(void)
{
	fct_destructor4();
}

Obj g_obj_same_unit_before_provider("global - same unit before provider");

#define TRACEPOINT_CREATE_PROBES
#include "tp.h"

Obj g_obj_same_unit_after_provider("global - same unit after provider");

static void fct_constructor4(void)
{
	tracepoint(tp, constructor_c_same_unit_before_provider);
}

static void fct_destructor4(void)
{
	tracepoint(tp, destructor_c_same_unit_before_provider);
}

void test_constructor4_same_unit_after(void) __attribute__((constructor));
void test_constructor4_same_unit_after(void)
{
	tracepoint(tp, constructor_c_same_unit_after_provider);
}

void test_destructor4_same_unit_after(void) __attribute__((destructor));
void test_destructor4_same_unit_after(void)
{
	tracepoint(tp, destructor_c_same_unit_after_provider);
}
